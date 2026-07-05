"""Wallet graph and fund flow tracking."""

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import networkx as nx

from .config import Config
from .constants import KNOWN_MIXERS
from .models import (
    FlowPath,
    FundEdge,
    MonitoredTx,
    TraceResult,
    WalletCluster,
    WalletNode,
)

logger = logging.getLogger(__name__)


class FundTracer:
    """Builds and maintains an in-memory directed graph of fund flows."""

    def __init__(self, config: Config):
        self.config = config
        self.graph = nx.DiGraph()
        self._address_labels: dict[str, list[str]] = defaultdict(list)
        self._known_bad_set: set[str] = set()

    def record_transaction(self, tx: MonitoredTx) -> None:
        """Record a transaction in the fund flow graph."""
        from_addr = tx.from_address
        to_addr = tx.to_address

        if not to_addr:
            return

        # Add/update nodes
        self._ensure_node(from_addr, tx.timestamp)
        self._ensure_node(to_addr, tx.timestamp)

        # Update node stats
        from_node = self.graph.nodes[from_addr]
        from_node["total_sent_wei"] = from_node.get("total_sent_wei", 0) + tx.value_wei
        from_node["tx_count"] = from_node.get("tx_count", 0) + 1
        from_node["last_seen"] = tx.timestamp

        to_node = self.graph.nodes[to_addr]
        to_node["total_received_wei"] = to_node.get("total_received_wei", 0) + tx.value_wei
        to_node["tx_count"] = to_node.get("tx_count", 0) + 1
        to_node["last_seen"] = tx.timestamp

        # Add or update edge
        if self.graph.has_edge(from_addr, to_addr):
            edge = self.graph[from_addr][to_addr]
            edge["total_value_wei"] = edge.get("total_value_wei", 0) + tx.value_wei
            edge["tx_count"] = edge.get("tx_count", 0) + 1
            edge["tx_hashes"].append(tx.hash)
            edge["last_timestamp"] = tx.timestamp
        else:
            self.graph.add_edge(
                from_addr,
                to_addr,
                total_value_wei=tx.value_wei,
                tx_count=1,
                tx_hashes=[tx.hash],
                first_timestamp=tx.timestamp,
                last_timestamp=tx.timestamp,
            )

    def _ensure_node(self, address: str, timestamp: datetime) -> None:
        """Ensure a node exists in the graph."""
        if not self.graph.has_node(address):
            self.graph.add_node(
                address,
                first_seen=timestamp,
                last_seen=timestamp,
                total_received_wei=0,
                total_sent_wei=0,
                tx_count=0,
                risk_score=0.0,
                is_known_bad=address.lower() in {a.lower() for a in self._known_bad_set},
            )

    def get_wallet_info(self, address: str) -> WalletNode | None:
        """Get wallet information from the graph."""
        if not self.graph.has_node(address):
            return None

        node = self.graph.nodes[address]
        return WalletNode(
            address=address,
            first_seen=node.get("first_seen", datetime.now(timezone.utc)),
            last_seen=node.get("last_seen", datetime.now(timezone.utc)),
            total_received_wei=node.get("total_received_wei", 0),
            total_sent_wei=node.get("total_sent_wei", 0),
            tx_count=node.get("tx_count", 0),
            risk_score=node.get("risk_score", 0.0),
            is_known_bad=node.get("is_known_bad", False),
        )

    def trace_funds(
        self, address: str, depth: int | None = None
    ) -> TraceResult:
        """Trace fund flows for an address using BFS."""
        if depth is None:
            depth = self.config.max_trace_depth

        upstream_flows = self._bfs_upstream(address, depth)
        downstream_flows = self._bfs_downstream(address, depth)

        total_inflow = sum(flow.total_wei for flow in upstream_flows)
        total_outflow = sum(flow.total_wei for flow in downstream_flows)

        unique_senders = set()
        for flow in upstream_flows:
            if len(flow.path) > 1:
                unique_senders.add(flow.path[0])

        unique_receivers = set()
        for flow in downstream_flows:
            if len(flow.path) > 1:
                unique_receivers.add(flow.path[-1])

        risk_score = self._calculate_address_risk(address)

        return TraceResult(
            origin=address,
            upstream_flows=upstream_flows,
            downstream_flows=downstream_flows,
            total_inflow_wei=total_inflow,
            total_outflow_wei=total_outflow,
            unique_senders=len(unique_senders),
            unique_receivers=len(unique_receivers),
            risk_score=risk_score,
        )

    def _bfs_upstream(
        self, address: str, max_depth: int
    ) -> list[FlowPath]:
        """BFS backwards along reversed edges."""
        if not self.graph.has_node(address):
            return []

        flows = []
        visited = {address: 0}

        # BFS queue: (current_node, path, cumulative_value, tx_hashes)
        queue: list[tuple[str, list[str], int, list[str]]] = [
            (address, [address], 0, [])
        ]

        while queue:
            current, path, cum_value, hashes = queue.pop(0)
            depth = len(path) - 1

            if depth >= max_depth:
                continue

            # Get predecessors (who sent TO current)
            for predecessor in self.graph.predecessors(current):
                edge = self.graph[predecessor][current]

                if predecessor not in visited or visited[predecessor] < max_depth:
                    new_path = [predecessor] + path
                    new_value = cum_value + edge.get("total_value_wei", 0)
                    new_hashes = edge.get("tx_hashes", []) + hashes

                    flows.append(
                        FlowPath(
                            path=new_path,
                            total_wei=new_value,
                            tx_hashes=new_hashes,
                        )
                    )

                    visited[predecessor] = depth + 1
                    queue.append((predecessor, new_path, new_value, new_hashes))

        return flows

    def _bfs_downstream(
        self, address: str, max_depth: int
    ) -> list[FlowPath]:
        """BFS forwards from address."""
        if not self.graph.has_node(address):
            return []

        flows = []
        visited = {address: 0}

        queue: list[tuple[str, list[str], int, list[str]]] = [
            (address, [address], 0, [])
        ]

        while queue:
            current, path, cum_value, hashes = queue.pop(0)
            depth = len(path) - 1

            if depth >= max_depth:
                continue

            # Get successors (who received FROM current)
            for successor in self.graph.successors(current):
                edge = self.graph[current][successor]

                if successor not in visited or visited[successor] < max_depth:
                    new_path = path + [successor]
                    new_value = cum_value + edge.get("total_value_wei", 0)
                    new_hashes = hashes + edge.get("tx_hashes", [])

                    flows.append(
                        FlowPath(
                            path=new_path,
                            total_wei=new_value,
                            tx_hashes=new_hashes,
                        )
                    )

                    visited[successor] = depth + 1
                    queue.append((successor, new_path, new_value, new_hashes))

        return flows

    def get_predecessors(
        self, address: str, depth: int = 1
    ) -> set[str]:
        """Get all predecessors up to depth levels."""
        if not self.graph.has_node(address):
            return set()

        predecessors = set()
        current_level = {address}

        for _ in range(depth):
            next_level = set()
            for node in current_level:
                for pred in self.graph.predecessors(node):
                    if pred not in predecessors:
                        next_level.add(pred)
                        predecessors.add(pred)
            current_level = next_level

        return predecessors

    def get_successors(
        self, address: str, depth: int = 1
    ) -> set[str]:
        """Get all successors up to depth levels."""
        if not self.graph.has_node(address):
            return set()

        successors = set()
        current_level = {address}

        for _ in range(depth):
            next_level = set()
            for node in current_level:
                for succ in self.graph.successors(node):
                    if succ not in successors:
                        next_level.add(succ)
                        successors.add(succ)
            current_level = next_level

        return successors

    def find_clusters(self) -> list[WalletCluster]:
        """Find wallet clusters using weakly connected components."""
        clusters = []

        for component in nx.weakly_connected_components(self.graph):
            if len(component) < 2:
                continue

            # Calculate internal volume
            total_volume = 0
            internal_edges = 0
            for u, v in self.graph.edges():
                if u in component and v in component:
                    total_volume += self.graph[u][v].get("total_value_wei", 0)
                    internal_edges += 1

            if total_volume / 1e18 < self.config.min_cluster_volume_eth:
                continue

            # Find external counterparties
            external_counterparties = set()
            for node in component:
                for neighbor in self.graph.neighbors(node):
                    if neighbor not in component:
                        external_counterparties.add(node)

            # Calculate risk score
            risk_score = self._calculate_cluster_risk(
                list(component), total_volume
            )

            clusters.append(
                WalletCluster(
                    addresses=list(component),
                    total_volume_wei=total_volume,
                    shared_counterparties=len(external_counterparties),
                    risk_score=risk_score,
                )
            )

        return sorted(clusters, key=lambda c: c.risk_score, reverse=True)

    def _calculate_cluster_risk(
        self, addresses: list[str], total_volume: int
    ) -> float:
        """Calculate risk score for a wallet cluster."""
        if total_volume == 0:
            return 0.0

        bad_connections = 0
        total_connections = 0

        for addr in addresses:
            # Count connections to known bad addresses
            for neighbor in self.graph.neighbors(addr):
                total_connections += 1
                node_data = self.graph.nodes.get(neighbor, {})
                if node_data.get("is_known_bad", False):
                    bad_connections += 1

            for neighbor in self.graph.predecessors(addr):
                total_connections += 1
                node_data = self.graph.nodes.get(neighbor, {})
                if node_data.get("is_known_bad", False):
                    bad_connections += 1

        if total_connections == 0:
            return 0.0

        risk = (bad_connections / total_connections) * 0.6
        return min(1.0, risk)

    def compute_risk_scores(self) -> None:
        """Compute risk scores for all wallet nodes."""
        for node in self.graph.nodes():
            risk = self._calculate_address_risk(node)
            self.graph.nodes[node]["risk_score"] = risk

    def _calculate_address_risk(self, address: str) -> float:
        """Calculate risk score for a single address."""
        if not self.graph.has_node(address):
            return 0.0

        node = self.graph.nodes[address]
        score = 0.0

        # Connection to known bad addresses
        bad_connections = 0
        total_connections = 0

        for neighbor in self.graph.neighbors(address):
            total_connections += 1
            neighbor_data = self.graph.nodes.get(neighbor, {})
            if neighbor_data.get("is_known_bad", False):
                bad_connections += 1

        for neighbor in self.graph.predecessors(address):
            total_connections += 1
            neighbor_data = self.graph.nodes.get(neighbor, {})
            if neighbor_data.get("is_known_bad", False):
                bad_connections += 1

        if total_connections > 0:
            score += 0.5 * min(1, bad_connections / 3)

        # Mixer exposure
        mixer_volume = 0
        total_volume = node.get("total_received_wei", 0) + node.get("total_sent_wei", 0)

        for neighbor in self.graph.neighbors(address):
            edge = self.graph[address][neighbor]
            if neighbor.lower() in {a.lower() for a in KNOWN_MIXERS}:
                mixer_volume += edge.get("total_value_wei", 0)

        for neighbor in self.graph.predecessors(address):
            edge = self.graph[neighbor][address]
            if neighbor.lower() in {a.lower() for a in KNOWN_MIXERS}:
                mixer_volume += edge.get("total_value_wei", 0)

        if total_volume > 0:
            score += 0.2 * min(1, mixer_volume / total_volume)

        # Spread (unique counterparties)
        unique_counterparties = len(set(self.graph.neighbors(address))) + len(
            set(self.graph.predecessors(address))
        )
        score += 0.15 * min(1, unique_counterparties / 50)

        # Recency factor
        last_seen = node.get("last_seen")
        if last_seen:
            if isinstance(last_seen, datetime):
                age_hours = (
                    datetime.now(timezone.utc) - last_seen
                ).total_seconds() / 3600
            else:
                age_hours = 0
            recency = max(0, 1 - age_hours / 24)
            score += 0.15 * recency

        return min(1.0, score)

    def get_transaction_history(
        self, address: str, limit: int = 100
    ) -> list[FundEdge]:
        """Get transaction history for an address."""
        if not self.graph.has_node(address):
            return []

        edges = []

        # Outgoing transactions
        for successor in self.graph.successors(address):
            edge_data = self.graph[address][successor]
            tx_hashes = edge_data.get("tx_hashes", [])
            for tx_hash in tx_hashes[:limit]:
                edges.append(
                    FundEdge(
                        from_addr=address,
                        to_addr=successor,
                        value_wei=edge_data.get("total_value_wei", 0)
                        // max(1, len(tx_hashes)),
                        tx_hash=tx_hash,
                        timestamp=edge_data.get(
                            "last_timestamp", datetime.now(timezone.utc)
                        ),
                        block_number=0,
                    )
                )

        # Incoming transactions
        for predecessor in self.graph.predecessors(address):
            edge_data = self.graph[predecessor][address]
            tx_hashes = edge_data.get("tx_hashes", [])
            for tx_hash in tx_hashes[:limit]:
                edges.append(
                    FundEdge(
                        from_addr=predecessor,
                        to_addr=address,
                        value_wei=edge_data.get("total_value_wei", 0)
                        // max(1, len(tx_hashes)),
                        tx_hash=tx_hash,
                        timestamp=edge_data.get(
                            "last_timestamp", datetime.now(timezone.utc)
                        ),
                        block_number=0,
                    )
                )

        return sorted(edges, key=lambda e: e.timestamp, reverse=True)[:limit]

    def get_fund_flow_summary(self, address: str) -> dict[str, Any]:
        """Get aggregated stats for a wallet."""
        if not self.graph.has_node(address):
            return {"address": address, "not_found": True}

        node = self.graph.nodes[address]
        return {
            "address": address,
            "total_received_eth": node.get("total_received_wei", 0) / 1e18,
            "total_sent_eth": node.get("total_sent_wei", 0) / 1e18,
            "tx_count": node.get("tx_count", 0),
            "risk_score": node.get("risk_score", 0.0),
            "is_known_bad": node.get("is_known_bad", False),
            "first_seen": str(node.get("first_seen", "")),
            "last_seen": str(node.get("last_seen", "")),
        }

    def export_graph(self) -> dict[str, Any]:
        """Export graph as JSON-serializable dict."""
        nodes = []
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            nodes.append(
                {
                    "id": node,
                    "type": "wallet",
                    "data": {
                        **{
                            k: str(v) if isinstance(v, datetime) else v
                            for k, v in node_data.items()
                        },
                    },
                }
            )

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append(
                {
                    "source": u,
                    "target": v,
                    "data": {
                        **{
                            k: str(val) if isinstance(val, datetime) else val
                            for k, val in data.items()
                        },
                    },
                }
            )

        return {"nodes": nodes, "edges": edges}

    def add_known_bad_address(self, address: str) -> None:
        """Add an address to the known bad set."""
        self._known_bad_set.add(address.lower())
        if self.graph.has_node(address.lower()):
            self.graph.nodes[address.lower()]["is_known_bad"] = True
