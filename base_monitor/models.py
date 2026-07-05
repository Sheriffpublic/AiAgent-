"""Data models for the Base blockchain monitor."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class MonitoredTx:
    """Parsed transaction with enrichment."""
    hash: str
    from_address: str
    to_address: str | None
    value_wei: int
    gas_price: int
    block_number: int
    timestamp: datetime
    input_data: str
    method_id: str
    contract_address: str | None = None
    logs: list[dict] = field(default_factory=list)
    block_hash: str = ""
    nonce: int = 0
    tx_index: int = 0
    gas_used: int = 0
    status: int = 1  # 1 = success, 0 = revert

    @property
    def value_eth(self) -> float:
        return self.value_wei / 1e18

    @property
    def gas_price_gwei(self) -> float:
        return self.gas_price / 1e9

    @property
    def is_contract_creation(self) -> bool:
        return self.to_address is None


@dataclass
class Alert:
    """Detection result from heuristic engine."""
    id: str
    severity: str  # low, medium, high, critical
    category: str
    title: str
    description: str
    tx_hash: str
    from_address: str
    to_address: str | None
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)
    behavior_patterns: list[str] = field(default_factory=list)

    @property
    def severity_order(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(self.severity, 0)


@dataclass
class WalletNode:
    """Graph vertex representing a wallet."""
    address: str
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    total_received_wei: int = 0
    total_sent_wei: int = 0
    tx_count: int = 0
    labels: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    is_known_bad: bool = False

    @property
    def total_received_eth(self) -> float:
        return self.total_received_wei / 1e18

    @property
    def total_sent_eth(self) -> float:
        return self.total_sent_wei / 1e18


@dataclass
class FundEdge:
    """Directed edge representing a fund transfer."""
    from_addr: str
    to_addr: str
    value_wei: int
    tx_hash: str
    timestamp: datetime
    block_number: int

    @property
    def value_eth(self) -> float:
        return self.value_wei / 1e18


@dataclass
class WalletCluster:
    """Grouped related wallets."""
    addresses: list[str]
    total_volume_wei: int = 0
    shared_counterparties: int = 0
    risk_score: float = 0.0

    @property
    def total_volume_eth(self) -> float:
        return self.total_volume_wei / 1e18


@dataclass
class HeuristicResult:
    """Single rule match from heuristic engine."""
    rule_name: str
    rule_id: str
    severity: str
    matched_addresses: list[str]
    evidence: dict[str, Any]
    confidence: float = 1.0
    description: str = ""


@dataclass
class FlowPath:
    """A single path in fund tracing."""
    path: list[str]
    total_wei: int
    tx_hashes: list[str] = field(default_factory=list)

    @property
    def total_eth(self) -> float:
        return self.total_wei / 1e18


@dataclass
class TraceResult:
    """Result of fund tracing for an address."""
    origin: str
    upstream_flows: list[FlowPath] = field(default_factory=list)
    downstream_flows: list[FlowPath] = field(default_factory=list)
    total_inflow_wei: int = 0
    total_outflow_wei: int = 0
    unique_senders: int = 0
    unique_receivers: int = 0
    risk_score: float = 0.0

    @property
    def total_inflow_eth(self) -> float:
        return self.total_inflow_wei / 1e18

    @property
    def total_outflow_eth(self) -> float:
        return self.total_outflow_wei / 1e18
