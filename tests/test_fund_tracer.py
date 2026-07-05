"""Tests for the fund tracer."""

from datetime import datetime, timezone

import pytest

from base_monitor.config import Config
from base_monitor.fund_tracer import FundTracer
from base_monitor.models import MonitoredTx


@pytest.fixture
def config():
    return Config(max_trace_depth=5)


@pytest.fixture
def tracer(config):
    return FundTracer(config)


def make_tx(
    from_addr: str,
    to_addr: str,
    value_eth: float = 1.0,
    tx_hash: str = "0xtx",
    block: int = 100,
) -> MonitoredTx:
    """Create a test transaction."""
    return MonitoredTx(
        hash=tx_hash,
        from_address=from_addr,
        to_address=to_addr,
        value_wei=int(value_eth * 1e18),
        gas_price=1000000000,
        block_number=block,
        timestamp=datetime.now(timezone.utc),
        input_data="0x",
        method_id="0x",
    )


class TestFundTracer:
    def test_record_transaction(self, tracer):
        tx = make_tx("0xaaa", "0xbbb", value_eth=5.0)
        tracer.record_transaction(tx)

        assert tracer.graph.has_node("0xaaa")
        assert tracer.graph.has_node("0xbbb")
        assert tracer.graph.has_edge("0xaaa", "0xbbb")

    def test_get_wallet_info(self, tracer):
        tx = make_tx("0xaaa", "0xbbb", value_eth=5.0)
        tracer.record_transaction(tx)

        info = tracer.get_wallet_info("0xaaa")
        assert info is not None
        assert info.address == "0xaaa"
        assert info.total_sent_wei == int(5.0 * 1e18)

    def test_trace_funds_downstream(self, tracer):
        # Create chain: A -> B -> C
        tracer.record_transaction(make_tx("0xaaa", "0xbbb", 10.0, "tx1"))
        tracer.record_transaction(make_tx("0xbbb", "0xccc", 5.0, "tx2"))

        result = tracer.trace_funds("0xaaa")
        assert result.origin == "0xaaa"
        assert len(result.downstream_flows) > 0

    def test_trace_funds_upstream(self, tracer):
        # Create chain: A -> B -> C
        tracer.record_transaction(make_tx("0xaaa", "0xbbb", 10.0, "tx1"))
        tracer.record_transaction(make_tx("0xbbb", "0xccc", 5.0, "tx2"))

        result = tracer.trace_funds("0xccc")
        assert result.origin == "0xccc"
        assert len(result.upstream_flows) > 0

    def test_find_clusters(self, tracer):
        # Create connected cluster
        tracer.record_transaction(make_tx("0xaaa", "0xbbb", 1.0, "tx1"))
        tracer.record_transaction(make_tx("0xbbb", "0xaaa", 0.5, "tx2"))
        tracer.record_transaction(make_tx("0xccc", "0xddd", 1.0, "tx3"))

        clusters = tracer.find_clusters()
        assert len(clusters) >= 1

    def test_compute_risk_scores(self, tracer):
        tx = make_tx("0xaaa", "0xbbb", 5.0)
        tracer.record_transaction(tx)

        tracer.compute_risk_scores()
        node = tracer.graph.nodes["0xaaa"]
        assert "risk_score" in node

    def test_export_graph(self, tracer):
        tx = make_tx("0xaaa", "0xbbb", 5.0)
        tracer.record_transaction(tx)

        export = tracer.export_graph()
        assert "nodes" in export
        assert "edges" in export
        assert len(export["nodes"]) == 2
        assert len(export["edges"]) == 1
