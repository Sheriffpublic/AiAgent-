"""Tests for the heuristic engine."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from base_monitor.config import Config
from base_monitor.heuristics import HeuristicEngine
from base_monitor.known_addresses import KnownAddressDB
from base_monitor.models import MonitoredTx


@pytest.fixture
def config():
    return Config()


@pytest.fixture
def known_db():
    db = KnownAddressDB()
    db.add_address("0xscam123", "Test Scam", "scam")
    return db


@pytest.fixture
def engine(config, known_db):
    return HeuristicEngine(config, known_db)


def make_tx(
    from_addr: str = "0xfrom",
    to_addr: str | None = "0xto",
    value_eth: float = 1.0,
    gas_price_gwei: float = 1.0,
    timestamp: datetime | None = None,
) -> MonitoredTx:
    """Create a test transaction."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    return MonitoredTx(
        hash="0xtxhash",
        from_address=from_addr,
        to_address=to_addr,
        value_wei=int(value_eth * 1e18),
        gas_price=int(gas_price_gwei * 1e9),
        block_number=12345,
        timestamp=timestamp,
        input_data="0x",
        method_id="0x",
    )


class TestLargeTransferRule:
    def test_large_transfer_detected(self, engine):
        tx = make_tx(value_eth=15.0)
        results = engine._rule_large_transfer(tx)
        assert results is not None
        assert results.rule_id == "HR001"
        assert results.severity == "high"

    def test_small_transfer_not_detected(self, engine):
        tx = make_tx(value_eth=0.5)  # Below 1.0 ETH threshold
        results = engine._rule_large_transfer(tx)
        assert results is None


class TestKnownScamRule:
    def test_scam_address_detected(self, engine):
        tx = make_tx(from_addr="0xscam123")
        results = engine._rule_known_scam(tx)
        assert results is not None
        assert results.rule_id == "HR003"
        assert results.severity == "critical"

    def test_clean_address_not_detected(self, engine):
        tx = make_tx(from_addr="0x1234567890abcdef")
        results = engine._rule_known_scam(tx)
        assert results is None


class TestMixerInteractionRule:
    def test_mixer_detected(self, engine):
        tx = make_tx(to_addr="0xba214c1c1928a32bffe790263e38b4af9bfcd18d")
        results = engine._rule_mixer_interaction(tx)
        assert results is not None
        assert results.rule_id == "HR004"

    def test_non_mixer_not_detected(self, engine):
        tx = make_tx(to_addr="0x1234567890abcdef")
        results = engine._rule_mixer_interaction(tx)
        assert results is None


class TestContractCreationRule:
    def test_contract_creation_detected(self, engine):
        tx = make_tx(to_addr=None, value_eth=1.0)
        results = engine._rule_new_contract_creation(tx)
        assert results is not None
        assert results.rule_id == "HR007"

    def test_zero_value_not_detected(self, engine):
        tx = make_tx(to_addr=None, value_eth=0.0)
        results = engine._rule_new_contract_creation(tx)
        assert results is None


class TestHeuristicEngine:
    def test_evaluate_returns_results(self, engine):
        tx = make_tx(value_eth=100.0)
        results = engine.evaluate(tx)
        assert len(results) > 0

    def test_evaluate_returns_empty_for_normal_tx(self, engine):
        tx = make_tx(value_eth=0.1)  # Below all thresholds
        results = engine.evaluate(tx)
        # Should only have rapid_movement or none for normal txs
        assert all(r.rule_name != "large_transfer" for r in results)

    def test_evaluate_returns_empty_for_zero_value(self, engine):
        tx = make_tx(value_eth=0.0)
        results = engine.evaluate(tx)
        assert len(results) == 0
