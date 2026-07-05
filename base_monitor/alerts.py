"""Alert management and dispatch."""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from .config import Config
from .models import Alert, HeuristicResult, MonitoredTx

if TYPE_CHECKING:
    from .fund_tracer import FundTracer
    from .known_addresses import KnownAddressDB
    from .output import OutputManager

logger = logging.getLogger(__name__)


class AlertManager:
    """Aggregates heuristic results into alerts, deduplicates, and dispatches."""

    def __init__(
        self,
        config: Config,
        output: "OutputManager",
        tracer: "FundTracer | None" = None,
        known_db: "KnownAddressDB | None" = None,
    ):
        self.config = config
        self.output = output
        self.tracer = tracer
        self.known_db = known_db
        self._cooldown_cache: dict[str, datetime] = defaultdict(
            lambda: datetime.min.replace(tzinfo=timezone.utc)
        )
        self._alert_count = 0
        self._suppressed_count = 0
        # Track behavior patterns per address
        self._address_patterns: dict[str, list[str]] = defaultdict(list)

    def process_results(
        self, results: list[HeuristicResult], tx: MonitoredTx
    ) -> None:
        """Process heuristic results into alerts."""
        for result in results:
            alert = self._create_alert(result, tx)

            if self._should_suppress(alert):
                self._suppressed_count += 1
                continue

            self._dispatch_alert(alert)
            self._alert_count += 1

    def _create_alert(
        self, result: HeuristicResult, tx: MonitoredTx
    ) -> Alert:
        """Create an alert from a heuristic result."""
        alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"

        severity = result.severity
        if result.confidence < 0.5:
            severity = "low"
        elif result.confidence < 0.7:
            severity = "medium"

        # Get risk scores from tracer
        from_risk = 0.0
        to_risk = 0.0
        from_label = ""
        to_label = ""

        if self.tracer:
            from_wallet = self.tracer.get_wallet_info(tx.from_address)
            if from_wallet:
                from_risk = from_wallet.risk_score
            if tx.to_address:
                to_wallet = self.tracer.get_wallet_info(tx.to_address)
                if to_wallet:
                    to_risk = to_wallet.risk_score

        # Get labels from known DB
        if self.known_db:
            from_label = self.known_db.get_label(tx.from_address) or ""
            if tx.to_address:
                to_label = self.known_db.get_label(tx.to_address) or ""

        # Detect behavior patterns
        behavior_patterns = self._detect_behavior_patterns(tx, result)

        # Track patterns for addresses
        for addr in [tx.from_address, tx.to_address]:
            if addr and result.rule_name not in self._address_patterns[addr]:
                self._address_patterns[addr].append(result.rule_name)

        return Alert(
            id=alert_id,
            severity=severity,
            category=result.rule_name,
            title=f"[{result.rule_id}] {result.rule_name.replace('_', ' ').title()}",
            description=result.description,
            tx_hash=tx.hash,
            from_address=tx.from_address,
            to_address=tx.to_address,
            timestamp=tx.timestamp,
            behavior_patterns=behavior_patterns,
            metadata={
                "rule_id": result.rule_id,
                "confidence": result.confidence,
                "matched_addresses": result.matched_addresses,
                "evidence": result.evidence,
                "value_eth": tx.value_eth,
                "gas_price_gwei": tx.gas_price_gwei,
                "from_risk_score": from_risk,
                "to_risk_score": to_risk,
                "from_label": from_label,
                "to_label": to_label,
                "behavior_pattern": behavior_patterns[0] if behavior_patterns else "",
            },
        )

    def _detect_behavior_patterns(
        self, tx: MonitoredTx, result: HeuristicResult
    ) -> list[str]:
        """Detect behavior patterns based on transaction and history."""
        patterns = []
        addr = tx.from_address

        # Get historical patterns for this address
        historical = self._address_patterns.get(addr, [])

        # Pattern detection rules
        if result.rule_name == "rapid_movement" and "high_frequency_sender" in historical:
            patterns.append("🤖 Bot Activity")

        if result.rule_name == "mixer_interaction":
            patterns.append("🌀 Tornado Cash User")

        if result.rule_name == "known_scam":
            patterns.append("☠️ Scam Interaction")

        if result.rule_name == "large_transfer" and tx.value_eth > 100:
            patterns.append("🐋 Whale Movement")

        if result.rule_name == "value_obfuscation":
            patterns.append("💸 Structuring Pattern")

        if result.rule_name == "flash_loan":
            patterns.append("⚡ Flash Loan Attack")

        if result.rule_name == "high_frequency_sender":
            patterns.append("🤖 High Frequency Bot")

        # Check for money laundering patterns
        if len(historical) >= 3 and "mixer_interaction" in historical:
            if result.rule_name == "rapid_movement":
                patterns.append("🔄 Suspected Laundering")

        # Check for rug pull patterns
        if result.rule_name == "contract_creation" and tx.value_eth > 10:
            patterns.append("🚨 Potential Rug Setup")

        # Check for MEV patterns
        if result.rule_name == "unusual_gas" and result.rule_name in historical:
            patterns.append("📈 MEV Activity")

        return patterns if patterns else ["⚡ Suspicious Activity"]

    def _should_suppress(self, alert: Alert) -> bool:
        """Check if alert should be suppressed due to cooldown."""
        cooldown_key = f"{alert.from_address}:{alert.to_address}:{alert.category}"
        now = datetime.now(timezone.utc)

        if now - self._cooldown_cache[cooldown_key] < timedelta(seconds=300):
            return True

        self._cooldown_cache[cooldown_key] = now
        return False

    def _dispatch_alert(self, alert: Alert) -> None:
        """Dispatch an alert to the output manager."""
        self.output.print_alert(alert)
        self.output.log_json(
            {
                "event": "alert",
                "id": alert.id,
                "severity": alert.severity,
                "category": alert.category,
                "title": alert.title,
                "description": alert.description,
                "tx_hash": alert.tx_hash,
                "from": alert.from_address,
                "to": alert.to_address,
                "timestamp": alert.timestamp.isoformat(),
                "metadata": alert.metadata,
            },
            event_type="alert",
        )

    def flush(self) -> None:
        """Flush any pending alerts."""
        logger.info(
            f"Alert manager stats: {self._alert_count} dispatched, "
            f"{self._suppressed_count} suppressed"
        )

    def get_stats(self) -> dict:
        """Get alert manager statistics."""
        return {
            "dispatched": self._alert_count,
            "suppressed": self._suppressed_count,
            "cooldown_entries": len(self._cooldown_cache),
        }

    def search_address(self, address: str) -> dict | None:
        """Search for an address and return its info."""
        if self.known_db:
            label = self.known_db.get_label(address)
            category = self.known_db.get_category(address)
            is_bad = self.known_db.is_known_bad(address)

            if label or category:
                risk = 1.0 if is_bad else 0.5
                return {
                    "address": address,
                    "label": label,
                    "category": category,
                    "risk_score": risk,
                    "is_known_bad": is_bad,
                }

        if self.tracer:
            wallet = self.tracer.get_wallet_info(address)
            if wallet:
                return {
                    "address": address,
                    "label": "",
                    "category": "",
                    "risk_score": wallet.risk_score,
                    "is_known_bad": wallet.is_known_bad,
                    "total_received_eth": wallet.total_received_eth,
                    "total_sent_eth": wallet.total_sent_eth,
                    "tx_count": wallet.tx_count,
                    "first_seen": str(wallet.first_seen),
                    "last_seen": str(wallet.last_seen),
                    "behavior_patterns": self._address_patterns.get(address, []),
                }

        return None
