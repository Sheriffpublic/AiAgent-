"""Rule engine for suspicious behavior detection."""

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .config import Config
from .constants import (
    FLASH_LOAN_PROVIDERS,
    KNOWN_BRIDGES,
    KNOWN_MIXERS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from .known_addresses import KnownAddressDB
from .models import HeuristicResult, MonitoredTx

logger = logging.getLogger(__name__)


class HeuristicEngine:
    """Evaluates transactions against configurable heuristic rules."""

    def __init__(self, config: Config, known_db: KnownAddressDB):
        self.config = config
        self.known_db = known_db
        self._recent_activity: dict[str, list[float]] = defaultdict(list)
        self._recent_values: dict[str, list[int]] = defaultdict(list)

        self._rules: list[Callable[[MonitoredTx], HeuristicResult | None]] = [
            self._rule_large_transfer,
            self._rule_rapid_movement,
            self._rule_known_scam,
            self._rule_mixer_interaction,
            self._rule_flash_loan,
            self._rule_unusual_gas,
            self._rule_new_contract_creation,
            self._rule_high_frequency_sender,
            self._rule_bridge_suspicious,
            self._rule_value_obfuscation,
        ]

    def evaluate(self, tx: MonitoredTx) -> list[HeuristicResult]:
        """Run all enabled rules, return non-None results."""
        # Filter by minimum alert value threshold
        if tx.value_eth < self.config.min_alert_value_eth:
            return []

        results = []
        for rule in self._rules:
            try:
                result = rule(tx)
                if result is not None:
                    results.append(result)
            except Exception as e:
                logger.error(f"Rule {rule.__name__} failed: {e}")
                continue
        return results

    def _rule_large_transfer(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG if native transfer exceeds configurable threshold."""
        if tx.value_eth < self.config.large_transfer_threshold_eth:
            return None

        return HeuristicResult(
            rule_name="large_transfer",
            rule_id="HR001",
            severity=SEVERITY_HIGH,
            matched_addresses=[tx.from_address, tx.to_address]
            if tx.to_address
            else [tx.from_address],
            evidence={
                "value_eth": tx.value_eth,
                "threshold_eth": self.config.large_transfer_threshold_eth,
                "multiplier": tx.value_eth
                / self.config.large_transfer_threshold_eth,
            },
            confidence=min(1.0, tx.value_eth / (self.config.large_transfer_threshold_eth * 5)),
            description=f"Large transfer: {tx.value_eth:.2f} ETH",
        )

    def _rule_rapid_movement(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG if sender made many transactions within time window."""
        now = tx.timestamp.timestamp() if isinstance(tx.timestamp, datetime) else tx.timestamp
        window = self.config.rapid_movement_window_seconds

        self._recent_activity[tx.from_address].append(now)
        cutoff = now - window
        self._recent_activity[tx.from_address] = [
            t for t in self._recent_activity[tx.from_address] if t > cutoff
        ]

        count = len(self._recent_activity[tx.from_address])
        if count < self.config.rapid_movement_count:
            return None

        return HeuristicResult(
            rule_name="rapid_movement",
            rule_id="HR002",
            severity=SEVERITY_MEDIUM,
            matched_addresses=[tx.from_address],
            evidence={
                "tx_count": count,
                "window_seconds": window,
                "threshold": self.config.rapid_movement_count,
            },
            confidence=min(1.0, count / (self.config.rapid_movement_count * 3)),
            description=f"Rapid movement: {count} txs in {window}s",
        )

    def _rule_known_scam(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG if from/to address is in known scam database."""
        flagged = []
        if self.known_db.is_known_bad(tx.from_address):
            flagged.append(("from", tx.from_address))
        if tx.to_address and self.known_db.is_known_bad(tx.to_address):
            flagged.append(("to", tx.to_address))

        if not flagged:
            return None

        evidence = {
            "flagged_addresses": [
                {"role": role, "address": addr, "label": self.known_db.get_label(addr)}
                for role, addr in flagged
            ]
        }

        return HeuristicResult(
            rule_name="known_scam",
            rule_id="HR003",
            severity=SEVERITY_CRITICAL,
            matched_addresses=[addr for _, addr in flagged],
            evidence=evidence,
            confidence=1.0,
            description=f"Known scam address interaction: {len(flagged)} address(es)",
        )

    def _rule_mixer_interaction(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG if tx interacts with known mixer contracts."""
        interacted_mixers = []
        if tx.to_address and tx.to_address.lower() in {
            addr.lower() for addr in KNOWN_MIXERS
        }:
            interacted_mixers.append(tx.to_address)

        if tx.from_address.lower() in {addr.lower() for addr in KNOWN_MIXERS}:
            interacted_mixers.append(tx.from_address)

        if not interacted_mixers:
            return None

        return HeuristicResult(
            rule_name="mixer_interaction",
            rule_id="HR004",
            severity=SEVERITY_HIGH,
            matched_addresses=interacted_mixers,
            evidence={
                "mixer_addresses": interacted_mixers,
                "mixer_names": [
                    KNOWN_MIXERS.get(addr.lower(), "Unknown Mixer")
                    for addr in interacted_mixers
                ],
            },
            confidence=1.0,
            description="Mixer contract interaction detected",
        )

    def _rule_flash_loan(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG suspected flash loan attack patterns."""
        # Check if interacting with flash loan providers
        provider_hit = False
        provider_name = None
        if tx.to_address:
            for provider_addr, name in FLASH_LOAN_PROVIDERS.items():
                if tx.to_address.lower() == provider_addr.lower():
                    provider_hit = True
                    provider_name = name
                    break

        # Check for high-value interaction with provider
        if provider_hit and tx.value_eth > self.config.flash_loan_value_threshold_eth:
            return HeuristicResult(
                rule_name="flash_loan",
                rule_id="HR005",
                severity=SEVERITY_CRITICAL,
                matched_addresses=[tx.from_address, tx.to_address]
                if tx.to_address
                else [tx.from_address],
                evidence={
                    "provider": provider_name,
                    "value_eth": tx.value_eth,
                    "threshold_eth": self.config.flash_loan_value_threshold_eth,
                },
                confidence=0.8,
                description=f"Flash loan pattern: {tx.value_eth:.2f} ETH via {provider_name}",
            )

        return None

    def _rule_unusual_gas(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG abnormally high gas price."""
        # Calculate average gas from recent transactions
        now = tx.timestamp.timestamp() if isinstance(tx.timestamp, datetime) else tx.timestamp
        avg_gas = self._calculate_average_gas(tx.from_address, now)

        if avg_gas == 0:
            return None

        gas_ratio = tx.gas_price / avg_gas
        if gas_ratio < self.config.unusual_gas_multiplier:
            return None

        return HeuristicResult(
            rule_name="unusual_gas",
            rule_id="HR006",
            severity=SEVERITY_MEDIUM,
            matched_addresses=[tx.from_address],
            evidence={
                "gas_price_gwei": tx.gas_price_gwei,
                "average_gas_gwei": avg_gas / 1e9,
                "ratio": gas_ratio,
                "multiplier_threshold": self.config.unusual_gas_multiplier,
            },
            confidence=min(1.0, gas_ratio / (self.config.unusual_gas_multiplier * 3)),
            description=f"Unusual gas: {gas_ratio:.1f}x average",
        )

    def _rule_new_contract_creation(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG new contract creation with non-zero value."""
        if not tx.is_contract_creation:
            return None
        if tx.value_wei == 0:
            return None

        return HeuristicResult(
            rule_name="contract_creation",
            rule_id="HR007",
            severity=SEVERITY_LOW,
            matched_addresses=[tx.from_address],
            evidence={
                "value_eth": tx.value_eth,
                "input_data_length": len(tx.input_data),
            },
            confidence=0.6,
            description=f"Contract creation with {tx.value_eth:.4f} ETH value",
        )

    def _rule_high_frequency_sender(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG address sending at bot-like frequency."""
        now = tx.timestamp.timestamp() if isinstance(tx.timestamp, datetime) else tx.timestamp
        one_hour_ago = now - 3600

        self._recent_activity[tx.from_address].append(now)
        hourly_count = len(
            [t for t in self._recent_activity[tx.from_address] if t > one_hour_ago]
        )

        if hourly_count < self.config.high_frequency_tx_per_hour:
            return None

        return HeuristicResult(
            rule_name="high_frequency_sender",
            rule_id="HR008",
            severity=SEVERITY_MEDIUM,
            matched_addresses=[tx.from_address],
            evidence={
                "tx_count_per_hour": hourly_count,
                "threshold": self.config.high_frequency_tx_per_hour,
            },
            confidence=min(1.0, hourly_count / (self.config.high_frequency_tx_per_hour * 2)),
            description=f"High frequency: {hourly_count} txs/hour",
        )

    def _rule_bridge_suspicious(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG suspicious bridge interactions."""
        if not tx.to_address:
            return None

        to_lower = tx.to_address.lower()
        is_bridge = any(
            addr.lower() == to_lower for addr in KNOWN_BRIDGES
        )

        if not is_bridge:
            return None

        # Check if interacting with known bad address
        is_suspicious = (
            self.known_db.is_known_bad(tx.from_address)
            or self.known_db.is_known_bad(tx.to_address)
        )

        if not is_suspicious:
            return None

        return HeuristicResult(
            rule_name="bridge_suspicious",
            rule_id="HR009",
            severity=SEVERITY_HIGH,
            matched_addresses=[tx.from_address, tx.to_address],
            evidence={
                "bridge_address": tx.to_address,
                "value_eth": tx.value_eth,
                "flagged_addresses": [
                    addr
                    for addr in [tx.from_address, tx.to_address]
                    if self.known_db.is_known_bad(addr)
                ],
            },
            confidence=0.9,
            description="Suspicious bridge interaction with flagged address",
        )

    def _rule_value_obfuscation(
        self, tx: MonitoredTx
    ) -> HeuristicResult | None:
        """FLAG many small transfers to same destination (structuring)."""
        if tx.value_eth > 1.0:
            return None

        if not tx.to_address:
            return None

        now = tx.timestamp.timestamp() if isinstance(tx.timestamp, datetime) else tx.timestamp
        window = 600  # 10 minutes

        self._recent_values[(tx.from_address, tx.to_address)].append(
            (now, tx.value_wei)
        )
        cutoff = now - window
        self._recent_values[(tx.from_address, tx.to_address)] = [
            (t, v)
            for t, v in self._recent_values[(tx.from_address, tx.to_address)]
            if t > cutoff
        ]

        transfers = self._recent_values[(tx.from_address, tx.to_address)]
        if len(transfers) < 5:
            return None

        total_value = sum(v for _, v in transfers)
        if total_value < 10**18:  # Less than 1 ETH total
            return None

        return HeuristicResult(
            rule_name="value_obfuscation",
            rule_id="HR010",
            severity=SEVERITY_MEDIUM,
            matched_addresses=[tx.from_address, tx.to_address],
            evidence={
                "transfer_count": len(transfers),
                "total_value_eth": total_value / 1e18,
                "window_seconds": window,
                "average_value_eth": (total_value / len(transfers)) / 1e18,
            },
            confidence=min(1.0, len(transfers) / 15),
            description=f"Value obfuscation: {len(transfers)} small txs to same address",
        )

    def _calculate_average_gas(self, address: str, now: float) -> int:
        """Calculate average gas price for an address over recent activity."""
        window = 3600  # 1 hour
        cutoff = now - window
        recent = [
            t for t in self._recent_activity.get(address, []) if t > cutoff
        ]
        if not recent:
            return 0
        # This is a simplified calculation - in production, store gas prices
        # For now, return a baseline average
        return int(1e9)  # 1 Gwei baseline
