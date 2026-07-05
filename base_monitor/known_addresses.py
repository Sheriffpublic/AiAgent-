"""Known address database for scam/mixer/exchange addresses."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class KnownAddressDB:
    """Maintains a queryable database of known addresses with labels."""

    def __init__(self):
        self._addresses: dict[str, dict[str, str]] = {}

    def load_from_file(self, path: str | Path) -> None:
        """Load known addresses from a JSON file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for entry in data.get("addresses", []):
                address = entry.get("address", "").lower()
                label = entry.get("label", "Unknown")
                category = entry.get("category", "unknown")
                self._addresses[address] = {
                    "label": label,
                    "category": category,
                }

            logger.info(
                f"Loaded {len(self._addresses)} known addresses from {path}"
            )
        except FileNotFoundError:
            logger.warning(f"Known addresses file not found: {path}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse known addresses file: {e}")

    def is_known_bad(self, address: str) -> bool:
        """Check if an address is known to be bad/scam."""
        address_lower = address.lower()
        entry = self._addresses.get(address_lower)
        if not entry:
            return False
        return entry.get("category", "").lower() in {
            "scam",
            "sanctioned",
            "malicious",
            "exploit",
        }

    def get_label(self, address: str) -> str | None:
        """Get the label for a known address."""
        entry = self._addresses.get(address.lower())
        return entry.get("label") if entry else None

    def get_category(self, address: str) -> str | None:
        """Get the category for a known address."""
        entry = self._addresses.get(address.lower())
        return entry.get("category") if entry else None

    def add_address(
        self, address: str, label: str, category: str
    ) -> None:
        """Add an address to the database."""
        self._addresses[address.lower()] = {
            "label": label,
            "category": category,
        }

    def get_all_bad_addresses(self) -> list[str]:
        """Get all known bad addresses."""
        return [
            addr
            for addr, data in self._addresses.items()
            if data.get("category", "").lower()
            in {"scam", "sanctioned", "malicious", "exploit"}
        ]

    def get_by_category(self, category: str) -> list[dict[str, str]]:
        """Get all addresses in a category."""
        return [
            {"address": addr, **data}
            for addr, data in self._addresses.items()
            if data.get("category", "").lower() == category.lower()
        ]

    def export(self) -> dict[str, Any]:
        """Export database as JSON-serializable dict."""
        return {
            "addresses": [
                {"address": addr, **data}
                for addr, data in self._addresses.items()
            ]
        }

    def save_to_file(self, path: str | Path) -> None:
        """Save database to a JSON file."""
        data = self.export()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {len(self._addresses)} addresses to {path}")
