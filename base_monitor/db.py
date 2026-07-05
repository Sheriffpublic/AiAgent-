"""Optional SQLite persistence for graph data and alert history."""

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class MonitorDB:
    """Optional SQLite persistence for the monitor."""

    def __init__(self, sqlite_path: str | None):
        self.sqlite_path = sqlite_path
        self._db = None

    async def initialize(self) -> None:
        """Initialize the database if path is provided."""
        if not self.sqlite_path:
            return

        try:
            import aiosqlite

            self._db = await aiosqlite.connect(self.sqlite_path)
            await self._create_tables()
            logger.info(f"Database initialized at {self.sqlite_path}")
        except ImportError:
            logger.warning(
                "aiosqlite not installed, persistence disabled"
            )
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")

    async def _create_tables(self) -> None:
        """Create database tables."""
        if not self._db:
            return

        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                severity TEXT,
                category TEXT,
                title TEXT,
                description TEXT,
                tx_hash TEXT,
                from_address TEXT,
                to_address TEXT,
                timestamp TEXT,
                metadata TEXT
            )
        """)

        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS wallets (
                address TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                total_received_wei INTEGER,
                total_sent_wei INTEGER,
                tx_count INTEGER,
                risk_score REAL,
                is_known_bad INTEGER
            )
        """)

        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_addr TEXT,
                to_addr TEXT,
                value_wei INTEGER,
                tx_hash TEXT,
                timestamp TEXT,
                block_number INTEGER,
                UNIQUE(from_addr, to_addr, tx_hash)
            )
        """)

        await self._db.commit()

    async def save_alert(self, alert: dict[str, Any]) -> None:
        """Save an alert to the database."""
        if not self._db:
            return

        try:
            await self._db.execute(
                """
                INSERT OR REPLACE INTO alerts
                (id, severity, category, title, description, tx_hash,
                 from_address, to_address, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.get("id"),
                    alert.get("severity"),
                    alert.get("category"),
                    alert.get("title"),
                    alert.get("description"),
                    alert.get("tx_hash"),
                    alert.get("from"),
                    alert.get("to"),
                    alert.get("timestamp"),
                    json.dumps(alert.get("metadata", {})),
                ),
            )
            await self._db.commit()
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")

    async def save_wallet(self, wallet: dict[str, Any]) -> None:
        """Save wallet data to the database."""
        if not self._db:
            return

        try:
            await self._db.execute(
                """
                INSERT OR REPLACE INTO wallets
                (address, first_seen, last_seen, total_received_wei,
                 total_sent_wei, tx_count, risk_score, is_known_bad)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    wallet.get("address"),
                    wallet.get("first_seen"),
                    wallet.get("last_seen"),
                    wallet.get("total_received_wei", 0),
                    wallet.get("total_sent_wei", 0),
                    wallet.get("tx_count", 0),
                    wallet.get("risk_score", 0.0),
                    1 if wallet.get("is_known_bad", False) else 0,
                ),
            )
            await self._db.commit()
        except Exception as e:
            logger.error(f"Failed to save wallet: {e}")

    async def save_edge(self, edge: dict[str, Any]) -> None:
        """Save an edge to the database."""
        if not self._db:
            return

        try:
            await self._db.execute(
                """
                INSERT OR IGNORE INTO edges
                (from_addr, to_addr, value_wei, tx_hash, timestamp, block_number)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    edge.get("from_addr"),
                    edge.get("to_addr"),
                    edge.get("value_wei", 0),
                    edge.get("tx_hash"),
                    edge.get("timestamp"),
                    edge.get("block_number", 0),
                ),
            )
            await self._db.commit()
        except Exception as e:
            logger.error(f"Failed to save edge: {e}")

    async def get_alerts(
        self,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get alerts with optional filters."""
        if not self._db:
            return []

        try:
            query = "SELECT * FROM alerts"
            params: list[Any] = []

            if filters:
                conditions = []
                if "severity" in filters:
                    conditions.append("severity = ?")
                    params.append(filters["severity"])
                if "category" in filters:
                    conditions.append("category = ?")
                    params.append(filters["category"])
                if "from_address" in filters:
                    conditions.append("from_address = ?")
                    params.append(filters["from_address"])

                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = await self._db.execute(query, params)
            rows = await cursor.fetchall()

            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []

    async def get_wallet_history(
        self, address: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Get transaction history for a wallet."""
        if not self._db:
            return []

        try:
            cursor = await self._db.execute(
                """
                SELECT * FROM edges
                WHERE from_addr = ? OR to_addr = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (address, address, limit),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get wallet history: {e}")
            return []

    async def close(self) -> None:
        """Close the database connection."""
        if self._db:
            await self._db.close()
            logger.info("Database connection closed")
