"""Real-time transaction scanner and preprocessor."""

import asyncio
import logging
from collections import OrderedDict
from typing import TYPE_CHECKING

from .config import Config
from .models import Alert, MonitoredTx

if TYPE_CHECKING:
    from .chain import BaseChainClient
    from .heuristics import HeuristicEngine
    from .fund_tracer import FundTracer
    from .alerts import AlertManager

logger = logging.getLogger(__name__)


class LRU:
    """Simple LRU cache for transaction deduplication."""

    def __init__(self, maxsize: int = 10_000):
        self._cache: OrderedDict[str, bool] = OrderedDict()
        self._maxsize = maxsize

    def __contains__(self, key: str) -> bool:
        if key in self._cache:
            self._cache.move_to_end(key)
            return True
        return False

    def add(self, key: str) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            self._cache[key] = True
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)


class TransactionScanner:
    """Consumes raw blocks/txs from chain, processes through pipeline."""

    def __init__(
        self,
        config: Config,
        chain: "BaseChainClient",
        heuristics: "HeuristicEngine",
        tracer: "FundTracer",
        alert_mgr: "AlertManager",
    ):
        self.config = config
        self.chain = chain
        self.heuristics = heuristics
        self.tracer = tracer
        self.alert_mgr = alert_mgr
        self._running = False
        self._seen_txs = LRU(maxsize=config.lru_cache_size)
        self._tasks: list[asyncio.Task] = []
        self._processed_count = 0
        self._alert_count = 0

    async def start(self) -> None:
        """Launch block + pending scan tasks concurrently."""
        if self._running:
            logger.warning("Scanner already running")
            return

        self._running = True
        self._tasks = [
            asyncio.create_task(self._scan_blocks(), name="block_scanner"),
            asyncio.create_task(self._scan_pending(), name="pending_scanner"),
        ]
        logger.debug("Transaction scanner started")

    async def stop(self) -> None:
        """Cancel all tasks, wait for graceful shutdown."""
        self._running = False
        for task in self._tasks:
            task.cancel()

        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.debug(
            f"Scanner stopped. Processed {self._processed_count} txs, "
            f"fired {self._alert_count} alerts"
        )

    async def _scan_blocks(self) -> None:
        """Main loop: subscribe to newHeads, fetch full txs, process."""
        logger.debug("Block scanner started")
        try:
            async for block_data in self.chain.subscribe_new_blocks():
                if not self._running:
                    break

                # Handle both hex strings and integers
                block_number_raw = block_data.get("number", 0)
                if isinstance(block_number_raw, str):
                    block_number = int(block_number_raw, 16)
                else:
                    block_number = int(block_number_raw)

                try:
                    transactions = await self.chain.get_block_transactions(
                        block_number
                    )
                    # Only log if there are transactions
                    if transactions:
                        logger.info(f"Block #{block_number}: {len(transactions)} txs")
                    for tx in transactions:
                        await self._process_transaction(tx)

                except Exception as e:
                    logger.debug(f"Block {block_number}: {e}")
                    continue

        except asyncio.CancelledError:
            logger.debug("Block scanner cancelled")
        except Exception as e:
            logger.error(f"Block scanner error: {e}")

    async def _scan_pending(self) -> None:
        """Subscribe to pending txs for early detection (best-effort)."""
        logger.debug("Pending tx scanner started")
        try:
            async for tx_hash in self.chain.subscribe_pending_txs():
                if not self._running:
                    break

                # Skip if already seen
                if tx_hash in self._seen_txs:
                    continue

                try:
                    tx = await self.chain.get_full_transaction(tx_hash)
                    await self._process_transaction(tx, is_pending=True)
                except Exception:
                    # Pending txs may not be available yet - this is normal
                    continue

        except asyncio.CancelledError:
            logger.debug("Pending scanner cancelled")
        except Exception as e:
            logger.debug(f"Pending scanner: {e}")

    async def _process_transaction(
        self, tx: MonitoredTx, is_pending: bool = False
    ) -> None:
        """Process a single transaction through the pipeline."""
        # Dedup check
        if tx.hash in self._seen_txs:
            return
        self._seen_txs.add(tx.hash)

        self._processed_count += 1

        # Skip failed transactions
        if tx.status == 0:
            return

        # Run heuristics
        try:
            results = self.heuristics.evaluate(tx)
        except Exception as e:
            logger.error(f"Heuristic evaluation error for {tx.hash}: {e}")
            results = []

        # Record in fund tracer
        try:
            self.tracer.record_transaction(tx)
        except Exception as e:
            logger.error(f"Fund tracer error for {tx.hash}: {e}")

        # Dispatch alerts
        if results:
            try:
                self.alert_mgr.process_results(results, tx)
                self._alert_count += len(results)
            except Exception as e:
                logger.error(f"Alert dispatch error for {tx.hash}: {e}")

        # Log progress periodically
        if self._processed_count % 100 == 0:
            logger.info(
                f"Processed {self._processed_count} txs, "
                f"fired {self._alert_count} alerts"
            )

    def get_stats(self) -> dict:
        """Get scanner statistics."""
        return {
            "running": self._running,
            "processed_count": self._processed_count,
            "alert_count": self._alert_count,
            "cache_size": len(self._seen_txs._cache),
        }
