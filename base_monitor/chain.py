"""Base chain WebSocket connection and interaction."""

import asyncio
import logging
import random
from datetime import datetime, timezone
from typing import AsyncIterator

from web3 import AsyncWeb3
from web3.providers import WebSocketProvider

from .config import Config
from .constants import (
    DEFAULT_BASE_RECONNECT_DELAY,
    DEFAULT_CIRCUIT_BREAKER_FAILURES,
    DEFAULT_CIRCUIT_BREAKER_TIMEOUT,
    DEFAULT_MAX_RECONNECT_DELAY,
)
from .models import MonitoredTx

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """Prevents hammering a failing RPC endpoint."""

    def __init__(
        self,
        failure_threshold: int = DEFAULT_CIRCUIT_BREAKER_FAILURES,
        recovery_timeout: float = DEFAULT_CIRCUIT_BREAKER_TIMEOUT,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.is_open = False
        self.last_failure_time: float = 0

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = asyncio.get_event_loop().time()
        if self.failure_count >= self.failure_threshold:
            self.is_open = True
            logger.warning(
                f"Circuit breaker opened after {self.failure_count} failures"
            )

    def record_success(self) -> None:
        self.failure_count = 0
        self.is_open = False

    def allow_request(self) -> bool:
        if not self.is_open:
            return True
        current_time = asyncio.get_event_loop().time()
        if current_time - self.last_failure_time >= self.recovery_timeout:
            logger.info("Circuit breaker half-open, allowing test request")
            return True
        return False


class BaseChainClient:
    """Manages WebSocket + HTTP connections to Base chain."""

    def __init__(self, config: Config):
        self.config = config
        self.w3: AsyncWeb3 | None = None
        self._connected = False
        self._reconnect_attempts = 0
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=config.circuit_breaker_failures,
            recovery_timeout=config.circuit_breaker_timeout,
        )
        self._last_block_number: int | None = None

    async def connect(self) -> None:
        """Establish WebSocket connection to Base."""
        try:
            self.w3 = await AsyncWeb3(
                WebSocketProvider(self.config.ws_url)
            ).__aenter__()

            # Verify connection
            chain_id = await self.w3.eth.chain_id
            if chain_id != self.config.chain_id:
                raise ConnectionError(
                    f"Connected to wrong chain: {chain_id} "
                    f"(expected {self.config.chain_id})"
                )

            self._connected = True
            self._reconnect_attempts = 0
            self._circuit_breaker.record_success()
            logger.debug(f"Connected to Base (chain ID: {chain_id})")

        except Exception as e:
            self._connected = False
            self._circuit_breaker.record_failure()
            raise

    async def disconnect(self) -> None:
        """Gracefully close WebSocket connection."""
        if self.w3 and self._connected:
            try:
                await self.w3.provider.disconnect()
            except Exception as e:
                logger.warning(f"Error during disconnect: {e}")
            finally:
                self._connected = False
                logger.info("Disconnected from Base")

    async def subscribe_new_blocks(self) -> AsyncIterator[dict]:
        """Yield block header dicts as they arrive."""
        while True:
            try:
                if not self._connected:
                    await self._reconnect_with_backoff()

                subscription = await self.w3.eth.subscribe("newHeads")
                logger.debug(f"Subscribed to newHeads: {subscription}")

                async for response in self.w3.socket.process_subscriptions():
                    # Handle subscription errors gracefully
                    if "error" in response:
                        error_msg = response["error"].get("message", "Unknown error")
                        logger.debug(f"Subscription error: {error_msg}")
                        if "timed out" in error_msg.lower():
                            await asyncio.sleep(1)
                            break
                        continue

                    if "result" in response:
                        block_data = response["result"]
                        if block_data is None:
                            continue
                        # Handle both hex strings and integers from web3.py v7
                        block_number_raw = block_data.get("number", 0)
                        if isinstance(block_number_raw, str):
                            self._last_block_number = int(block_number_raw, 16)
                        else:
                            self._last_block_number = int(block_number_raw)
                        yield block_data

            except asyncio.CancelledError:
                raise
            except Exception as e:
                # Connection lost - will reconnect
                self._connected = False
                self._circuit_breaker.record_failure()
                await asyncio.sleep(self.config.block_poll_interval)

    async def subscribe_pending_txs(self) -> AsyncIterator[str]:
        """Yield pending transaction hashes as they arrive."""
        while True:
            try:
                if not self._connected:
                    await self._reconnect_with_backoff()

                subscription = await self.w3.eth.subscribe(
                    "newPendingTransactions"
                )
                logger.debug(f"Subscribed to pending txs: {subscription}")

                async for response in self.w3.socket.process_subscriptions():
                    # Handle subscription errors gracefully
                    if "error" in response:
                        error_msg = response["error"].get("message", "Unknown error")
                        logger.debug(f"Pending tx subscription error: {error_msg}")
                        if "timed out" in error_msg.lower():
                            await asyncio.sleep(1)
                            break
                        continue

                    if "result" in response:
                        tx_hash = response["result"]
                        if tx_hash is None:
                            continue
                        yield tx_hash

            except asyncio.CancelledError:
                raise
            except Exception as e:
                # Connection lost - will reconnect
                self._connected = False
                self._circuit_breaker.record_failure()
                await asyncio.sleep(self.config.block_poll_interval)

    async def get_full_transaction(self, tx_hash: str) -> MonitoredTx:
        """Fetch full transaction + receipt, parse into MonitoredTx."""
        tx = await self.w3.eth.get_transaction(tx_hash)
        receipt = await self.w3.eth.get_transaction_receipt(tx_hash)

        block = await self.w3.eth.get_block(tx["blockNumber"])
        timestamp = datetime.fromtimestamp(block["timestamp"], tz=timezone.utc)

        # Handle both bytes and string formats from web3.py
        input_raw = tx.get("input", "0x")
        if isinstance(input_raw, bytes):
            input_data = input_raw.hex()
        else:
            input_data = input_raw
        if not input_data.startswith("0x"):
            input_data = "0x" + input_data
        method_id = input_data[:10] if len(input_data) >= 10 else input_data

        tx_hash_raw = tx["hash"]
        tx_hash_str = tx_hash_raw.hex() if isinstance(tx_hash_raw, bytes) else str(tx_hash_raw)
        if not tx_hash_str.startswith("0x"):
            tx_hash_str = "0x" + tx_hash_str

        block_hash_raw = tx["blockHash"]
        block_hash_str = block_hash_raw.hex() if isinstance(block_hash_raw, bytes) else str(block_hash_raw)
        if not block_hash_str.startswith("0x"):
            block_hash_str = "0x" + block_hash_str

        return MonitoredTx(
            hash=tx_hash_str,
            from_address=tx["from"],
            to_address=tx.get("to"),
            value_wei=tx["value"],
            gas_price=tx["gasPrice"],
            block_number=tx["blockNumber"],
            timestamp=timestamp,
            input_data=input_data,
            method_id=method_id,
            block_hash=block_hash_str,
            nonce=tx["nonce"],
            tx_index=tx["transactionIndex"],
            gas_used=receipt["gasUsed"],
            status=receipt.get("status", 1),
            logs=[dict(log) for log in receipt.get("logs", [])],
        )

    async def get_block_transactions(self, block_number: int) -> list[MonitoredTx]:
        """Fetch all transactions in a block with receipts."""
        block = await self.w3.eth.get_block(block_number, full_transactions=True)
        transactions = []

        for tx in block.get("transactions", []):
            try:
                receipt = await self.w3.eth.get_transaction_receipt(tx["hash"])
                timestamp = datetime.fromtimestamp(
                    block["timestamp"], tz=timezone.utc
                )

                # Handle both bytes and string formats
                input_raw = tx.get("input", b"")
                if isinstance(input_raw, bytes):
                    input_data = input_raw.hex()
                else:
                    input_data = input_raw
                if not input_data.startswith("0x"):
                    input_data = "0x" + input_data
                method_id = input_data[:10] if len(input_data) >= 10 else input_data

                tx_hash_raw = tx["hash"]
                tx_hash_str = tx_hash_raw.hex() if isinstance(tx_hash_raw, bytes) else str(tx_hash_raw)
                if not tx_hash_str.startswith("0x"):
                    tx_hash_str = "0x" + tx_hash_str

                block_hash_raw = tx["blockHash"]
                block_hash_str = block_hash_raw.hex() if isinstance(block_hash_raw, bytes) else str(block_hash_raw)
                if not block_hash_str.startswith("0x"):
                    block_hash_str = "0x" + block_hash_str

                monitored_tx = MonitoredTx(
                    hash=tx_hash_str,
                    from_address=tx["from"],
                    to_address=tx.get("to"),
                    value_wei=tx["value"],
                    gas_price=tx["gasPrice"],
                    block_number=block_number,
                    timestamp=timestamp,
                    input_data=input_data,
                    method_id=method_id,
                    block_hash=block_hash_str,
                    nonce=tx["nonce"],
                    tx_index=tx["transactionIndex"],
                    gas_used=receipt["gasUsed"],
                    status=receipt.get("status", 1),
                    logs=[dict(log) for log in receipt.get("logs", [])],
                )
                transactions.append(monitored_tx)

            except Exception as e:
                # Skip failed tx processing silently
                continue

        return transactions

    async def get_balance(self, address: str) -> int:
        """Get native ETH balance in wei."""
        return await self.w3.eth.get_balance(address)

    async def get_code(self, address: str) -> str:
        """Get contract code at address."""
        code = await self.w3.eth.get_code(address)
        return code.hex()

    async def estimate_gas(self, tx: dict) -> int:
        """Estimate gas for a transaction."""
        return await self.w3.eth.estimate_gas(tx)

    async def _reconnect_with_backoff(self) -> None:
        """Exponential backoff reconnection."""
        if not self._circuit_breaker.allow_request():
            await asyncio.sleep(self._circuit_breaker.recovery_timeout)
            return

        while True:
            # Start with longer delays to avoid spam
            delay = min(
                max(2.0, self.config.base_reconnect_delay)
                * (2 ** min(self._reconnect_attempts, 6)),
                self.config.max_reconnect_delay,
            )
            jitter = random.uniform(-0.3 * delay, 0.3 * delay)
            actual_delay = max(1.0, delay + jitter)

            self._reconnect_attempts += 1
            await asyncio.sleep(actual_delay)

            try:
                await self.connect()
                logger.info(
                    f"Reconnected after {self._reconnect_attempts} attempts"
                )
                return
            except Exception as e:
                self._circuit_breaker.record_failure()
                logger.warning(f"Reconnect attempt failed: {e}")

                if self._reconnect_attempts >= 100:
                    logger.error("Max reconnect attempts reached")
                    raise

    @property
    def is_connected(self) -> bool:
        return self._connected and self.w3 is not None

    @property
    def last_block_number(self) -> int | None:
        return self._last_block_number
