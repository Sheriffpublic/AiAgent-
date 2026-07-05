"""Entry point for the Base blockchain monitor."""

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from .alerts import AlertManager
from .chain import BaseChainClient
from .config import load_config
from .fund_tracer import FundTracer
from .heuristics import HeuristicEngine
from .known_addresses import KnownAddressDB
from .output import OutputManager
from .scanner import TransactionScanner


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="base_monitor",
        description="Base Blockchain Sheriff - Real-time Suspicious Behavior Detection",
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to TOML configuration file",
    )
    parser.add_argument(
        "--ws-url",
        type=str,
        help="WebSocket RPC endpoint URL",
    )
    parser.add_argument(
        "--rpc-url",
        type=str,
        help="HTTP RPC endpoint URL",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="JSON log output file path",
    )
    parser.add_argument(
        "--color/--no-color",
        dest="enable_color",
        default=None,
        help="Enable/disable colored output",
    )
    parser.add_argument(
        "--trace",
        type=str,
        help="Trace funds for a specific address (interactive mode)",
    )
    parser.add_argument(
        "--search",
        type=str,
        help="Search for a wallet address (check if known/malicious)",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=10,
        help="Max trace depth (default: 10)",
    )
    parser.add_argument(
        "--threshold-transfer",
        type=float,
        help="Large transfer threshold in ETH",
    )
    parser.add_argument(
        "--min-alert-value",
        type=float,
        default=0.0,
        help="Minimum ETH value to trigger alerts (default: 0.0)",
    )

    return parser.parse_args()


def setup_logging(log_level: str) -> None:
    """Configure logging."""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Suppress noisy third-party logs
    for name in [
        "web3",
        "web3.providers",
        "web3.providers.PersistentSubscriptionManager",
        "web3.providers.WebSocketProvider",
        "web3.middleware",
        "eth_account",
        "urllib3",
        "asyncio",
        "aiohttp",
    ]:
        logging.getLogger(name).setLevel(logging.ERROR)


async def run_monitor(args: argparse.Namespace) -> None:
    """Run the blockchain monitor."""
    # Load configuration
    cli_overrides = {}
    if args.ws_url:
        cli_overrides["ws_url"] = args.ws_url
    if args.rpc_url:
        cli_overrides["rpc_url"] = args.rpc_url
    if args.log_level:
        cli_overrides["log_level"] = args.log_level
    if args.output:
        cli_overrides["output_file"] = args.output
    if args.enable_color is not None:
        cli_overrides["enable_color"] = args.enable_color
    if args.threshold_transfer:
        cli_overrides["large_transfer_threshold_eth"] = args.threshold_transfer
    if args.min_alert_value > 0:
        cli_overrides["min_alert_value_eth"] = args.min_alert_value

    config = load_config(config_path=args.config, cli_overrides=cli_overrides)

    # Setup logging
    setup_logging(config.log_level)
    logger = logging.getLogger(__name__)

    # Load known addresses
    known_db = KnownAddressDB()
    known_addresses_path = Path(__file__).parent.parent / "known_addresses.json"
    if known_addresses_path.exists():
        known_db.load_from_file(known_addresses_path)

    # Initialize components
    output = OutputManager(config)
    output.print_startup_banner()
    output.print_settings_panel(config)

    chain = BaseChainClient(config)
    try:
        output.print_status("Connecting to Base network...")
        await chain.connect()
        output.print_status("Connected! Listening for transactions...", style="bold green")
    except Exception as e:
        output.print_status(f"Failed to connect: {e}", style="bold red")
        sys.exit(1)

    tracer = FundTracer(config)
    heuristics = HeuristicEngine(config, known_db)
    alert_mgr = AlertManager(config, output, tracer=tracer, known_db=known_db)
    scanner = TransactionScanner(config, chain, heuristics, tracer, alert_mgr)

    # Handle graceful shutdown
    shutdown_event = asyncio.Event()

    def signal_handler():
        logger.info("Shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    try:
        # Start scanner
        await scanner.start()

        # If trace mode, handle interactively
        if args.trace:
            output.print_status(f"Tracing funds for: {args.trace}")
            trace = tracer.trace_funds(args.trace, depth=args.depth)
            output.print_trace(trace)
        else:
            # Run until shutdown
            await shutdown_event.wait()

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        # Cleanup
        await scanner.stop()
        await chain.disconnect()
        await alert_mgr.flush()
        output.close()
        logger.info("Monitor stopped")


async def run_trace(address: str, depth: int, config_path: str | None) -> None:
    """Run a single trace on an address."""
    config = load_config(config_path=config_path)
    setup_logging("INFO")

    known_db = KnownAddressDB()
    known_addresses_path = Path(__file__).parent.parent / "known_addresses.json"
    if known_addresses_path.exists():
        known_db.load_from_file(known_addresses_path)

    output = OutputManager(config)
    tracer = FundTracer(config)

    output.print_status(f"Tracing funds for: {address}")

    trace = tracer.trace_funds(address, depth=depth)
    output.print_trace(trace)

    output.close()


async def run_search(query: str, config_path: str | None) -> None:
    """Search for a wallet address."""
    config = load_config(config_path=config_path)
    setup_logging("WARNING")

    known_db = KnownAddressDB()
    known_addresses_path = Path(__file__).parent.parent / "known_addresses.json"
    if known_addresses_path.exists():
        known_db.load_from_file(known_addresses_path)

    output = OutputManager(config)
    tracer = FundTracer(config)

    # Search in known addresses
    results = []

    # Check if it's a known address
    label = known_db.get_label(query)
    category = known_db.get_category(query)
    is_bad = known_db.is_known_bad(query)

    if label:
        results.append({
            "address": query,
            "label": label,
            "category": category or "unknown",
            "risk_score": 1.0 if is_bad else 0.3,
        })

    # Check all known bad addresses if query is partial
    if not results:
        for addr, data in known_db._addresses.items():
            if query.lower() in addr.lower() or query.lower() in data.get("label", "").lower():
                results.append({
                    "address": addr,
                    "label": data.get("label", ""),
                    "category": data.get("category", ""),
                    "risk_score": 1.0 if data.get("category", "").lower() in {"scam", "malicious"} else 0.3,
                })

    # Get wallet info from tracer if available
    wallet_info = tracer.get_wallet_info(query)
    if wallet_info:
        results.append({
            "address": query,
            "label": label or "",
            "category": category or "observed",
            "risk_score": wallet_info.risk_score,
        })

    output.print_search_results(query, results)

    # If we have full wallet info, show detailed view
    if wallet_info:
        output.print_wallet_info(query, {
            "total_received_eth": wallet_info.total_received_eth,
            "total_sent_eth": wallet_info.total_sent_eth,
            "tx_count": wallet_info.tx_count,
            "risk_score": wallet_info.risk_score,
            "is_known_bad": wallet_info.is_known_bad,
            "first_seen": str(wallet_info.first_seen),
            "last_seen": str(wallet_info.last_seen),
        }, known_db)

    output.close()


def main():
    """Main entry point."""
    args = parse_args()

    if args.search:
        # Run search mode
        asyncio.run(run_search(args.search, args.config))
    elif args.trace:
        # Run trace mode
        asyncio.run(run_trace(args.trace, args.depth, args.config))
    else:
        # Run monitor mode
        asyncio.run(run_monitor(args))


if __name__ == "__main__":
    main()
