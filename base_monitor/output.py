"""CLI colored output and structured JSON logging using Rich."""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich import box

from .config import Config
from .models import Alert, TraceResult

logger = logging.getLogger(__name__)


class OutputManager:
    """Handles dual output: Rich colored terminal + structured JSON."""

    def __init__(self, config: Config):
        self.config = config
        self._json_file = None
        self.console = Console()
        self._alert_count = 0
        self._suppress_web3_logs()

        if config.output_file:
            try:
                self._json_file = open(config.output_file, "a", encoding="utf-8")
            except Exception as e:
                logger.error(f"Failed to open output file: {e}")

    def _suppress_web3_logs(self) -> None:
        """Suppress noisy web3.py internal logs."""
        for name in [
            "web3",
            "web3.providers",
            "web3.providers.PersistentSubscriptionManager",
            "web3.providers.WebSocketProvider",
            "web3.middleware",
            "eth_account",
            "urllib3",
            "asyncio",
        ]:
            logging.getLogger(name).setLevel(logging.WARNING)

    def print_startup_banner(self) -> None:
        """Print a beautiful startup banner."""
        banner = Text()
        banner = Text()
        banner.append("  _____ _    _ ______ _____  _____ ______ ______ ______ \n", style="bold cyan")
        banner.append(" / ____| |  | |  ____|  __ \\|_   _|  ____|  ____|  ____|\n", style="bold cyan")
        banner.append("| (___ | |__| | |__  | |__) | | | | |__  | |__  | |__   \n", style="bold cyan")
        banner.append(" \\___ \\|  __  |  __| |  _  /  | | |  __| |  __| |  __|  \n", style="bold cyan")
        banner.append(" ____) | |  | | |____| | \\ \\ _| |_| |    | |    | |     \n", style="bold cyan")
        banner.append("|_____/|_|  |_|______|_|  \\_\\_____|_|    |_|    |_|     \n", style="bold cyan")  
        banner.append("\n", style="bold white")
        banner.append("   ⚖️  BLOCKCHAIN SECURITY AGENT  ⚖️", style="bold yellow")

        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column("Key", style="dim")
        info_table.add_column("Value")
        info_table.add_row("Chain", f"[bold green]Base[/bold green] (ID: {self.config.chain_id})")
        info_table.add_row("WebSocket", f"[link={self.config.ws_url}]{self.config.ws_url}[/link]")
        info_table.add_row("RPC", f"[link={self.config.rpc_url}]{self.config.rpc_url}[/link]")
        info_table.add_row("Log Level", f"[yellow]{self.config.log_level}[/yellow]")
        info_table.add_row("Trace Depth", f"[cyan]{self.config.max_trace_depth}[/cyan]")

        # Alert settings
        min_val = self.config.min_alert_value_eth
        min_style = "green" if min_val == 0 else "yellow" if min_val < 1 else "red"
        info_table.add_row("─" * 15, "─" * 25)
        info_table.add_row("Min Alert Value", f"[bold {min_style}]{min_val} ETH[/bold {min_style}]")
        info_table.add_row("Large Transfer", f"[cyan]{self.config.large_transfer_threshold_eth} ETH[/cyan]")
        info_table.add_row("Rapid Window", f"[cyan]{self.config.rapid_movement_window_seconds}s[/cyan]")
        info_table.add_row("Rapid Count", f"[cyan]{self.config.rapid_movement_count} txs[/cyan]")

        self.console.print()
        self.console.print(Panel(banner, border_style="cyan", expand=False))
        self.console.print(Panel(info_table, title="[bold]Configuration[/bold]", border_style="blue"))
        self.console.print()

    def print_alert(self, alert: Alert) -> None:
        """Print a formatted alert using Rich."""
        self._alert_count += 1

        severity_styles = {
            "CRITICAL": ("bold white on red", "red", "🚨"),
            "HIGH": ("bold red", "red", "🔴"),
            "MEDIUM": ("bold yellow", "yellow", "🟡"),
            "LOW": ("bold cyan", "cyan", "🔵"),
        }
        severity = alert.severity.upper()
        style, border, icon = severity_styles.get(severity, ("bold", "white", "⚪"))

        # Header with alert ID and severity
        header = Text()
        header.append(f" {icon} ALERT ", style=style)
        header.append(f" {alert.id} ", style="dim")
        header.append(f" {severity} ", style=style)

        # Alert details table
        details = Table(show_header=False, box=None, padding=(0, 1))
        details.add_column("Key", style="bold dim")
        details.add_column("Value")
        details.add_row("Rule", f"[bold]{alert.title}[/bold]")
        details.add_row("TX", f"[dim]{alert.tx_hash[:20]}...[/dim]")

        # From address with risk score
        from_risk = alert.metadata.get("from_risk_score", 0)
        from_label = alert.metadata.get("from_label", "")
        from_style = self._get_risk_style(from_risk)
        from_display = f"[cyan]{alert.from_address[:20]}...[/cyan]"
        if from_label:
            from_display += f" [bold {from_style}]({from_label})[/bold {from_style}]"
        from_display += f" [dim]Risk: {from_risk:.0%}[/dim]"
        details.add_row("From", from_display)

        # To address with risk score
        if alert.to_address:
            to_risk = alert.metadata.get("to_risk_score", 0)
            to_label = alert.metadata.get("to_label", "")
            to_style = self._get_risk_style(to_risk)
            to_display = f"[cyan]{alert.to_address[:20]}...[/cyan]"
            if to_label:
                to_display += f" [bold {to_style}]({to_label})[/bold {to_style}]"
            to_display += f" [dim]Risk: {to_risk:.0%}[/dim]"
            details.add_row("To", to_display)

        details.add_row("Value", f"[bold green]{alert.metadata.get('value_eth', 0):.4f} ETH[/bold green]")
        details.add_row("Gas", f"{alert.metadata.get('gas_price_gwei', 0):.2f} Gwei")
        details.add_row("Confidence", f"{alert.metadata.get('confidence', 0) * 100:.0f}%")

        # Behavior pattern
        behavior = alert.metadata.get("behavior_pattern", "")
        if behavior:
            details.add_row("Pattern", f"[bold magenta]{behavior}[/bold magenta]")

        # Evidence if available
        evidence = alert.metadata.get("evidence", {})
        if evidence:
            if "mixer_names" in evidence:
                details.add_row("Mixer", f"[red]{', '.join(evidence['mixer_names'])}[/red]")
            if "flagged_addresses" in evidence:
                for addr_info in evidence["flagged_addresses"]:
                    details.add_row("Flagged", f"[red]{addr_info.get('label', 'Unknown')}[/red]")
            if "tx_count" in evidence:
                details.add_row("Txs in Window", f"[yellow]{evidence['tx_count']}[/yellow]")

        panel = Panel(
            details,
            title=header,
            subtitle=f"[dim italic]{alert.description}[/dim italic]",
            border_style=border,
            expand=False,
            padding=(1, 2),
        )

        self.console.print()
        self.console.print(panel)
        self.console.print()
        self._log_json_alert(alert)

    def _get_risk_style(self, risk_score: float) -> str:
        """Get style based on risk score."""
        if risk_score >= 0.7:
            return "red"
        elif risk_score >= 0.4:
            return "yellow"
        elif risk_score >= 0.2:
            return "cyan"
        return "green"

    def print_status(self, message: str, style: str = "dim blue") -> None:
        """Print a status message."""
        self.console.print(f"[{style}]⚡ {message}[/{style}]")

    def print_wallet_info(self, address: str, info: dict, known_db=None) -> None:
        """Print detailed wallet information with risk score and labels."""
        risk_score = info.get("risk_score", 0)
        risk_style = self._get_risk_style(risk_score)

        # Risk level label
        if risk_score >= 0.7:
            risk_label = "HIGH RISK"
        elif risk_score >= 0.4:
            risk_label = "MEDIUM RISK"
        elif risk_score >= 0.2:
            risk_label = "LOW RISK"
        else:
            risk_label = "SAFE"

        # Get label from known DB
        label = ""
        category = ""
        is_known_bad = info.get("is_known_bad", False)
        if known_db:
            label = known_db.get_label(address) or ""
            category = known_db.get_category(address) or ""

        # Header
        header = Text()
        header.append(" 🔍 WALLET ANALYSIS ", style="bold white")
        if is_known_bad:
            header.append(" ⚠️ KNOWN BAD ", style="bold white on red")

        # Details table
        details = Table(show_header=False, box=None, padding=(0, 1))
        details.add_column("Key", style="bold dim")
        details.add_column("Value")

        details.add_row("Address", f"[cyan]{address}[/cyan]")

        if label:
            details.add_row("Label", f"[bold yellow]{label}[/bold yellow]")
        if category:
            details.add_row("Category", f"[bold magenta]{category.upper()}[/bold magenta]")

        # Risk score with visual bar
        risk_bar = self._create_risk_bar(risk_score)
        details.add_row("Risk Score", f"[{risk_style}]{risk_bar} {risk_score:.0%} ({risk_label})[/{risk_style}]")

        # Financial stats
        details.add_row("─" * 20, "─" * 30)
        details.add_row("Total Received", f"[green]{info.get('total_received_eth', 0):.4f} ETH[/green]")
        details.add_row("Total Sent", f"[red]{info.get('total_sent_eth', 0):.4f} ETH[/red]")
        details.add_row("TX Count", str(info.get("tx_count", 0)))
        details.add_row("First Seen", str(info.get("first_seen", "N/A")))
        details.add_row("Last Seen", str(info.get("last_seen", "N/A")))

        # Behavior patterns
        patterns = info.get("behavior_patterns", [])
        if patterns:
            details.add_row("─" * 20, "─" * 30)
            details.add_row("Behaviors", "")
            for pattern in patterns:
                details.add_row("  →", f"[yellow]{pattern}[/yellow]")

        panel = Panel(
            details,
            title=header,
            border_style=risk_style,
            expand=False,
            padding=(1, 2),
        )

        self.console.print(panel)

    def _create_risk_bar(self, risk_score: float, width: int = 20) -> str:
        """Create a visual risk bar."""
        filled = int(risk_score * width)
        empty = width - filled
        if risk_score >= 0.7:
            return f"[red]{'█' * filled}{'░' * empty}[/red]"
        elif risk_score >= 0.4:
            return f"[yellow]{'█' * filled}{'░' * empty}[/yellow]"
        elif risk_score >= 0.2:
            return f"[cyan]{'█' * filled}{'░' * empty}[/cyan]"
        return f"[green]{'█' * filled}{'░' * empty}[/green]"

    def print_search_results(self, query: str, results: list[dict]) -> None:
        """Print wallet search results."""
        header = Text()
        header.append(" 🔎 WALLET SEARCH ", style="bold cyan")
        header.append(f" Query: {query}", style="dim")

        if not results:
            self.console.print(Panel(
                "[yellow]No results found for this query.[/yellow]",
                title=header,
                border_style="yellow",
                expand=False,
            ))
            return

        table = Table(box=box.ROUNDED, title=header, border_style="cyan")
        table.add_column("Address", style="cyan")
        table.add_column("Label", style="bold")
        table.add_column("Category", style="magenta")
        table.add_column("Risk", justify="center")

        for result in results:
            risk = result.get("risk_score", 0)
            risk_style = self._get_risk_style(risk)
            table.add_row(
                result.get("address", "")[:20] + "...",
                result.get("label", "-"),
                result.get("category", "-"),
                f"[{risk_style}]{risk:.0%}[/{risk_style}]",
            )

        self.console.print(Panel(table, border_style="cyan", expand=False))

    def print_block(self, block_number: int, tx_count: int) -> None:
        """Print block processing info."""
        self.console.print(
            f"[dim]📦 Block #[/dim][bold cyan]{block_number}[/bold cyan] "
            f"[dim]({tx_count} txs)[/dim]"
        )

    def print_trace(self, trace: TraceResult) -> None:
        """Print fund trace results with Rich formatting."""
        header = Text()
        header.append("FUND TRACE RESULTS", style="bold white")
        header.append(f"\nAddress: {trace.origin}", style="cyan")

        stats_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Value")
        stats_table.add_row("Total Inflow", f"[green]{trace.total_inflow_eth:.4f} ETH[/green]")
        stats_table.add_row("Total Outflow", f"[red]{trace.total_outflow_eth:.4f} ETH[/red]")
        stats_table.add_row("Unique Senders", str(trace.unique_senders))
        stats_table.add_row("Unique Receivers", str(trace.unique_receivers))

        risk_color = "red" if trace.risk_score > 0.5 else "yellow" if trace.risk_score > 0.2 else "green"
        stats_table.add_row("Risk Score", f"[{risk_color}]{trace.risk_score:.2f}[/{risk_color}]")

        self.console.print(Panel(stats_table, title="[bold]Statistics[/bold]", border_style="blue"))

        # Upstream flows
        if trace.upstream_flows:
            upstream_table = Table(title="[bold green]Upstream Flows[/bold green]", box=box.ROUNDED)
            upstream_table.add_column("Amount (ETH)", style="green")
            upstream_table.add_column("Path")
            for flow in trace.upstream_flows[:5]:
                path = " → ".join([a[:10] for a in flow.path[:4]])
                if len(flow.path) > 4:
                    path += " → ..."
                upstream_table.add_row(f"{flow.total_eth:.4f}", path)
            self.console.print(upstream_table)

        # Downstream flows
        if trace.downstream_flows:
            downstream_table = Table(title="[bold red]Downstream Flows[/bold red]", box=box.ROUNDED)
            downstream_table.add_column("Amount (ETH)", style="red")
            downstream_table.add_column("Path")
            for flow in trace.downstream_flows[:5]:
                path = " → ".join([a[:10] for a in flow.path[:4]])
                if len(flow.path) > 4:
                    path += " → ..."
                downstream_table.add_row(f"{flow.total_eth:.4f}", path)
            self.console.print(downstream_table)

    def print_stats(self, stats: dict) -> None:
        """Print scanner statistics."""
        stats_table = Table(title="[bold]Scanner Statistics[/bold]", box=box.ROUNDED)
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Value")
        stats_table.add_row("Status", "[green]Running[/green]" if stats.get("running") else "[red]Stopped[/red]")
        stats_table.add_row("Processed TXs", str(stats.get("processed_count", 0)))
        stats_table.add_row("Alerts Fired", str(stats.get("alert_count", 0)))
        stats_table.add_row("Cache Size", str(stats.get("cache_size", 0)))
        self.console.print(stats_table)

    def log_json(self, data: dict[str, Any], event_type: str) -> None:
        """Write structured JSON log."""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            **data,
        }

        if self._json_file:
            try:
                self._json_file.write(json.dumps(log_entry) + "\n")
                self._json_file.flush()
            except Exception as e:
                logger.error(f"Failed to write JSON log: {e}")

    def _log_json_alert(self, alert: Alert) -> None:
        """Log alert to JSON file."""
        self.log_json(
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

    def print_settings_panel(self, config) -> None:
        """Print interactive settings panel."""
        settings = Table(show_header=False, box=None, padding=(0, 2))
        settings.add_column("Setting", style="bold")
        settings.add_column("Value")

        settings.add_row("Min Alert Value", f"[bold yellow]{config.min_alert_value_eth} ETH[/bold yellow]")
        settings.add_row("Large Transfer", f"[cyan]{config.large_transfer_threshold_eth} ETH[/cyan]")
        settings.add_row("Rapid Movement", f"{config.rapid_movement_count} txs in {config.rapid_movement_window_seconds}s")
        settings.add_row("High Frequency", f"{config.high_frequency_tx_per_hour} txs/hour")

        panel = Panel(
            settings,
            title="[bold]⚙️ Alert Settings[/bold]",
            subtitle="[dim]Use --min-alert-value to change[/dim]",
            border_style="yellow",
            expand=False,
            padding=(1, 2),
        )
        self.console.print(panel)

    def print_settings_update(self, setting: str, old_value: float, new_value: float) -> None:
        """Print settings update notification."""
        self.console.print(
            f"[bold green]✓[/bold green] [dim]{setting}:[/dim] "
            f"[yellow]{old_value}[/yellow] → [bold green]{new_value}[/bold green]"
        )

    def close(self) -> None:
        """Close file handles."""
        if self._json_file:
            self._json_file.close()
            self._json_file = None
