"""Configuration management for the Base blockchain monitor."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .constants import (
    BASE_CHAIN_ID,
    BASE_RPC_HTTP,
    BASE_RPC_WS,
    DEFAULT_BASE_RECONNECT_DELAY,
    DEFAULT_CIRCUIT_BREAKER_FAILURES,
    DEFAULT_CIRCUIT_BREAKER_TIMEOUT,
    DEFAULT_FLASH_LOAN_VALUE_ETH,
    DEFAULT_HIGH_FREQUENCY_TX_PER_HOUR,
    DEFAULT_LARGE_TRANSFER_ETH,
    DEFAULT_LRU_CACHE_SIZE,
    DEFAULT_MAX_RECONNECT_DELAY,
    DEFAULT_MAX_TRACE_DEPTH,
    DEFAULT_MIN_CLUSTER_VOLUME_ETH,
    DEFAULT_RAPID_MOVEMENT_COUNT,
    DEFAULT_RAPID_MOVEMENT_WINDOW_SEC,
    DEFAULT_UNUSUAL_GAS_MULTIPLIER,
)


@dataclass
class Config:
    """Main configuration class with layered priority."""

    # Chain configuration
    rpc_url: str = BASE_RPC_HTTP
    ws_url: str = BASE_RPC_WS
    chain_id: int = BASE_CHAIN_ID

    # Thresholds
    large_transfer_threshold_eth: float = DEFAULT_LARGE_TRANSFER_ETH
    rapid_movement_window_seconds: int = DEFAULT_RAPID_MOVEMENT_WINDOW_SEC
    rapid_movement_count: int = DEFAULT_RAPID_MOVEMENT_COUNT
    flash_loan_value_threshold_eth: float = DEFAULT_FLASH_LOAN_VALUE_ETH
    unusual_gas_multiplier: float = DEFAULT_UNUSUAL_GAS_MULTIPLIER
    high_frequency_tx_per_hour: int = DEFAULT_HIGH_FREQUENCY_TX_PER_HOUR
    min_alert_value_eth: float = 0.0  # Minimum ETH value to trigger alerts

    # Scanning
    block_poll_interval: float = 2.0
    max_reconnect_delay: float = DEFAULT_MAX_RECONNECT_DELAY
    subscription_queue_size: int = 500
    lru_cache_size: int = DEFAULT_LRU_CACHE_SIZE

    # Reconnection
    base_reconnect_delay: float = DEFAULT_BASE_RECONNECT_DELAY
    circuit_breaker_failures: int = DEFAULT_CIRCUIT_BREAKER_FAILURES
    circuit_breaker_timeout: float = DEFAULT_CIRCUIT_BREAKER_TIMEOUT

    # Output
    log_format: str = "json"
    log_level: str = "INFO"
    enable_color: bool = True
    output_file: str | None = None

    # Fund tracing
    max_trace_depth: int = DEFAULT_MAX_TRACE_DEPTH
    min_cluster_volume_eth: float = DEFAULT_MIN_CLUSTER_VOLUME_ETH
    sqlite_path: str | None = None

    # Heuristics
    enabled_heuristics: list[str] = field(default_factory=lambda: [
        "large_transfer",
        "rapid_movement",
        "known_scam",
        "mixer_interaction",
        "flash_loan",
        "unusual_gas",
        "contract_creation",
        "high_frequency_sender",
        "bridge_suspicious",
        "value_obfuscation",
    ])

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        """Create config from a dictionary."""
        config = cls()
        for key, value in data.items():
            if hasattr(config, key):
                # Convert empty strings to None for Optional[str] fields
                if value == "" and key in ("output_file", "sqlite_path", "persistence_path"):
                    value = None
                setattr(config, key, value)
        return config

    @classmethod
    def from_toml(cls, path: str | Path) -> "Config":
        """Load configuration from a TOML file."""
        try:
            import tomli
        except ImportError:
            try:
                import tomllib as tomli
            except ImportError:
                raise ImportError("tomli or tomllib required for TOML parsing")

        with open(path, "rb") as f:
            data = tomli.load(f)

        flat_data: dict[str, Any] = {}

        # Flatten nested TOML structure
        for section, values in data.items():
            if isinstance(values, dict):
                for key, value in values.items():
                    flat_data[key] = value
            else:
                flat_data[section] = values

        return cls.from_dict(flat_data)

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        config = cls()
        env_prefix = "BASE_MONITOR_"

        env_map = {
            f"{env_prefix}RPC_URL": "rpc_url",
            f"{env_prefix}WS_URL": "ws_url",
            f"{env_prefix}LOG_LEVEL": "log_level",
            f"{env_prefix}LOG_FORMAT": "log_format",
            f"{env_prefix}OUTPUT_FILE": "output_file",
            f"{env_prefix}LARGE_TRANSFER_ETH": "large_transfer_threshold_eth",
            f"{env_prefix}MAX_TRACE_DEPTH": "max_trace_depth",
            f"{env_prefix}SQLITE_PATH": "sqlite_path",
        }

        for env_var, attr_name in env_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                current_type = type(getattr(config, attr_name))
                if current_type == int:
                    setattr(config, attr_name, int(value))
                elif current_type == float:
                    setattr(config, attr_name, float(value))
                elif current_type == bool:
                    setattr(config, attr_name, value.lower() in ("true", "1", "yes"))
                else:
                    setattr(config, attr_name, value)

        return config

    def merge(self, overrides: "Config") -> "Config":
        """Merge another config on top of this one (overrides win)."""
        import dataclasses
        merged = Config()
        defaults = Config()
        for field_name in self.__dataclass_fields__:
            override_val = getattr(overrides, field_name)
            default_val = getattr(self, field_name)
            class_default = getattr(defaults, field_name)
            # Use override if it differs from the class default
            if override_val != class_default:
                setattr(merged, field_name, override_val)
            else:
                setattr(merged, field_name, default_val)
        return merged


def load_config(
    config_path: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> Config:
    """
    Load configuration with layered priority:
    1. Defaults (Config class defaults)
    2. Config file (config/default.toml)
    3. User config file (if provided)
    4. Environment variables
    5. CLI overrides
    """
    # Start with defaults
    config = Config()

    # Load default.toml if it exists
    default_config_path = Path(__file__).parent.parent / "config" / "default.toml"
    if default_config_path.exists():
        config = config.merge(Config.from_toml(default_config_path))

    # Load user config if provided
    if config_path and Path(config_path).exists():
        config = config.merge(Config.from_toml(config_path))

    # Apply environment variables
    env_config = Config.from_env()
    config = config.merge(env_config)

    # Apply CLI overrides (highest priority)
    if cli_overrides:
        cli_config = Config.from_dict(cli_overrides)
        config = config.merge(cli_config)

    return config
