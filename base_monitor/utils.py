"""Helper functions for address handling and conversions."""

from eth_utils import (
    keccak,
    to_checksum_address,
    is_address,
    is_checksum_address,
)


def to_hex(value: int) -> str:
    """Convert an integer to hex string."""
    return hex(value)


def from_hex(hex_str: str) -> int:
    """Convert a hex string to integer."""
    return int(hex_str, 16)


def checksum_address(address: str) -> str:
    """Convert an address to checksum format."""
    return to_checksum_address(address)


def is_valid_address(address: str) -> bool:
    """Check if an address is valid."""
    return is_address(address)


def normalize_address(address: str) -> str:
    """Normalize an address to lowercase."""
    return address.lower()


def wei_to_eth(wei: int) -> float:
    """Convert wei to ETH."""
    return wei / 1e18


def eth_to_wei(eth: float) -> int:
    """Convert ETH to wei."""
    return int(eth * 1e18)


def wei_to_gwei(wei: int) -> float:
    """Convert wei to Gwei."""
    return wei / 1e9


def gwei_to_wei(gwei: float) -> int:
    """Convert Gwei to wei."""
    return int(gwei * 1e9)


def short_address(address: str, chars: int = 6) -> str:
    """Shorten an address for display."""
    if len(address) <= chars * 2 + 2:
        return address
    return f"{address[:chars + 2]}...{address[-chars:]}"


def short_hash(hash_str: str, chars: int = 8) -> str:
    """Shorten a hash for display."""
    if len(hash_str) <= chars + 2:
        return hash_str
    return f"{hash_str[:chars + 2]}..."


def method_id_to_name(method_id: str) -> str:
    """Convert a method ID to a human-readable name."""
    METHOD_NAMES = {
        "0x": "transfer",
        "0xa9059cbb": "erc20Transfer",
        "0x23b872dd": "erc20TransferFrom",
        "0x095ea7b3": "erc20Approve",
        "0x38ed1739": "swapExactTokensForTokens",
        "0x7ff36ab5": "swapExactETHForTokens",
        "0x18cbafe5": "swapExactTokensForETH",
        "0xfb3bdb41": "swapETHForExactTokens",
        "0x3593564c": "execute",
    }
    return METHOD_NAMES.get(method_id.lower(), "unknown")


def encode_function_selector(signature: str) -> str:
    """Encode a function signature to a 4-byte selector."""
    return "0x" + keccak(text=signature)[:4].hex()


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"
