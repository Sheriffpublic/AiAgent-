"""Chain constants and known addresses for Base network."""

# Base chain configuration
BASE_CHAIN_ID = 8453
BASE_RPC_HTTP = "https://mainnet.base.org"
BASE_RPC_WS = "wss://base-rpc.publicnode.com"

# Ethereum decimals
ETH_DECIMALS = 18
GWEI_DECIMALS = 9

# Known mixer contracts on Base (Tornado Cash proxy)
KNOWN_MIXERS = {
    "0xba214c1c1928a32bffe790263e38b4af9bfcd18d": "Tornado Cash Proxy",
}

# Known bridge contracts on Base
KNOWN_BRIDGES = {
    "0x4200000000000000000000000000000000000010": "L2StandardBridge",
    "0x3154cf16ccdb4c6d922629664174b904d80f2c35": "Base Bridge",
}

# DEX router addresses on Base
DEX_ROUTERS = {
    "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap V2 Router",
    "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap V3 Router",
    "0x198ef799ba9284f0c3fc96fa13fe7ea7a4960d40": "Aerodrome Router",
}

# Flash loan providers (Aave, Compound)
FLASH_LOAN_PROVIDERS = {
    "0x2f39d218133afab8f2b819b1066c7e434ad94e9e": "Aave Pool",
    "0x3d5bc3c8d13dcb8bf317092d847ff3c8fa3f335c": "Compound Comptroller",
}

# ERC-20 method IDs
METHOD_IDS = {
    "0xa9059cbb": "erc20Transfer",
    "0x23b872dd": "erc20TransferFrom",
    "0x095ea7b3": "erc20Approve",
    "0x38ed1739": "swapExactTokensForTokens",
    "0x7ff36ab5": "swapExactETHForTokens",
    "0x18cbafe5": "swapExactTokensForETH",
    "0xfb3bdb41": "swapETHForExactTokens",
}

# Heuristic rule IDs
HEURISTIC_RULES = {
    "HR001": "large_transfer",
    "HR002": "rapid_movement",
    "HR003": "known_scam",
    "HR004": "mixer_interaction",
    "HR005": "flash_loan",
    "HR006": "unusual_gas",
    "HR007": "contract_creation",
    "HR008": "high_frequency_sender",
    "HR009": "bridge_suspicious",
    "HR010": "value_obfuscation",
}

# Severity levels
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Default thresholds (can be overridden by config)
DEFAULT_LARGE_TRANSFER_ETH = 100.0  # 1 ETH
DEFAULT_RAPID_MOVEMENT_WINDOW_SEC = 60  # 1 minute
DEFAULT_RAPID_MOVEMENT_COUNT = 3  # 3 txs
DEFAULT_FLASH_LOAN_VALUE_ETH = 100.0
DEFAULT_UNUSUAL_GAS_MULTIPLIER = 2.0
DEFAULT_HIGH_FREQUENCY_TX_PER_HOUR = 20
DEFAULT_MAX_TRACE_DEPTH = 10
DEFAULT_MIN_CLUSTER_VOLUME_ETH = 0.1

# LRU cache size for deduplication
DEFAULT_LRU_CACHE_SIZE = 10_000

# Reconnection parameters
DEFAULT_BASE_RECONNECT_DELAY = 2.0
DEFAULT_MAX_RECONNECT_DELAY = 120.0
DEFAULT_CIRCUIT_BREAKER_FAILURES = 10
DEFAULT_CIRCUIT_BREAKER_TIMEOUT = 60.0
