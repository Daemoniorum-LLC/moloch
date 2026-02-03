# Moloch Configuration Reference

Complete reference for all configuration options in Moloch.

## Configuration File Format

Moloch uses TOML format for configuration. The default location is `/opt/moloch/config/node.toml`.

## Node Section

Basic node identity and paths.

```toml
[node]
# Chain identifier (must match all nodes on the network)
# Type: String
# Required: Yes
chain_id = "moloch-mainnet"

# Base directory for all data
# Type: Path
# Default: "./data"
data_dir = "/opt/moloch/data"

# Log level
# Type: String (trace, debug, info, warn, error)
# Default: "info"
log_level = "info"

# Log format
# Type: String (json, text)
# Default: "text"
log_format = "json"

# Log output file (empty = stdout)
# Type: Path
# Default: ""
log_file = "/opt/moloch/logs/moloch.log"
```

## Network Section

P2P networking configuration.

```toml
[network]
# Address to listen for P2P connections
# Type: String (host:port)
# Default: "0.0.0.0:9000"
listen_addr = "0.0.0.0:9000"

# External address announced to peers
# Type: String (host:port)
# Default: Same as listen_addr
external_addr = "node1.example.com:9000"

# Maximum number of peer connections
# Type: Integer
# Default: 50
max_peers = 50

# Minimum number of peer connections to maintain
# Type: Integer
# Default: 3
min_peers = 3

# Bootstrap nodes for peer discovery
# Type: Array of multiaddr strings
# Default: []
boot_nodes = [
    "/dns/boot1.moloch.network/tcp/9000/p2p/12D3KooW...",
    "/dns/boot2.moloch.network/tcp/9000/p2p/12D3KooW...",
]

# Connection timeout
# Type: Duration (e.g., "10s", "1m")
# Default: "10s"
connection_timeout = "10s"

# Handshake timeout
# Type: Duration
# Default: "5s"
handshake_timeout = "5s"

# Keepalive interval
# Type: Duration
# Default: "30s"
keepalive_interval = "30s"

# Idle connection timeout
# Type: Duration
# Default: "120s"
idle_timeout = "120s"

# Maximum concurrent sync requests
# Type: Integer
# Default: 4
max_concurrent_requests = 4

# Message buffer size per peer
# Type: Integer
# Default: 100
message_buffer_size = 100
```

### TLS Configuration

```toml
[network.tls]
# Enable TLS for P2P connections
# Type: Boolean
# Default: true
enabled = true

# TLS certificate file
# Type: Path
# Required if TLS enabled
cert_file = "/opt/moloch/config/tls/cert.pem"

# TLS private key file
# Type: Path
# Required if TLS enabled
key_file = "/opt/moloch/config/tls/key.pem"

# CA certificate file for peer verification
# Type: Path
# Optional
ca_file = "/opt/moloch/config/tls/ca.pem"

# Verify peer certificates
# Type: Boolean
# Default: true
verify_peers = true
```

## Consensus Section

Proof-of-Authority consensus configuration.

```toml
[consensus]
# Run as a validator
# Type: Boolean
# Default: false
validator = true

# Path to validator private key
# Type: Path
# Required if validator = true
validator_key = "/opt/moloch/keys/node.key"

# Target block time in milliseconds
# Type: Integer
# Default: 1000
block_time_ms = 1000

# Maximum events per block
# Type: Integer
# Default: 1000
max_events_per_block = 1000

# Finality threshold (fraction of validators needed)
# Type: Float (0.0 - 1.0)
# Default: 0.667 (2/3)
finality_threshold = 0.667

# Blocks per epoch (for validator set changes)
# Type: Integer
# Default: 100
epoch_length = 100
```

## Storage Section

Database and persistence configuration.

```toml
[storage]
# Storage backend
# Type: String (rocksdb, memory)
# Default: "rocksdb"
backend = "rocksdb"

# Path to chain data (relative to data_dir)
# Type: Path
# Default: "chain"
chain_path = "chain"

# Path to MMR data
# Type: Path
# Default: "mmr"
mmr_path = "mmr"

# Path to index data
# Type: Path
# Default: "index"
index_path = "index"

# RocksDB block cache size in MB
# Type: Integer
# Default: 128
cache_size_mb = 512

# Write buffer size in MB
# Type: Integer
# Default: 64
write_buffer_size_mb = 64

# Maximum open files
# Type: Integer
# Default: 10000
max_open_files = 10000

# Enable compression
# Type: String (none, snappy, lz4, zstd)
# Default: "lz4"
compression = "lz4"

# Sync writes to disk
# Type: Boolean
# Default: true
sync_writes = true
```

## API Section

REST and WebSocket API configuration.

```toml
[api]
# Enable API server
# Type: Boolean
# Default: true
enabled = true

# API listen address
# Type: String (host:port)
# Default: "0.0.0.0:8080"
listen_addr = "0.0.0.0:8080"

# Maximum concurrent connections
# Type: Integer
# Default: 1000
max_connections = 1000

# Request body size limit
# Type: String (e.g., "1MB", "10MB")
# Default: "10MB"
max_body_size = "10MB"

# Request timeout
# Type: Duration
# Default: "30s"
request_timeout = "30s"

# Enable CORS
# Type: Boolean
# Default: false
cors_enabled = true

# CORS allowed origins (if CORS enabled)
# Type: Array of strings
# Default: ["*"]
cors_origins = ["https://app.example.com"]
```

### API Authentication

```toml
[api.auth]
# Require authentication
# Type: Boolean
# Default: false
require_auth = true

# JWT secret file (for JWT authentication)
# Type: Path
# Required if JWT enabled
jwt_secret_file = "/opt/moloch/config/jwt_secret"

# JWT token expiry
# Type: Duration
# Default: "24h"
jwt_expiry = "24h"

# API keys file (for API key authentication)
# Type: Path
# Optional
api_keys_file = "/opt/moloch/config/api_keys.json"
```

### Rate Limiting

```toml
[api.rate_limit]
# Enable rate limiting
# Type: Boolean
# Default: true
enabled = true

# Requests per minute per IP
# Type: Integer
# Default: 600
requests_per_minute = 600

# Burst size
# Type: Integer
# Default: 100
burst_size = 100

# WebSocket connections per IP
# Type: Integer
# Default: 5
websocket_connections = 5
```

## Metrics Section

Prometheus metrics configuration.

```toml
[metrics]
# Enable metrics endpoint
# Type: Boolean
# Default: true
enabled = true

# Metrics listen address
# Type: String (host:port)
# Default: "0.0.0.0:9090"
prometheus_addr = "0.0.0.0:9090"

# Enable detailed histograms
# Type: Boolean
# Default: false
detailed_histograms = true
```

## Mempool Section

Event mempool configuration.

```toml
[mempool]
# Maximum pending events
# Type: Integer
# Default: 10000
max_size = 10000

# Event TTL before expiry
# Type: Duration
# Default: "5m"
event_ttl = "5m"

# Rebroadcast interval
# Type: Duration
# Default: "30s"
rebroadcast_interval = "30s"

# Enable concurrent mempool (lock-free)
# Type: Boolean
# Default: true
concurrent = true

# Number of shards for concurrent mempool
# Type: Integer
# Default: 16
shards = 16
```

## Index Section

Secondary index configuration.

```toml
[index]
# Enable secondary indexes
# Type: Boolean
# Default: true
enabled = true

# Enable actor index
# Type: Boolean
# Default: true
actor_index = true

# Enable resource index
# Type: Boolean
# Default: true
resource_index = true

# Enable time index
# Type: Boolean
# Default: true
time_index = true

# Enable event type index
# Type: Boolean
# Default: true
type_index = true

# Maximum results per query
# Type: Integer
# Default: 1000
max_results = 1000
```

## Anchoring Section

External blockchain anchoring configuration.

```toml
[anchoring]
# Enable anchoring
# Type: Boolean
# Default: false
enabled = true

# Anchor every N blocks
# Type: Integer
# Default: 100
interval_blocks = 100

# Provider selection strategy
# Type: String (all, first, cheapest, fastest)
# Default: "all"
selection_strategy = "all"

# Maximum anchor cost in USD
# Type: Float
# Default: 0.0 (no limit)
max_cost_usd = 10.0
```

### Bitcoin Anchoring

```toml
[anchoring.bitcoin]
# Enable Bitcoin anchoring
# Type: Boolean
# Default: false
enabled = true

# Bitcoin Core RPC URL
# Type: String
# Required if enabled
rpc_url = "http://localhost:8332"

# RPC username
# Type: String
# Required if enabled
rpc_user = "moloch"

# RPC password file
# Type: Path
# Required if enabled
rpc_password_file = "/opt/moloch/config/bitcoin_rpc_password"

# Bitcoin network
# Type: String (mainnet, testnet, signet, regtest)
# Default: "mainnet"
network = "mainnet"

# Wallet name
# Type: String
# Default: "moloch-anchor"
wallet = "moloch-anchor"

# Required confirmations
# Type: Integer
# Default: 6
required_confirmations = 6

# Fee rate in sat/vB (0 = auto-estimate)
# Type: Integer
# Default: 0
fee_rate_sat_vb = 0

# Fee estimation target blocks
# Type: Integer
# Default: 6
fee_target_blocks = 6

# RPC timeout
# Type: Duration
# Default: "30s"
timeout = "30s"

# Maximum retries
# Type: Integer
# Default: 3
max_retries = 3
```

### Ethereum Anchoring

```toml
[anchoring.ethereum]
# Enable Ethereum anchoring
# Type: Boolean
# Default: false
enabled = true

# Ethereum RPC URL
# Type: String
# Required if enabled
rpc_url = "http://localhost:8545"

# Chain ID
# Type: Integer
# Default: 1 (mainnet)
chain_id = 1

# Private key file for signing
# Type: Path
# Required if enabled
private_key_file = "/opt/moloch/config/eth_private_key"

# Contract address (if using anchor contract)
# Type: String
# Optional
contract_address = "0x..."

# Required confirmations
# Type: Integer
# Default: 12
required_confirmations = 12

# Gas price multiplier (1.0 = estimated)
# Type: Float
# Default: 1.1
gas_price_multiplier = 1.1

# Max gas price in gwei
# Type: Integer
# Default: 100
max_gas_price_gwei = 100
```

## HoloCrypt Section

Privacy features configuration.

```toml
[holocrypt]
# Enable HoloCrypt privacy features
# Type: Boolean
# Default: false
enabled = true

# Default encryption policy
# Type: String (none, selective, full)
# Default: "selective"
default_policy = "selective"

# Enable zero-knowledge proofs
# Type: Boolean
# Default: true
zk_proofs_enabled = true

# Enable threshold encryption
# Type: Boolean
# Default: false
threshold_enabled = false

# Enable post-quantum encryption
# Type: Boolean
# Default: false
pqc_enabled = false
```

## Light Client Section

Light client configuration (for light nodes only).

```toml
[light]
# Run as light client
# Type: Boolean
# Default: false
enabled = false

# Maximum headers to store
# Type: Integer
# Default: 10000
max_headers = 10000

# Checkpoint height (for fast bootstrap)
# Type: Integer
# Optional
checkpoint_height = 1000000

# Checkpoint hash
# Type: String
# Required if checkpoint_height set
checkpoint_hash = "abc123..."
```

## Federation Section

Cross-chain federation configuration.

```toml
[federation]
# Enable federation
# Type: Boolean
# Default: false
enabled = false

# Federated chains
# Type: Array of chain configs
chains = [
    { id = "moloch-chain-2", endpoint = "https://chain2.example.com" },
]

# Trust level for unknown chains
# Type: String (untrusted, basic, elevated, full)
# Default: "untrusted"
default_trust_level = "basic"
```

## Environment Variables

All configuration options can be overridden with environment variables:

```bash
# Format: MOLOCH_<SECTION>_<KEY>

# Examples:
MOLOCH_NODE_CHAIN_ID=moloch-testnet
MOLOCH_NETWORK_LISTEN_ADDR=0.0.0.0:9001
MOLOCH_STORAGE_CACHE_SIZE_MB=1024
MOLOCH_API_ENABLED=false
MOLOCH_CONSENSUS_VALIDATOR=true
```

## Configuration Precedence

1. Command-line arguments (highest)
2. Environment variables
3. Configuration file
4. Default values (lowest)

## Validation

Validate configuration before starting:

```bash
./target/release/moloch validate-config --config /opt/moloch/config/node.toml
```

## Example Configurations

### Minimal Validator

```toml
[node]
chain_id = "moloch-mainnet"
data_dir = "/opt/moloch/data"

[consensus]
validator = true
validator_key = "/opt/moloch/keys/node.key"

[network]
boot_nodes = ["/dns/boot.moloch.network/tcp/9000/p2p/12D3KooW..."]
```

### API-Only Node

```toml
[node]
chain_id = "moloch-mainnet"
data_dir = "/opt/moloch/data"

[consensus]
validator = false

[api]
enabled = true
listen_addr = "0.0.0.0:8080"

[api.rate_limit]
requests_per_minute = 6000
```

### Full Production Validator

See `docs/developer/deployment.md` for complete production configuration.
