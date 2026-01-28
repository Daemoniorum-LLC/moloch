# Moloch Deployment Guide

Production deployment guide for the Moloch cryptographic audit chain.

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| CPU | 4 cores | 8+ cores | More cores improve batch verification |
| RAM | 8 GB | 32 GB | RocksDB benefits from memory |
| Storage | 100 GB SSD | 500 GB NVMe | Event growth ~1KB/event |
| Network | 100 Mbps | 1 Gbps | Validator nodes need low latency |

### Software Requirements

- **Operating System**: Linux (Ubuntu 22.04 LTS recommended)
- **Rust**: 1.75+ (2021 edition)
- **RocksDB**: 8.0+ development libraries
- **OpenSSL**: 3.0+ for TLS

### Optional Components

- **Bitcoin Core**: 25.0+ for Bitcoin anchoring
- **Ethereum Client**: Geth/Nethermind for Ethereum anchoring
- **Prometheus**: For metrics export
- **Grafana**: For dashboard visualization

## Installation

### From Source

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev librocksdb-dev clang

# Clone repository
git clone https://github.com/Daemoniorum-LLC/moloch.git
cd moloch

# Build release binaries
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Verify build
./target/release/moloch --version
```

### Using Docker

```bash
# Pull official image
docker pull daemoniorum/moloch:latest

# Or build locally
docker build -t moloch:local .

# Run with volume for data persistence
docker run -d \
  --name moloch-node \
  -v /var/lib/moloch:/data \
  -p 9000:9000 \
  -p 8080:8080 \
  daemoniorum/moloch:latest
```

## Configuration

### Directory Structure

```
/opt/moloch/
├── bin/
│   └── moloch           # Main binary
├── config/
│   ├── node.toml        # Node configuration
│   ├── genesis.json     # Genesis block (for new chains)
│   └── validators.json  # Validator set
├── data/
│   ├── chain/           # RocksDB chain data
│   ├── mmr/             # MMR storage
│   └── index/           # Secondary indexes
├── keys/
│   ├── node.key         # Node private key
│   └── node.pub         # Node public key
└── logs/
    └── moloch.log       # Application logs
```

### Node Configuration (node.toml)

```toml
# Node identity
[node]
chain_id = "moloch-mainnet"
data_dir = "/opt/moloch/data"
log_level = "info"

# Network configuration
[network]
listen_addr = "0.0.0.0:9000"
external_addr = "node1.example.com:9000"
max_peers = 50
boot_nodes = [
    "/dns/boot1.moloch.network/tcp/9000/p2p/12D3KooW...",
    "/dns/boot2.moloch.network/tcp/9000/p2p/12D3KooW...",
]

# TLS configuration
[network.tls]
cert_file = "/opt/moloch/config/tls/cert.pem"
key_file = "/opt/moloch/config/tls/key.pem"
ca_file = "/opt/moloch/config/tls/ca.pem"

# Consensus configuration
[consensus]
validator = true
validator_key = "/opt/moloch/keys/node.key"
block_time_ms = 1000
max_events_per_block = 1000

# Storage configuration
[storage]
backend = "rocksdb"
cache_size_mb = 512
write_buffer_size_mb = 64
max_open_files = 10000

# API configuration
[api]
enabled = true
listen_addr = "0.0.0.0:8080"
max_connections = 1000
rate_limit_per_minute = 600

# API authentication
[api.auth]
require_auth = true
jwt_secret_file = "/opt/moloch/config/jwt_secret"
api_keys_file = "/opt/moloch/config/api_keys.json"

# Metrics configuration
[metrics]
enabled = true
prometheus_addr = "0.0.0.0:9090"

# Anchoring configuration (optional)
[anchoring]
enabled = true
interval_blocks = 100

[anchoring.bitcoin]
enabled = true
rpc_url = "http://localhost:8332"
rpc_user = "moloch"
rpc_password_file = "/opt/moloch/config/bitcoin_rpc_password"
network = "mainnet"
wallet = "moloch-anchor"
required_confirmations = 6
```

### Genesis Configuration (genesis.json)

```json
{
  "chain_id": "moloch-mainnet",
  "timestamp": "2024-01-01T00:00:00Z",
  "validators": [
    {
      "public_key": "ed25519:abc123...",
      "power": 1,
      "name": "validator-1"
    },
    {
      "public_key": "ed25519:def456...",
      "power": 1,
      "name": "validator-2"
    },
    {
      "public_key": "ed25519:ghi789...",
      "power": 1,
      "name": "validator-3"
    }
  ],
  "consensus": {
    "block_time_ms": 1000,
    "max_events_per_block": 1000
  }
}
```

## Deployment Modes

### Single Node (Development)

```bash
# Generate node keys
./target/release/moloch keygen --output /opt/moloch/keys/

# Initialize chain
./target/release/moloch init \
  --chain-id "moloch-dev" \
  --genesis /opt/moloch/config/genesis.json

# Start node
./target/release/moloch run --config /opt/moloch/config/node.toml
```

### Validator Cluster (Production)

**Node 1 (Initial Validator):**
```bash
# Generate keys on each node
./target/release/moloch keygen --output /opt/moloch/keys/

# Share public keys among validators
# Create genesis with all validator public keys

# Initialize with shared genesis
./target/release/moloch init \
  --chain-id "moloch-mainnet" \
  --genesis /opt/moloch/config/genesis.json

# Start validator
./target/release/moloch run \
  --config /opt/moloch/config/node.toml \
  --validator
```

**Additional Validators:**
```bash
# Same process, but use boot_nodes to connect to existing validators
./target/release/moloch run \
  --config /opt/moloch/config/node.toml \
  --validator \
  --boot-nodes "/dns/node1.example.com/tcp/9000/p2p/12D3KooW..."
```

### Non-Validator Node (Archive/API)

```bash
# No validator flag, receives and stores all data
./target/release/moloch run \
  --config /opt/moloch/config/node.toml \
  --api-only
```

## Systemd Service

### Service File (/etc/systemd/system/moloch.service)

```ini
[Unit]
Description=Moloch Audit Chain Node
After=network.target

[Service]
Type=simple
User=moloch
Group=moloch
ExecStart=/opt/moloch/bin/moloch run --config /opt/moloch/config/node.toml
Restart=always
RestartSec=10
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/moloch/data /opt/moloch/logs

# Resource limits
MemoryMax=8G
CPUQuota=400%

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
# Create moloch user
sudo useradd -r -s /bin/false moloch

# Set permissions
sudo chown -R moloch:moloch /opt/moloch

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable moloch
sudo systemctl start moloch

# Check status
sudo systemctl status moloch
sudo journalctl -u moloch -f
```

## High Availability Setup

### Architecture

```
                    ┌─────────────────────────────────────────┐
                    │            Load Balancer                │
                    │         (HAProxy/NGINX)                 │
                    └─────────────────┬───────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
              ▼                       ▼                       ▼
     ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
     │   API Node 1    │    │   API Node 2    │    │   API Node 3    │
     │  (non-validator)│    │  (non-validator)│    │  (non-validator)│
     └────────┬────────┘    └────────┬────────┘    └────────┬────────┘
              │                       │                       │
              └───────────────────────┼───────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
              ▼                       ▼                       ▼
     ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
     │  Validator 1    │◄──►│  Validator 2    │◄──►│  Validator 3    │
     │                 │    │                 │    │                 │
     └─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Load Balancer Configuration (HAProxy)

```
frontend moloch_api
    bind *:443 ssl crt /etc/ssl/moloch.pem
    default_backend moloch_api_servers

backend moloch_api_servers
    balance roundrobin
    option httpchk GET /v1/status
    server api1 10.0.1.1:8080 check
    server api2 10.0.1.2:8080 check
    server api3 10.0.1.3:8080 check
```

## Bitcoin Anchoring Setup

### Bitcoin Core Configuration

```bash
# bitcoin.conf
server=1
rpcuser=moloch
rpcpassword=<secure-password>
rpcallowip=127.0.0.1
wallet=moloch-anchor

# For mainnet
chain=main
# For testnet
# chain=test
```

### Create Anchor Wallet

```bash
# Create wallet
bitcoin-cli createwallet "moloch-anchor"

# Generate address for funding
bitcoin-cli -rpcwallet=moloch-anchor getnewaddress "anchor-funds"

# Fund the wallet (send BTC to this address)
```

### Moloch Anchoring Configuration

```toml
[anchoring.bitcoin]
enabled = true
rpc_url = "http://127.0.0.1:8332"
rpc_user = "moloch"
rpc_password_file = "/opt/moloch/config/bitcoin_rpc_password"
network = "mainnet"
wallet = "moloch-anchor"
required_confirmations = 6
fee_rate_sat_vb = 0  # 0 = auto-estimate
```

## Backup and Recovery

### Backup Script

```bash
#!/bin/bash
# /opt/moloch/scripts/backup.sh

BACKUP_DIR="/backup/moloch/$(date +%Y%m%d)"
DATA_DIR="/opt/moloch/data"

# Stop node for consistent backup
sudo systemctl stop moloch

# Create backup
mkdir -p "$BACKUP_DIR"
rsync -av "$DATA_DIR/" "$BACKUP_DIR/data/"
cp /opt/moloch/config/*.toml "$BACKUP_DIR/"
cp /opt/moloch/keys/*.key "$BACKUP_DIR/"

# Restart node
sudo systemctl start moloch

# Compress and encrypt
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
gpg --encrypt --recipient backup@example.com "$BACKUP_DIR.tar.gz"

# Upload to remote storage
aws s3 cp "$BACKUP_DIR.tar.gz.gpg" s3://moloch-backups/

# Cleanup
rm -rf "$BACKUP_DIR" "$BACKUP_DIR.tar.gz"
```

### Recovery Process

```bash
# 1. Stop node
sudo systemctl stop moloch

# 2. Download and decrypt backup
aws s3 cp s3://moloch-backups/20240115.tar.gz.gpg .
gpg --decrypt 20240115.tar.gz.gpg > 20240115.tar.gz
tar -xzf 20240115.tar.gz

# 3. Restore data
rm -rf /opt/moloch/data/*
rsync -av 20240115/data/ /opt/moloch/data/

# 4. Restore configuration (if needed)
cp 20240115/*.toml /opt/moloch/config/

# 5. Set permissions
sudo chown -R moloch:moloch /opt/moloch

# 6. Start node
sudo systemctl start moloch

# 7. Verify sync
curl http://localhost:8080/v1/status
```

## Security Checklist

### Network Security

- [ ] TLS 1.3 enabled for all connections
- [ ] Firewall rules restrict P2P ports to known validators
- [ ] API endpoints behind load balancer with DDoS protection
- [ ] Rate limiting configured

### Access Control

- [ ] SSH key-only authentication
- [ ] Principle of least privilege for service accounts
- [ ] API keys rotated regularly
- [ ] JWT secrets secured

### Data Protection

- [ ] Encrypted backups
- [ ] Private keys stored securely (HSM for production)
- [ ] Logs sanitized of sensitive data

### Monitoring

- [ ] Metrics exported to monitoring system
- [ ] Alerts configured for critical events
- [ ] Log aggregation enabled
- [ ] Regular security audits scheduled

## Troubleshooting

### Node Won't Start

```bash
# Check logs
journalctl -u moloch -n 100 --no-pager

# Verify configuration
./target/release/moloch validate-config --config /opt/moloch/config/node.toml

# Check permissions
ls -la /opt/moloch/data
ls -la /opt/moloch/keys
```

### Sync Issues

```bash
# Check peer connections
curl http://localhost:8080/v1/status | jq .peer_count

# Check sync status
curl http://localhost:8080/v1/status | jq .syncing

# Manually add peers
./target/release/moloch peers add "/dns/peer.example.com/tcp/9000/p2p/12D3KooW..."
```

### Storage Issues

```bash
# Check disk space
df -h /opt/moloch/data

# Compact RocksDB
./target/release/moloch maintenance compact

# Check database integrity
./target/release/moloch maintenance verify
```
