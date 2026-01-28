# Moloch Operations Guide

Guide for operating and maintaining a Moloch node in production.

## Monitoring

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `moloch_chain_height` | Current block height | No increase in 5m |
| `moloch_peer_count` | Connected peers | < 3 |
| `moloch_mempool_size` | Pending events | > 10000 |
| `moloch_block_time_ms` | Block production time | > 2000 |
| `moloch_sync_lag` | Blocks behind tip | > 10 |
| `moloch_api_latency_ms` | API response time | p99 > 500 |
| `moloch_storage_bytes` | Disk usage | > 80% capacity |

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'moloch'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
```

### Grafana Dashboard

Import the pre-built dashboard from `docs/monitoring/grafana-dashboard.json` or create panels for:

1. **Chain Health**
   - Block height over time
   - Block production rate
   - Finalization lag

2. **Network**
   - Peer connections
   - Bandwidth usage
   - Message rates

3. **Performance**
   - API latency percentiles
   - Mempool depth
   - Event throughput

4. **Resources**
   - CPU usage
   - Memory usage
   - Disk I/O

### Log Analysis

```bash
# View recent logs
journalctl -u moloch -n 100 --no-pager

# Filter by level
journalctl -u moloch | grep -E "ERROR|WARN"

# Follow logs
journalctl -u moloch -f

# Export logs for analysis
journalctl -u moloch --since "1 hour ago" > moloch_logs.txt
```

### Health Checks

```bash
# API health endpoint
curl http://localhost:8080/v1/health

# Detailed status
curl http://localhost:8080/v1/status | jq

# Expected output:
# {
#   "chain_id": "moloch-mainnet",
#   "head_height": 12345,
#   "head_hash": "abc123...",
#   "peer_count": 5,
#   "syncing": false,
#   "version": "1.0.0"
# }
```

## Alerting

### Critical Alerts

```yaml
# Alert rules (Prometheus)
groups:
  - name: moloch
    rules:
      - alert: MolochNodeDown
        expr: up{job="moloch"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Moloch node is down"

      - alert: MolochNotProducingBlocks
        expr: increase(moloch_chain_height[5m]) == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "No new blocks in 5 minutes"

      - alert: MolochLowPeerCount
        expr: moloch_peer_count < 3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low peer count: {{ $value }}"

      - alert: MolochHighMempool
        expr: moloch_mempool_size > 10000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Mempool backlog: {{ $value }} events"

      - alert: MolochSyncLag
        expr: moloch_sync_lag > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Node is {{ $value }} blocks behind"

      - alert: MolochDiskSpaceLow
        expr: moloch_storage_bytes / moloch_storage_capacity > 0.8
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Disk usage above 80%"
```

## Maintenance Tasks

### Daily

1. **Review logs** for errors and warnings
2. **Check metrics** for anomalies
3. **Verify backups** completed successfully

### Weekly

1. **Disk space audit**
   ```bash
   du -sh /opt/moloch/data/*
   ```

2. **Peer connectivity review**
   ```bash
   curl http://localhost:8080/v1/peers | jq
   ```

3. **Performance review**
   - Check block production times
   - Review API latencies

### Monthly

1. **Security updates**
   ```bash
   sudo apt update && sudo apt upgrade
   ```

2. **Log rotation verification**
   ```bash
   ls -la /opt/moloch/logs/
   ```

3. **Backup restoration test**
   - Restore to staging environment
   - Verify data integrity

### Quarterly

1. **Capacity planning review**
2. **Security audit**
3. **Disaster recovery drill**

## Common Operations

### Adding a Peer Manually

```bash
# Add peer
./target/release/moloch peers add "/dns/peer.example.com/tcp/9000/p2p/12D3KooW..."

# List peers
./target/release/moloch peers list

# Remove peer
./target/release/moloch peers remove "12D3KooW..."
```

### Validator Operations

```bash
# Check validator status
./target/release/moloch validator status

# Expected output for active validator:
# Validator: active
# Public Key: ed25519:abc123...
# Power: 1
# Blocks Proposed (24h): 1440
# Next Slot: 12345 (in 2s)
```

### Storage Management

```bash
# Check storage statistics
./target/release/moloch storage stats

# Output:
# Chain Data:     45.2 GB
# MMR Data:       2.1 GB
# Index Data:     8.5 GB
# Total:          55.8 GB
# Events:         1,234,567
# Blocks:         12,345

# Compact database (reduces disk usage)
./target/release/moloch maintenance compact

# Prune old data (if configured)
./target/release/moloch maintenance prune --before-height 1000000
```

### Resyncing

```bash
# Full resync (preserves keys and config)
sudo systemctl stop moloch
rm -rf /opt/moloch/data/chain/*
rm -rf /opt/moloch/data/mmr/*
rm -rf /opt/moloch/data/index/*
sudo systemctl start moloch

# Monitor sync progress
watch -n 5 'curl -s http://localhost:8080/v1/status | jq "{height: .head_height, syncing: .syncing}"'
```

### Key Rotation

```bash
# Generate new keys (for non-validators only)
./target/release/moloch keygen --output /opt/moloch/keys/new/

# For validators: coordinate with other validators
# 1. Propose validator set change
# 2. Wait for approval
# 3. Switch to new key at epoch boundary
```

## Incident Response

### Node Not Syncing

```
Symptoms:
- head_height not increasing
- syncing: true but no progress

Steps:
1. Check peer connections
   curl http://localhost:8080/v1/status | jq .peer_count

2. If peer_count = 0:
   - Check firewall rules
   - Verify boot nodes are reachable
   - Add peers manually

3. If peer_count > 0:
   - Check for network partition
   - Verify peers are on same chain_id
   - Check for clock skew

4. Check logs for errors
   journalctl -u moloch -n 100 | grep ERROR

5. If needed, force resync from checkpoint
```

### High Latency

```
Symptoms:
- API response time > 500ms
- Block production slow

Steps:
1. Check system resources
   htop

2. If CPU high:
   - Check for runaway processes
   - Consider scaling horizontally

3. If memory high:
   - Increase RocksDB cache (if RAM available)
   - Reduce max_open_files

4. If I/O high:
   - Check disk health
   - Consider NVMe upgrade
   - Run compaction: ./target/release/moloch maintenance compact

5. If network high:
   - Check for DDoS
   - Review rate limits
   - Consider adding API nodes
```

### Consensus Stall

```
Symptoms:
- No new blocks
- All validators appear online

Steps:
1. Check all validator logs for errors

2. Verify clock synchronization
   chronyc tracking

3. Check network connectivity between validators

4. If one validator stuck:
   - Restart that validator
   - Other validators should continue

5. If majority stuck:
   - Coordinate manual restart of all validators
   - Investigate root cause before restart

6. If <2/3 validators online:
   - Chain cannot progress (by design)
   - Bring offline validators back online
```

### Data Corruption

```
Symptoms:
- Verification errors in logs
- Inconsistent state

Steps:
1. Stop node immediately
   sudo systemctl stop moloch

2. Assess damage
   ./target/release/moloch maintenance verify

3. If minor corruption:
   - Run repair tool
   ./target/release/moloch maintenance repair

4. If major corruption:
   - Restore from backup
   - Or resync from scratch

5. Investigate root cause:
   - Hardware failure?
   - Software bug?
   - Unclean shutdown?
```

## Upgrades

### Planning

1. **Read release notes** for breaking changes
2. **Test on staging** with production data copy
3. **Schedule maintenance window**
4. **Notify stakeholders**

### Rolling Upgrade (Zero Downtime)

For non-breaking changes:

```bash
# On each node sequentially:

# 1. Build new version
cd /opt/moloch/src
git pull
cargo build --release

# 2. Graceful restart
sudo systemctl restart moloch

# 3. Verify health
curl http://localhost:8080/v1/status

# 4. Wait for sync before proceeding to next node
```

### Coordinated Upgrade

For breaking changes:

```bash
# 1. Stop all nodes at scheduled time
# (Coordinate via out-of-band channel)

# 2. Upgrade binary on all nodes

# 3. Run any required migrations
./target/release/moloch migrate

# 4. Start validators first (in agreed order)

# 5. Start API nodes

# 6. Verify consensus resumes
```

### Rollback

```bash
# If upgrade fails:

# 1. Stop node
sudo systemctl stop moloch

# 2. Restore previous binary
cp /opt/moloch/bin/moloch.backup /opt/moloch/bin/moloch

# 3. If schema changed, restore data from backup
# (See recovery process in deployment.md)

# 4. Start node
sudo systemctl start moloch
```

## Performance Tuning

### RocksDB Tuning

```toml
# node.toml
[storage]
# Increase for better read performance (uses RAM)
cache_size_mb = 1024

# Increase for better write performance
write_buffer_size_mb = 128

# Increase if hitting "too many open files"
max_open_files = 50000

# Enable compression for smaller disk usage
compression = "lz4"
```

### Network Tuning

```toml
# node.toml
[network]
# Increase for more redundancy
max_peers = 100

# Increase for faster sync
max_concurrent_requests = 10

# Adjust based on bandwidth
message_buffer_size = 1000
```

### System Tuning

```bash
# /etc/sysctl.conf

# Increase file descriptor limit
fs.file-max = 1000000

# Network tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# Apply changes
sudo sysctl -p
```

## Runbooks

### Runbook: Node Restart

```
Trigger: Planned maintenance or performance issues

Steps:
1. Notify stakeholders (if validator)
2. Verify no critical events pending
   curl http://localhost:8080/v1/status | jq .mempool_size
3. Graceful stop
   sudo systemctl stop moloch
4. Wait for clean shutdown (check logs)
5. Start node
   sudo systemctl start moloch
6. Verify health
   curl http://localhost:8080/v1/health
7. Monitor for 5 minutes
8. Notify stakeholders of completion

Rollback:
- If node fails to start, check logs
- Restore from backup if data corrupted
```

### Runbook: Emergency Shutdown

```
Trigger: Security incident, data corruption, or critical bug

Steps:
1. Immediately stop all nodes
   sudo systemctl stop moloch
2. Disable auto-restart
   sudo systemctl disable moloch
3. Preserve state for investigation
   cp -r /opt/moloch/data /opt/moloch/data.incident-$(date +%s)
4. Notify security team
5. Do NOT delete any data
6. Document timeline of events

Recovery:
- Wait for security clearance
- Follow "Data Corruption" recovery if needed
```
