# Moloch Benchmark Report

**Date:** 2025-01-03
**Platform:** Linux (WSL2), AVX-512 capable CPU
**Allocator:** mimalloc

---

## Executive Summary

Moloch is an enterprise audit chain with post-quantum cryptography, zero-knowledge proofs, and threshold encryption. Key performance highlights:

| Capability | Performance | Note |
|------------|-------------|------|
| **ZK Proof Generation** | **1.9 µs** | 500K+ proofs/second |
| **ZK Proof Verification** | **1.5 µs** | 685K+ verifications/second |
| **Post-Quantum Keygen (ML-KEM-768)** | **51 µs** | Only 4x slower than Ed25519 |
| **Threshold Encryption (5-of-7)** | **71 µs** | 14K ops/second |
| **MMR Root Computation** | **167 ns** | 6M roots/second |
| **Block Validation (batch)** | **2.13x faster** | vs sequential |
| **Lock-Free Mempool** | **9.8x faster** | vs mutex at 8 threads |

---

## Zero-Knowledge Proofs

Ultra-fast ZK proofs for auditable privacy:

| Operation | Time | Throughput |
|-----------|------|------------|
| Existence proof | **1.93 µs** | 518K proofs/s |
| Event type proof | **2.07 µs** | 483K proofs/s |
| Actor membership proof | **2.60 µs** | 385K proofs/s |
| Proof verification | **1.46 µs** | **685K verifications/s** |

**Use cases:**
- Prove an audit event exists without revealing content
- Prove event type (e.g., "Push") without revealing actor
- Prove actor is in a set without revealing which one

---

## Post-Quantum Cryptography (ML-KEM-768)

Quantum-resistant encryption ready for the future:

| Operation | Time | vs Ed25519 |
|-----------|------|------------|
| ML-KEM-768 keygen | **51 µs** | 4x slower |
| Quantum-safe seal | **57 µs** | - |
| Quantum-safe unseal | **74 µs** | - |
| Ed25519 keygen | 12.8 µs | (baseline) |

**Trade-off:** 4x slower keygen for quantum resistance is excellent. ML-KEM-768 provides NIST Level 3 security.

---

## HoloCrypt (Selective Field Encryption)

Encrypt sensitive fields while keeping structure visible:

| Operation | Time | Throughput |
|-----------|------|------------|
| Seal (default policy) | **24 µs** | 42K seals/s |
| Seal (all encrypted) | **24 µs** | 42K seals/s |
| Seal (all public) | **20 µs** | 50K seals/s |
| Unseal | **40 µs** | 25K unseals/s |
| Verify structure | **27 µs** | 38K verifications/s |

**Policies:**
- `default`: Encrypt sensitive fields (actor, metadata)
- `all_encrypted`: Full encryption
- `all_public`: No encryption (transparent mode)

---

## Threshold Encryption

Multi-party decryption with k-of-n schemes:

| Scheme | Seal | Unseal |
|--------|------|--------|
| 2-of-3 | **65 µs** | **47 µs** |
| 3-of-5 | **67 µs** | **51 µs** |
| 5-of-7 | **71 µs** | - |

**Use case:** Require multiple parties to decrypt sensitive audit events.

---

## Merkle Mountain Range (MMR)

Efficient append-only accumulator for audit logs:

### Root Computation (Cached)
| Leaves | Time | Throughput |
|--------|------|------------|
| 10 | **167 ns** | 6M roots/s |
| 100 | **271 ns** | 3.7M roots/s |
| 1,000 | **644 ns** | 1.6M roots/s |
| 5,000 | **544 ns** | 1.8M roots/s |

### Append Operations
| Batch Size | Sequential | Batch | Speedup |
|------------|------------|-------|---------|
| 100 | 62.5 µs | **29.8 µs** | **2.1x** |
| 500 | 338 µs | **153 µs** | **2.2x** |
| 1,000 | 625 µs | **309 µs** | **2.0x** |

### Proof Generation
| Count | Sequential | Parallel | Speedup |
|-------|------------|----------|---------|
| 100 | 149 µs | **61 µs** | **2.4x** |
| 500 | 790 µs | **299 µs** | **2.6x** |
| 1,000 | 1.55 ms | **567 µs** | **2.7x** |

### Proof Verification
| Count | Sequential | Parallel | Speedup |
|-------|------------|----------|---------|
| 500 | 1.08 ms | **795 µs** | **1.4x** |
| 1,000 | 2.24 ms | **1.94 ms** | **1.2x** |

---

## Block Validation

Parallel validation of event signatures:

| Block Size | Sequential | Batch | Parallel | Speedup |
|------------|------------|-------|----------|---------|
| 10 events | 222 µs | 136 µs | 138 µs | **1.6x** |
| 100 events | 2.03 ms | 1.13 ms | 1.14 ms | **1.8x** |
| 500 events | 10.1 ms | 4.74 ms | 4.68 ms | **2.1x** |

**Key insight:** Batch signature verification is critical for block validation throughput.

---

## Lock-Free Mempool

High-concurrency transaction pool:

### Single-Threaded Take
| Pool Size | Mutex | Lock-Free | Speedup |
|-----------|-------|-----------|---------|
| 1,000 | 393 µs | **89 µs** | **4.4x** |

### Concurrent Add (8 threads)
| Threads | Mutex | Lock-Free | Speedup |
|---------|-------|-----------|---------|
| 2 | 20K elem/s | 53K elem/s | **2.6x** |
| 4 | 20K elem/s | 101K elem/s | **5x** |
| 8 | 20K elem/s | **194K elem/s** | **9.8x** |

### Producer-Consumer
| Config | Throughput |
|--------|------------|
| 2 producers, 2 consumers | 50K elem/s |
| 4 producers, 2 consumers | 97K elem/s |
| 4 producers, 4 consumers | 97K elem/s |

**Key insight:** Lock-free scales near-linearly with threads; mutex hits contention ceiling.

---

## Serialization Comparison

| Format | Serialize | Deserialize | Size |
|--------|-----------|-------------|------|
| JSON | 3.1 µs | 7.2 µs | ~450 bytes |
| Bincode | 412 ns | 1.1 µs | ~280 bytes |
| rkyv | 1.4 µs | **0 ns** (zero-copy) | ~320 bytes |

**rkyv zero-copy:** Access archived data directly without deserialization - perfect for memory-mapped storage.

---

## Event Operations

| Operation | Time |
|-----------|------|
| Create + sign | **18.4 µs** |
| Compute ID | **1.2 µs** |
| Validate signature | **19.2 µs** |

---

## Hash Throughput (BLAKE3 via Arcanum)

| Size | Throughput |
|------|------------|
| 32 bytes | 147 MB/s |
| 256 bytes | 668 MB/s |
| 1 KB | 1.19 GB/s |
| 4 KB | 1.64 GB/s |
| 16 KB | 2.44 GB/s |

Using Arcanum's SIMD-accelerated BLAKE3.

---

## Signature Operations (Ed25519)

| Operation | Time |
|-----------|------|
| Sign | **15.2 µs** |
| Verify | **18.5 µs** |

---

## Architecture Highlights

### Cryptographic Stack
- **Arcanum**: SIMD-accelerated BLAKE3, Ed25519
- **HoloCrypt**: Selective field encryption
- **Post-Quantum**: ML-KEM-768 (NIST Level 3)
- **Threshold**: k-of-n Shamir-based encryption

### Concurrency
- **Lock-free mempool**: Scales to 8+ threads
- **Parallel MMR**: Batch operations with rayon
- **Batch verification**: Ed25519 batch signature checking

### Storage
- **rkyv**: Zero-copy deserialization
- **MMR**: O(log n) inclusion proofs
- **Indexes**: By actor, resource, time, event type

---

## Running Benchmarks

```bash
cd /path/to/moloch

# All benchmarks
CARGO_INCREMENTAL=0 RUSTFLAGS="-C target-cpu=native" \
  cargo bench -p moloch-bench

# Specific benchmark suite
CARGO_INCREMENTAL=0 RUSTFLAGS="-C target-cpu=native" \
  cargo bench -p moloch-bench --bench crypto_benchmarks

# Available suites:
#   core_benchmarks    - Event, block, signatures
#   crypto_benchmarks  - HoloCrypt, ZK, PQC, threshold
#   mmr_benchmarks     - MMR operations
#   mempool_benchmarks - Lock-free vs mutex
#   chain_benchmarks   - Chain operations
#   storage_benchmarks - Storage layer
```

---

## Comparison with Other Systems

| Feature | Moloch | Ethereum | Hyperledger |
|---------|--------|----------|-------------|
| ZK Proofs | 1.9 µs | ~10ms (zkSNARK) | N/A |
| Post-Quantum | Yes (ML-KEM) | No | No |
| Threshold Encryption | Native | External | External |
| Consensus | PoA (Aura-style) | PoS | PBFT/Raft |
| TPS (theoretical) | 50K+ events/s | ~15 tx/s | ~3K tx/s |

---

*Generated: 2025-01-03*
*Moloch: Enterprise Audit Chain with Post-Quantum Security*
*Daemoniorum Engineering*
