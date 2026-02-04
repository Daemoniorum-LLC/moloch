# Moloch Agent Quickstart Guide

**Purpose:** This document helps AI agents quickly understand how to run benchmarks, find key files, and work with the Moloch audit chain.

**Last Updated:** 2025-01-03

---

## TL;DR - Run This

```bash
cd /path/to/moloch

# Run all benchmarks
CARGO_INCREMENTAL=0 RUSTFLAGS="-C target-cpu=native" \
  cargo bench -p moloch-bench

# Run specific crypto benchmarks (ZK, PQC, threshold)
CARGO_INCREMENTAL=0 RUSTFLAGS="-C target-cpu=native" \
  cargo bench -p moloch-bench --bench crypto_benchmarks
```

Expected highlights:
- **ZK proofs:** 1.9 µs generation, 1.5 µs verification
- **Post-quantum keygen:** 51 µs (only 4x slower than Ed25519)
- **Lock-free mempool:** 9.8x faster than mutex at 8 threads

---

## What is Moloch?

Moloch is an **enterprise audit chain** with:
- **HoloCrypt:** Selective field encryption (encrypt actor but not event type)
- **Zero-Knowledge Proofs:** Prove existence/type without revealing content
- **Post-Quantum:** ML-KEM-768 for quantum resistance
- **Threshold Encryption:** k-of-n multi-party decryption
- **MMR:** Merkle Mountain Range for O(log n) proofs
- **Lock-Free Mempool:** Near-linear scaling with threads

---

## Key Locations

### Workspace Root
```
/path/to/moloch/
```

### Crate Structure
```
moloch-core/          # Events, blocks, hashing, signatures
moloch-mmr/           # Merkle Mountain Range
moloch-chain/         # Chain state, mempool, block producer
moloch-storage/       # RocksDB storage layer
moloch-index/         # Secondary indexes, queries
moloch-holocrypt/     # HoloCrypt, ZK proofs, threshold, PQC
moloch-consensus/     # PoA consensus
moloch-net/           # P2P networking
moloch-api/           # REST/gRPC API
moloch-verify/        # Verification utilities
moloch-light/         # Light client
moloch-federation/    # Cross-chain federation
moloch-anchor/        # Generic anchoring
moloch-anchor-bitcoin/    # Bitcoin anchoring
moloch-anchor-ethereum/   # Ethereum anchoring
moloch-bench/         # Benchmarks
```

### Benchmark Files
```
moloch-bench/benches/
├── core_benchmarks.rs     # Events, blocks, signatures
├── crypto_benchmarks.rs   # HoloCrypt, ZK, PQC, threshold
├── mmr_benchmarks.rs      # MMR operations
├── mempool_benchmarks.rs  # Lock-free vs mutex
├── chain_benchmarks.rs    # Chain operations
└── storage_benchmarks.rs  # Storage layer
```

### Key Source Files

**Core Types:**
```
moloch-core/src/
├── event.rs       # AuditEvent, EventType, ActorId, ResourceId
├── block.rs       # Block, BlockBuilder, SealerId
├── hash.rs        # BLAKE3 hashing via Arcanum
├── crypto.rs      # SecretKey, PublicKey, Signature
└── lib.rs         # batch_verify_events, compute_events_root
```

**HoloCrypt (Privacy Layer):**
```
moloch-holocrypt/src/
├── encrypted.rs   # EncryptedEventBuilder, EncryptionPolicy
├── proofs.rs      # EventProof, ProofType (ZK proofs)
├── threshold.rs   # ThresholdConfig, ThresholdEvent, KeyShareSet
└── pqc.rs         # EventPqcKeyPair, PqcEvent, QuantumSafeEvent
```

**MMR:**
```
moloch-mmr/src/
├── mmr.rs         # Mmr, append, append_batch, proof, proof_batch
├── store.rs       # MemStore, trait definitions
└── proof.rs       # MmrProof, verification
```

**Chain:**
```
moloch-chain/src/
├── mempool.rs     # Mempool, LockFreeMempool
├── producer.rs    # BlockProducer
└── state.rs       # ChainState
```

---

## Required Flags

```bash
CARGO_INCREMENTAL=0    # Required for sccache compatibility
RUSTFLAGS="-C target-cpu=native"   # Enable AVX-512 SIMD
```

---

## Running Benchmarks

### All Benchmarks
```bash
CARGO_INCREMENTAL=0 RUSTFLAGS="-C target-cpu=native" \
  cargo bench -p moloch-bench
```

### Specific Suites
```bash
# Crypto (ZK, PQC, threshold, HoloCrypt)
cargo bench -p moloch-bench --bench crypto_benchmarks

# MMR operations
cargo bench -p moloch-bench --bench mmr_benchmarks

# Mempool (lock-free vs mutex)
cargo bench -p moloch-bench --bench mempool_benchmarks

# Core (events, blocks, signatures)
cargo bench -p moloch-bench --bench core_benchmarks

# Chain operations
cargo bench -p moloch-bench --bench chain_benchmarks
```

Results appear in `target/criterion/*/report/index.html`.

---

## Key APIs

### Creating an Audit Event
```rust
use moloch_core::crypto::SecretKey;
use moloch_core::event::{ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind};

let key = SecretKey::generate();
let actor = ActorId::new(key.public_key(), ActorKind::User);
let resource = ResourceId::new(ResourceKind::Repository, "my-repo");

let event = AuditEvent::builder()
    .now()
    .event_type(EventType::Push { force: false, commits: 5 })
    .actor(actor)
    .resource(resource)
    .outcome(Outcome::Success)
    .metadata(serde_json::json!({"branch": "main"}))
    .sign(&key)
    .unwrap();
```

### HoloCrypt (Selective Encryption)
```rust
use moloch_holocrypt::{EncryptedEventBuilder, EncryptionPolicy, generate_keypair};

let (sealing_key, opening_key) = generate_keypair("my-key");

// Encrypt with default policy (sensitive fields only)
let encrypted = EncryptedEventBuilder::new()
    .event(event)
    .policy(EncryptionPolicy::default())
    .build(&sealing_key)
    .unwrap();

// Decrypt
let decrypted = encrypted.decrypt(&opening_key).unwrap();
```

### Zero-Knowledge Proofs
```rust
use moloch_holocrypt::{EventProof, ProofType};

// Prove event exists without revealing content
let proof = EventProof::builder()
    .event(encrypted.clone())
    .prove_existence()
    .build()
    .unwrap();

// Verify
proof.verify(&encrypted).unwrap();

// Prove event type without revealing actor
let proof = EventProof::builder()
    .event(encrypted.clone())
    .prove_event_type("Push")
    .build()
    .unwrap();
```

### Threshold Encryption
```rust
use moloch_holocrypt::{ThresholdConfig, ThresholdEvent, KeyShareSet};

// 2-of-3 threshold encryption
let config = ThresholdConfig::two_of_three();
let (threshold_event, shares) = ThresholdEvent::seal(&event, config).unwrap();

// Collect 2 shares to decrypt
let mut share_set = KeyShareSet::new();
share_set.add(shares[0].clone());
share_set.add(shares[1].clone());

let decrypted = threshold_event.unseal(&share_set).unwrap();
```

### Post-Quantum Encryption
```rust
use moloch_holocrypt::{EventPqcKeyPair, QuantumSafeEvent};

// Generate ML-KEM-768 keypair
let pqc_key = EventPqcKeyPair::generate("my-pqc-key");

// Quantum-safe encryption
let sealed = QuantumSafeEvent::seal(&event, &pqc_key).unwrap();
let unsealed = sealed.unseal(&pqc_key).unwrap();
```

### MMR Operations
```rust
use moloch_mmr::{Mmr, MemStore};
use moloch_core::hash;

let mut mmr = Mmr::new(MemStore::new());

// Append leaves
let leaves: Vec<_> = (0..100).map(|i| hash(&i.to_le_bytes())).collect();
let positions = mmr.append_batch(&leaves).unwrap();

// Get root
let root = mmr.root();

// Generate proof
let proof = mmr.proof(positions[0]).unwrap();

// Verify
mmr.verify(&proof).unwrap();
```

### Lock-Free Mempool
```rust
use moloch_chain::mempool::LockFreeMempool;

let mempool = LockFreeMempool::new(10_000); // capacity

// Add events (thread-safe)
mempool.add(event);

// Take batch for block production
let batch = mempool.take_batch(100);
```

---

## Performance Results Summary

### ZK Proofs (The Star)
```
Existence proof:    1.93 µs  (518K proofs/sec)
Event type proof:   2.07 µs  (483K proofs/sec)
Proof verification: 1.46 µs  (685K verifications/sec)
```

### Post-Quantum (ML-KEM-768)
```
Keygen:       51 µs  (vs 12.8 µs for Ed25519 = 4x slower)
Seal:         57 µs
Unseal:       74 µs
```

### MMR
```
Root (1000 leaves): 644 ns  (1.6M roots/sec)
Proof gen (1000):   567 µs parallel (2.7x faster than sequential)
```

### Lock-Free Mempool
```
8 threads: 194K elem/s  (vs 20K for mutex = 9.8x faster)
```

---

## Common Patterns

### Batch Signature Verification
```rust
use moloch_core::batch_verify_events;

let events: Vec<AuditEvent> = /* ... */;
batch_verify_events(&events).unwrap();
```

### Parallel Merkle Root
```rust
use moloch_core::compute_events_root_parallel;

let root = compute_events_root_parallel(&events);
```

### Zero-Copy Serialization (rkyv)
```rust
use moloch_core::rkyv_types::{archive_event, access_event_unchecked};

// Serialize (for storage)
let bytes = archive_event(&event);

// Zero-copy access (no deserialization!)
let archived = unsafe { access_event_unchecked(&bytes) };
println!("Timestamp: {}", archived.timestamp_ms);
```

---

## Dependencies

Moloch uses Arcanum for cryptographic primitives:
```toml
arcanum-hash = { path = "../arcanum/crates/arcanum-hash", features = ["blake3"] }
arcanum-signatures = { path = "../arcanum/crates/arcanum-signatures", features = ["ed25519", "batch"] }
```

---

## Quick Validation

```bash
# Check compilation
CARGO_INCREMENTAL=0 cargo check -p moloch-core -p moloch-holocrypt

# Run tests
CARGO_INCREMENTAL=0 cargo test -p moloch-core
CARGO_INCREMENTAL=0 cargo test -p moloch-holocrypt

# Run specific crypto benchmark
CARGO_INCREMENTAL=0 RUSTFLAGS="-C target-cpu=native" \
  cargo bench -p moloch-bench --bench crypto_benchmarks -- "zk/prove"
```

---

## Architecture Notes

### Cryptographic Stack
1. **Arcanum**: SIMD-accelerated BLAKE3, Ed25519
2. **HoloCrypt**: Selective encryption built on XChaCha20-Poly1305
3. **ZK Proofs**: Hash-based commitments with selective reveal
4. **Post-Quantum**: ML-KEM-768 via arcanum-pqc
5. **Threshold**: Shamir secret sharing with k-of-n reconstruction

### Why So Fast?
- **SIMD everywhere**: AVX-512 for hashing, batch operations
- **Lock-free**: Mempool uses atomic operations, not mutexes
- **Zero-copy**: rkyv for storage access without deserialization
- **Batch operations**: Signature verification, MMR proofs
- **mimalloc**: Faster allocator than system malloc

---

## Summary

1. **Always use** `CARGO_INCREMENTAL=0 RUSTFLAGS="-C target-cpu=native"`
2. **ZK proofs** = 1.9 µs (blazing fast)
3. **Post-quantum** = 4x slower than Ed25519 (excellent trade-off)
4. **Lock-free mempool** = 9.8x faster at 8 threads
5. Benchmark suites in `moloch-bench/benches/`

---

*Document maintained for AI agent quality-of-life. Last verified: 2025-01-03*
