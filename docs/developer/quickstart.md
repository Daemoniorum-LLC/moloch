# Moloch Quickstart Guide

Get up and running with the Moloch cryptographic audit chain.

## Prerequisites

- Rust 1.75+ (2021 edition)
- RocksDB development libraries
- For anchoring: Bitcoin Core RPC / Ethereum RPC access (optional)

## Installation

```bash
git clone https://github.com/Daemoniorum-LLC/moloch.git
cd moloch

# Build all crates
cargo build --release

# Run tests
cargo test --lib

# Run benchmarks (optional)
RUSTFLAGS="-C target-cpu=native" cargo bench -p moloch-bench
```

## Core Concepts

### Audit Events

The fundamental unit is an `AuditEvent` - an immutable, signed record of an action:

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

### Blocks and Chain

Events are batched into signed blocks:

```rust
use moloch_core::block::{Block, BlockBuilder};

let block = BlockBuilder::new()
    .height(1)
    .parent(parent_hash)
    .events(events)
    .seal(&sealer_key)
    .unwrap();
```

### Merkle Mountain Range (MMR)

Efficient append-only accumulator with O(log n) proofs:

```rust
use moloch_mmr::{Mmr, MemStore};
use moloch_core::hash;

let mut mmr = Mmr::new(MemStore::new());
let leaves: Vec<_> = (0..100).map(|i| hash(&i.to_le_bytes())).collect();
let positions = mmr.append_batch(&leaves).unwrap();

// Generate and verify proof
let proof = mmr.proof(positions[0]).unwrap();
mmr.verify(&proof).unwrap();
```

## Privacy Features (HoloCrypt)

### Selective Encryption

Encrypt sensitive fields while keeping structure visible:

```rust
use moloch_holocrypt::{EncryptedEventBuilder, EncryptionPolicy, generate_keypair};

let (sealing_key, opening_key) = generate_keypair("my-key");

let encrypted = EncryptedEventBuilder::new()
    .event(event)
    .policy(EncryptionPolicy::default())
    .build(&sealing_key)
    .unwrap();

let decrypted = encrypted.decrypt(&opening_key).unwrap();
```

### Zero-Knowledge Proofs

Prove properties without revealing content:

```rust
use moloch_holocrypt::{EventProof, ProofType};

// Prove event exists
let proof = EventProof::builder()
    .event(encrypted.clone())
    .prove_existence()
    .build()
    .unwrap();

proof.verify(&encrypted).unwrap();

// Prove event type without revealing actor
let proof = EventProof::builder()
    .event(encrypted.clone())
    .prove_event_type("Push")
    .build()
    .unwrap();
```

### Threshold Encryption

k-of-n multi-party decryption:

```rust
use moloch_holocrypt::{ThresholdConfig, ThresholdEvent, KeyShareSet};

let config = ThresholdConfig::two_of_three();
let (threshold_event, shares) = ThresholdEvent::seal(&event, config).unwrap();

let mut share_set = KeyShareSet::new();
share_set.add(shares[0].clone());
share_set.add(shares[1].clone());

let decrypted = threshold_event.unseal(&share_set).unwrap();
```

### Post-Quantum Encryption

ML-KEM-768 for quantum resistance:

```rust
use moloch_holocrypt::{EventPqcKeyPair, QuantumSafeEvent};

let pqc_key = EventPqcKeyPair::generate("my-pqc-key");
let sealed = QuantumSafeEvent::seal(&event, &pqc_key).unwrap();
let unsealed = sealed.unseal(&pqc_key).unwrap();
```

## Running Benchmarks

```bash
# All benchmarks
CARGO_INCREMENTAL=0 RUSTFLAGS="-C target-cpu=native" cargo bench -p moloch-bench

# Specific suites
cargo bench -p moloch-bench --bench crypto_benchmarks  # ZK, PQC, threshold
cargo bench -p moloch-bench --bench mmr_benchmarks     # MMR operations
cargo bench -p moloch-bench --bench mempool_benchmarks # Lock-free vs mutex
cargo bench -p moloch-bench --bench core_benchmarks    # Events, blocks, sigs
```

Results are saved to `target/criterion/*/report/index.html`.

## Crate Overview

| Crate | Purpose |
|-------|---------|
| `moloch-core` | Events, blocks, signatures, hashing |
| `moloch-mmr` | Merkle Mountain Range accumulator |
| `moloch-chain` | Block chain state machine |
| `moloch-storage` | RocksDB + memory-mapped storage |
| `moloch-index` | Secondary indexes for queries |
| `moloch-holocrypt` | Selective encryption, ZK proofs, PQC |
| `moloch-consensus` | Aura-style Proof of Authority |
| `moloch-net` | P2P networking |
| `moloch-api` | REST/WebSocket API |
| `moloch-light` | Light client verification |
| `moloch-federation` | Cross-chain federation |
| `moloch-anchor` | Base anchoring traits |
| `moloch-anchor-bitcoin` | Bitcoin OP_RETURN anchoring |
| `moloch-anchor-ethereum` | Ethereum calldata anchoring |
| `moloch-verify` | Runtime verification |
| `moloch-bench` | Benchmarks |

## Next Steps

- See [Architecture](./architecture.md) for system design details
- See [API Reference](./api.md) for the REST/WebSocket API
- See [Security](./security.md) for threat model and security considerations
- See [BENCHMARK_REPORT.md](../../BENCHMARK_REPORT.md) for performance data
