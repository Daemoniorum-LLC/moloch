# Moloch

Cryptographic audit chain with post-quantum encryption, zero-knowledge proofs, and cross-chain anchoring.

See [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md) for performance data.

## Features

- **Signed Events** - Ed25519 signatures with Merkle Mountain Range (MMR) accumulation
- **Post-Quantum Encryption** - ML-KEM-768 (NIST Level 3)
- **Zero-Knowledge Proofs** - Prove event existence, type, or actor membership without revealing content
- **Selective Field Encryption** - HoloCrypt encrypts sensitive fields while keeping structure visible
- **Threshold Encryption** - k-of-n decryption schemes
- **Cross-Chain Anchoring** - Anchor roots to Bitcoin (OP_RETURN) and Ethereum (calldata)

## Architecture

```
moloch/
├── moloch-core           # Core types: Event, Block, signatures
├── moloch-mmr            # Merkle Mountain Range accumulator
├── moloch-chain          # Block chain management
├── moloch-storage        # RocksDB + mmap storage layer
├── moloch-index          # Indexes by actor, resource, time, type
├── moloch-net            # P2P networking and sync
├── moloch-consensus      # Aura-style Proof of Authority
├── moloch-api            # REST/WebSocket API layer
├── moloch-holocrypt      # Selective field encryption
├── moloch-light          # Light client verification
├── moloch-federation     # Cross-chain federation
├── moloch-verify         # Runtime verification & invariants
├── moloch-anchor         # Base anchoring traits
├── moloch-anchor-bitcoin # Bitcoin OP_RETURN anchoring
├── moloch-anchor-ethereum# Ethereum calldata anchoring
└── moloch-bench          # Benchmarks
```

## Quick Start

### Prerequisites

- Rust 1.75+ (2021 edition)
- RocksDB development libraries
- For anchoring: Bitcoin Core RPC / Ethereum RPC access

### Building

```bash
# Clone the repository
git clone https://github.com/Daemoniorum-LLC/nyx.git
cd nyx/moloch

# Build all crates
cargo build --release

# Run tests
cargo test --lib

# Run benchmarks
RUSTFLAGS="-C target-cpu=native" cargo bench -p moloch-bench
```

### Basic Usage

```rust
use moloch_core::{Event, EventPayload, Actor};
use moloch_chain::Chain;
use moloch_storage::Storage;

// Create an audit event
let event = Event::builder()
    .actor(Actor::user("alice@example.com"))
    .action("document.sign")
    .resource("contract-2024-001")
    .metadata(serde_json::json!({
        "ip": "192.168.1.100",
        "user_agent": "DocumentSigner/1.0"
    }))
    .build()?;

// Sign and add to chain
let signed_event = event.sign(&signing_key)?;
chain.append(signed_event)?;

// Generate inclusion proof
let proof = chain.prove_inclusion(event.id())?;

// Verify proof (can be done by any party)
assert!(proof.verify(&chain.root())?);
```

### Zero-Knowledge Proofs

```rust
use moloch_holocrypt::zk::{ExistenceProof, ActorMembershipProof};

// Prove an event exists without revealing its content
let existence_proof = ExistenceProof::generate(&event, &chain)?;
assert!(existence_proof.verify(&chain.root())?);

// Prove actor is in a set without revealing which one
let allowed_actors = vec!["alice", "bob", "charlie"];
let membership_proof = ActorMembershipProof::generate(
    &event.actor,
    &allowed_actors
)?;
assert!(membership_proof.verify(&allowed_actors)?);
```

### Selective Encryption (HoloCrypt)

```rust
use moloch_holocrypt::{HoloCrypt, Policy};

// Encrypt sensitive fields, keep structure visible
let holocrypt = HoloCrypt::new(&encryption_key);

let sealed = holocrypt.seal(&event, Policy::default())?;
// sealed.actor is encrypted
// sealed.action is visible
// sealed.resource is visible
// sealed.metadata is encrypted

// Unseal with the key
let unsealed = holocrypt.unseal(&sealed, &decryption_key)?;
```

### Threshold Encryption

```rust
use moloch_holocrypt::threshold::{ThresholdScheme, Share};

// 3-of-5 threshold encryption
let scheme = ThresholdScheme::new(3, 5)?;
let (public_key, shares) = scheme.keygen()?;

// Encrypt with public key
let ciphertext = scheme.encrypt(&public_key, &plaintext)?;

// Decrypt requires 3 shares
let decrypted = scheme.decrypt(&ciphertext, &shares[0..3])?;
```

### Cross-Chain Anchoring

```rust
use moloch_anchor_bitcoin::BitcoinAnchor;
use moloch_anchor_ethereum::EthereumAnchor;

// Anchor to Bitcoin via OP_RETURN
let btc_anchor = BitcoinAnchor::new(bitcoin_rpc)?;
let btc_txid = btc_anchor.anchor(&chain.root())?;

// Anchor to Ethereum via calldata
let eth_anchor = EthereumAnchor::new(ethereum_rpc)?;
let eth_txhash = eth_anchor.anchor(&chain.root())?;

// Later: verify anchor
assert!(btc_anchor.verify(&chain.root(), &btc_txid)?);
```

## Cryptographic Stack

Moloch uses [Arcanum](../arcanum) for cryptographic primitives:

- **Hashing**: BLAKE3
- **Signatures**: Ed25519 with batch verification
- **Post-Quantum**: ML-KEM-768 (NIST FIPS 203)
- **Key Derivation**: Argon2id

## Storage

- **RocksDB**: Primary persistent storage with column families
- **Memory-mapped files**: Zero-copy access via rkyv
- **Indexes**: Actor, resource, time range, event type

## Consensus

Moloch uses an Aura-style Proof of Authority consensus:

- Deterministic block proposer rotation
- Byzantine fault tolerant with 2/3 honest validators
- Sub-second block times
- Finality after anchor confirmation

## API

The `moloch-api` crate provides:

- REST API for event submission and querying
- WebSocket subscriptions for real-time events
- JWT and API key authentication
- Rate limiting and audit logging

## License

MIT License - see [LICENSE](LICENSE)

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Contributing

See contributing guidelines before submitting PRs.

## Related Projects

- [Arcanum](../arcanum) - Cryptographic primitives library
- [Haagenti](../haagenti) - AI model compression framework
