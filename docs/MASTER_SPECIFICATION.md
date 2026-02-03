# Moloch Cryptographic Audit Chain - Master Specification

**Version**: 1.0.0
**Date**: 2026-01-28
**Status**: Reverse-engineered from implementation

---

## Executive Summary

Moloch is a **cryptographic audit chain** designed for immutable, verifiable, and tamper-evident audit logging. It provides enterprise-grade infrastructure for recording audit events with cryptographic proofs, supporting features including:

- **Append-only audit logs** with cryptographic integrity guarantees
- **Proof-of-Authority (PoA) consensus** for predictable finality
- **Light client verification** for resource-constrained environments
- **Multi-chain federation** for cross-organizational audit trails
- **Privacy-preserving features** via HoloCrypt integration
- **External blockchain anchoring** for additional finality guarantees
- **REST and WebSocket APIs** for application integration

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Core Primitives (moloch-core)](#2-core-primitives-moloch-core)
3. [Merkle Mountain Range (moloch-mmr)](#3-merkle-mountain-range-moloch-mmr)
4. [Storage Layer (moloch-storage)](#4-storage-layer-moloch-storage)
5. [Chain State (moloch-chain)](#5-chain-state-moloch-chain)
6. [Consensus (moloch-consensus)](#6-consensus-moloch-consensus)
7. [Networking (moloch-net)](#7-networking-moloch-net)
8. [Event Indexing (moloch-index)](#8-event-indexing-moloch-index)
9. [External Anchoring (moloch-anchor)](#9-external-anchoring-moloch-anchor)
10. [Privacy Layer (moloch-holocrypt)](#10-privacy-layer-moloch-holocrypt)
11. [Light Client (moloch-light)](#11-light-client-moloch-light)
12. [Federation (moloch-federation)](#12-federation-moloch-federation)
13. [Verification Framework (moloch-verify)](#13-verification-framework-moloch-verify)
14. [API Layer (moloch-api)](#14-api-layer-moloch-api)
15. [System Invariants](#15-system-invariants)
16. [Cryptographic Specifications](#16-cryptographic-specifications)
17. [Error Taxonomy](#17-error-taxonomy)

---

## 1. Architecture Overview

### 1.1 Crate Dependency Graph

```
                              ┌─────────────────┐
                              │   moloch-api    │
                              │ (REST/WebSocket)│
                              └────────┬────────┘
                                       │
           ┌───────────────────────────┼───────────────────────────┐
           │                           │                           │
           ▼                           ▼                           ▼
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  moloch-chain   │         │ moloch-consensus│         │  moloch-index   │
│ (chain state)   │         │    (PoA)        │         │ (secondary idx) │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
         ┌─────────────────┐               ┌─────────────────┐
         │ moloch-storage  │               │   moloch-mmr    │
         │ (persistence)   │               │(merkle mountain)│
         └────────┬────────┘               └────────┬────────┘
                  │                                 │
                  └─────────────────┬───────────────┘
                                    │
                                    ▼
                         ┌─────────────────┐
                         │   moloch-core   │
                         │  (primitives)   │
                         └─────────────────┘

    Additional Crates:
    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │   moloch-net    │  │ moloch-anchor   │  │moloch-holocrypt │
    │  (networking)   │  │  (anchoring)    │  │   (privacy)     │
    └─────────────────┘  └─────────────────┘  └─────────────────┘

    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │  moloch-light   │  │moloch-federation│  │  moloch-verify  │
    │ (light client)  │  │  (cross-chain)  │  │ (verification)  │
    └─────────────────┘  └─────────────────┘  └─────────────────┘
```

### 1.2 Data Flow

```
Events → Mempool → Block Production → Chain Storage → MMR → Proofs
                       ↑
                   Consensus
                   (Validators)
```

### 1.3 Key Design Principles

1. **Append-Only**: Events and blocks are immutable once committed
2. **Cryptographic Integrity**: All data is content-addressed and hash-linked
3. **Verifiable**: Light clients can verify any event with compact proofs
4. **Deterministic**: Same inputs always produce same outputs
5. **Fail-Safe**: Errors are explicit, no silent failures

---

## 2. Core Primitives (moloch-core)

### 2.1 Hash Types

| Type | Size | Algorithm | Purpose |
|------|------|-----------|---------|
| `Hash` | 32 bytes | BLAKE3 | General-purpose hash |
| `BlockHash` | 32 bytes | BLAKE3 | Block identification |
| `EventId` | 32 bytes | BLAKE3 | Event identification |

**Hash Functions**:
```rust
fn hash(data: &[u8]) -> Hash           // BLAKE3 hash
fn hash_pair(left: Hash, right: Hash) -> Hash  // Merkle node
```

### 2.2 Cryptographic Keys

| Type | Algorithm | Size | Purpose |
|------|-----------|------|---------|
| `SecretKey` | Ed25519 | 32 bytes | Private signing key |
| `PublicKey` | Ed25519 | 32 bytes | Public verification key |
| `Sig` | Ed25519 | 64 bytes | Digital signature |

**Key Operations**:
- `SecretKey::generate()` - Generate new keypair
- `SecretKey::sign(message)` - Create signature
- `PublicKey::verify(message, signature)` - Verify signature

### 2.3 Events

**AuditEvent Structure**:
```rust
pub struct AuditEvent {
    pub id: EventId,           // Content-addressed identifier
    pub event_type: EventType, // Type category
    pub actor: ActorId,        // Who performed action
    pub resource: ResourceId,  // What was affected
    pub action: String,        // Action description
    pub timestamp: i64,        // Unix timestamp (ms)
    pub metadata: EventMetadata,
    pub signature: Sig,        // Actor signature
}
```

**Event Types** (33 categories):
- Repository: `RepoCreated`, `RepoDeleted`, `RepoTransferred`
- Git: `Push`, `BranchCreated`, `TagCreated`
- Access: `AccessGranted`, `AccessRevoked`, `Login`, `Logout`
- Agent: `AgentAction`, `AgentAuthorized`
- Privacy: `DataExportRequested`, `ConsentGiven`
- Custom: `Custom(String)`

### 2.4 Blocks

**Block Structure**:
```rust
pub struct Block {
    pub header: BlockHeader,
    pub events: Vec<AuditEvent>,
    pub signatures: Vec<(PublicKey, Sig)>,
}

pub struct BlockHeader {
    pub height: u64,
    pub parent_hash: BlockHash,
    pub events_root: Hash,      // Merkle root of events
    pub mmr_root: Hash,         // MMR root after this block
    pub timestamp: i64,
    pub proposer: PublicKey,
}
```

### 2.5 Proofs

| Proof Type | Purpose | Size |
|------------|---------|------|
| `InclusionProof` | Event in block | O(log n) |
| `MmrProof` | Block in chain | O(log n) |
| `ConsistencyProof` | Chain prefix property | O(log n) |

---

## 3. Merkle Mountain Range (moloch-mmr)

### 3.1 Purpose

The MMR provides O(log n) inclusion proofs for all events in the chain. It's an append-only authenticated data structure where:
- Leaves are block hashes
- Each append may merge perfect binary trees
- Root is computed by "bagging" all peaks

### 3.2 Position Numbering

Positions follow post-order traversal:
```
Height 2:        6              (peak)
                 / \
Height 1:      2   5            (internal)
               / \ / \
Height 0:    0  1 3  4          (leaves)
```

### 3.3 Key Operations

| Operation | Complexity | Description |
|-----------|------------|-------------|
| `append(leaf)` | O(1) amortized | Add new leaf |
| `root()` | O(log n) | Compute MMR root |
| `proof(pos)` | O(log n) | Generate inclusion proof |
| `verify(proof)` | O(log n) | Verify inclusion proof |

### 3.4 Storage Trait

```rust
pub trait MmrStore: Clone {
    fn get(&self, pos: u64) -> Result<Option<Hash>>;
    fn insert(&mut self, pos: u64, hash: Hash) -> Result<()>;
    fn size(&self) -> u64;
    fn set_size(&mut self, size: u64);
}
```

---

## 4. Storage Layer (moloch-storage)

### 4.1 Storage Backends

| Backend | Use Case | Persistence | Performance |
|---------|----------|-------------|-------------|
| `MemoryStorage` | Testing | None | Fastest |
| `RocksStorage` | Production | Disk | Fast |
| `MmapStorage` | Large datasets | Memory-mapped | Variable |

### 4.2 ChainStore Trait

```rust
pub trait ChainStore: Send + Sync {
    // Block operations
    fn put_block(&self, block: &Block) -> Result<()>;
    fn get_block(&self, height: u64) -> Result<Option<Block>>;
    fn latest_height(&self) -> Result<Option<u64>>;

    // Event operations
    fn get_event(&self, id: &EventId) -> Result<Option<AuditEvent>>;

    // MMR operations
    fn get_mmr_node(&self, pos: u64) -> Result<Option<Hash>>;
    fn put_mmr_node(&self, pos: u64, hash: Hash) -> Result<()>;
    fn mmr_size(&self) -> Result<u64>;
    fn mmr_leaf_count(&self) -> Result<u64>;
}
```

### 4.3 Column Families (RocksDB)

| Column | Key | Value | Purpose |
|--------|-----|-------|---------|
| `blocks` | height (BE u64) | Block (bincode) | Block storage |
| `events` | EventId | AuditEvent | Event lookup |
| `mmr` | position (BE u64) | Hash | MMR nodes |
| `meta` | key string | value bytes | Metadata |

---

## 5. Chain State (moloch-chain)

### 5.1 ChainState

Tracks the current state of the chain:
```rust
pub struct ChainState {
    pub height: u64,
    pub tip_hash: BlockHash,
    pub mmr_root: Hash,
    pub total_events: u64,
}
```

### 5.2 Mempool

Manages pending events before block inclusion:

| Feature | Description |
|---------|-------------|
| Capacity | Configurable max events |
| TTL | Events expire after timeout |
| Ordering | FIFO with priority support |
| Deduplication | By EventId |

**Concurrent Mempool**: Uses sharded locking for high throughput.

### 5.3 Block Builder

Constructs blocks from mempool events:
```rust
pub struct BlockBuilder {
    fn build(
        parent: &Block,
        events: Vec<AuditEvent>,
        proposer: &SecretKey,
    ) -> Block
}
```

---

## 6. Consensus (moloch-consensus)

### 6.1 Proof-of-Authority (PoA)

Moloch uses a round-robin PoA consensus:

```
Validators: [V₁, V₂, V₃, ..., Vₙ]
Proposer for height h: V[h mod n]
```

### 6.2 Validator Set

```rust
pub struct ValidatorSet {
    validators: Vec<PublicKey>,
    threshold: usize,  // 2f+1 where f = (n-1)/3
}
```

### 6.3 Finality

- **Threshold**: 2/3 + 1 validator signatures required
- **Instant Finality**: Block is final once threshold reached
- **No Forks**: Single canonical chain

### 6.4 Block Production Flow

```
1. Wait for slot (time-based rounds)
2. Check if node is proposer for this height
3. Collect events from mempool
4. Build block (compute merkle root, update MMR)
5. Sign block
6. Broadcast to validators
7. Collect signatures
8. Commit when threshold reached
```

---

## 7. Networking (moloch-net)

### 7.1 Protocol Stack

```
┌─────────────────────────────┐
│    Application Messages     │
│  (Gossip, Sync, Consensus)  │
├─────────────────────────────┤
│     Message Framing         │
│   (Length-prefixed bincode) │
├─────────────────────────────┤
│        TLS 1.3              │
│      (rustls)               │
├─────────────────────────────┤
│         TCP                 │
└─────────────────────────────┘
```

### 7.2 Message Types

**Handshake**:
- `Hello` / `HelloAck` - Connection setup with signature proof
- `Status` - Periodic state updates
- `Goodbye` - Graceful disconnect

**Gossip**:
- `NewEvent` - Broadcast new event
- `NewBlock` - Broadcast new block
- `Announce` - Pull-based announcements

**Sync**:
- `GetBlocks` / `Blocks` - Block range requests
- `GetHeaders` / `Headers` - Header-only sync
- `GetSnapshot` / `Snapshot` - State snapshot

**Consensus**:
- `Proposal` - Block proposal
- `Vote` - Block vote
- `GetVotes` / `Votes` - Vote collection

### 7.3 Peer Discovery

| Method | Description |
|--------|-------------|
| Static | Configured peer list |
| DNS | DNS-based discovery |
| PeerExchange | Learn from connected peers |

### 7.4 Peer Scoring

```rust
pub struct PeerScore {
    pub value: u32,           // 0-1000
    pub latency_score: u32,   // 30% weight
    pub reliability_score: u32, // 40% weight
    pub behavior_score: u32,  // 30% weight
}
```

- **Ban threshold**: score < 50
- **Good peer**: score >= 700

---

## 8. Event Indexing (moloch-index)

### 8.1 Index Types

| Index | Key | Lookup |
|-------|-----|--------|
| Actor | `Hash(ActorId)` | Events by actor |
| Resource | `(ResourceKind, ResourceId)` | Events by resource |
| EventType | `EventTypeKey` | Events by type |
| Timestamp | `i64` (ms) | Time-range queries |

### 8.2 Query DSL

```rust
Query::new()
    .actor(&actor_id)
    .resource_kind(ResourceKind::Repository)
    .time_range(start..end)
    .limit(100)
    .offset(0)
    .execute(&engine)?
```

### 8.3 Composite Queries

```rust
CompositeQuery::and(vec![
    Query::new().actor(&actor),
    Query::new().event_type(EventTypeKey::Push),
])
```

Supported: `AND`, `OR` (NOT requires full scan - disabled)

---

## 9. External Anchoring (moloch-anchor)

### 9.1 Purpose

Anchor chain state to external blockchains for additional finality guarantees.

### 9.2 Provider Abstraction

```rust
#[async_trait]
pub trait AnchorProvider: Send + Sync {
    fn id(&self) -> &str;
    async fn submit(&self, commitment: &Commitment) -> Result<AnchorTx>;
    async fn verify(&self, proof: &AnchorProof) -> Result<bool>;
    async fn confirmations(&self, tx_id: &TxId) -> Result<u64>;
}
```

### 9.3 Bitcoin Anchoring

**OP_RETURN Format**:
```
[MLCH (4)] [commitment_hash (32)] [chain_id_hash (8)] = 44 bytes
```

**Confirmation Model**:
- Probabilistic finality (PoW)
- Default: 6 confirmations (~60 minutes)
- SPV proofs for light verification

### 9.4 Commitment Structure

```rust
pub struct Commitment {
    pub chain_id: String,
    pub mmr_root: Hash,
    pub height: u64,
    pub event_count: u64,
    pub timestamp: i64,
}
```

---

## 10. Privacy Layer (moloch-holocrypt)

### 10.1 Features

| Feature | Description |
|---------|-------------|
| Encryption | AES-256-GCM event encryption |
| ZK Proofs | Zero-knowledge proofs for private verification |
| Threshold | Shamir secret sharing for key distribution |
| PQC | Post-quantum cryptography support |

### 10.2 Encrypted Events

```rust
pub struct EncryptedEvent {
    pub event_id: EventId,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_id: String,
}
```

### 10.3 Access Control

```rust
pub struct ThresholdPolicy {
    pub threshold: usize,    // k-of-n
    pub parties: Vec<PublicKey>,
}
```

---

## 11. Light Client (moloch-light)

### 11.1 Purpose

Verify chain state with minimal storage (~200 bytes/header vs ~100KB/block).

### 11.2 Trust Model

- **Bootstrap**: Checkpoint from trusted source
- **Sync**: Header-only synchronization
- **Verify**: Compact proofs for event inclusion

### 11.3 Proof Types

| Proof | Purpose | Size |
|-------|---------|------|
| `CompactProof` | Event in block | ~320 + 32×depth bytes |
| `MmrCompactProof` | Block in chain | ~16 + 32×(siblings+peaks) |
| `ConsistencyCompactProof` | Chain prefix | ~16 + 32×depth |

### 11.4 TrustedHeader

```rust
pub struct TrustedHeader {
    pub header: BlockHeader,
    pub signatures: Vec<(PublicKey, Sig)>,  // 2/3+1 validators
    pub mmr_root: Hash,
}
```

### 11.5 Checkpoint Bootstrap

```rust
pub struct Checkpoint {
    pub height: u64,
    pub hash: BlockHash,
    pub mmr_root: Hash,
    pub validators_hash: Hash,
    pub total_events: u64,
}
```

---

## 12. Federation (moloch-federation)

### 12.1 Purpose

Enable cross-chain audit trail verification between independent Moloch chains.

### 12.2 Trust Levels

```rust
pub enum TrustLevel {
    Untrusted = 0,  // Full verification
    Basic = 1,      // Standard verification
    Elevated = 2,   // Reduced verification
    Full = 3,       // Minimal verification
}
```

### 12.3 Cross-Chain Reference

```rust
pub struct CrossChainReference {
    pub source_chain: String,
    pub event_id: EventId,
    pub block_height: u64,
    pub block_hash: BlockHash,
    pub proof: Option<ProofBundle>,
}
```

### 12.4 Bridge Protocol

```
Chain A                    Bridge                    Chain B
   │                         │                         │
   │   RequestProof(event)   │                         │
   ├────────────────────────►│                         │
   │                         │    Query Event          │
   │                         ├────────────────────────►│
   │                         │    Return Proof         │
   │                         │◄────────────────────────┤
   │   ProofResponse(proof)  │                         │
   │◄────────────────────────┤                         │
```

---

## 13. Verification Framework (moloch-verify)

### 13.1 Invariant Checking

```rust
pub trait Invariant<S> {
    fn name(&self) -> &str;
    fn check(&self, state: &S) -> Result<(), InvariantViolation>;
    fn check_transition(&self, old: &S, new: &S) -> Result<(), InvariantViolation>;
}
```

### 13.2 Built-in Invariants

| Invariant | Property |
|-----------|----------|
| `MonotonicHeight` | Height always increases |
| `ConsecutiveHeight` | No height gaps |
| `MonotonicEvents` | Event count non-decreasing |
| `MmrConsistency` | MMR root changes with events |

### 13.3 Runtime Monitoring

```rust
pub struct RuntimeMonitor<S> {
    checks: Vec<Box<dyn RuntimeCheck<S>>>,
    history: VecDeque<CheckRecord>,
}
```

### 13.4 Formal Specifications

Pre/post-condition style specifications:
```rust
Specification::new("block_production")
    .requires(Condition::new("valid_proposer", "..."))
    .ensures(Condition::new("height_incremented", "..."))
    .maintains(Condition::new("monotonic_time", "..."))
```

---

## 14. API Layer (moloch-api)

### 14.1 REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/events` | POST | Submit event |
| `/v1/events/{id}` | GET | Get event by ID |
| `/v1/events` | GET | Query events |
| `/v1/blocks/latest` | GET | Get latest block |
| `/v1/blocks/{height}` | GET | Get block by height |
| `/v1/proofs/inclusion` | GET | Get inclusion proof |
| `/v1/proofs/consistency` | GET | Get consistency proof |
| `/v1/status` | GET | Get node status |

### 14.2 WebSocket API

**Connection**: `ws://host/ws`

**Messages**:
- `Subscribe(filter)` - Start subscription
- `Event(info)` - Event notification
- `Block(info)` - Block notification
- `Ping` / `Pong` - Keep-alive

### 14.3 Authentication

| Method | Header | Format |
|--------|--------|--------|
| API Key | `Authorization` | `ApiKey {secret}` |
| JWT | `Authorization` | `Bearer {token}` |

### 14.4 Permissions

```rust
pub enum Permission {
    Read,   // Read-only access
    Write,  // Can submit events
    Admin,  // Full access
}
```

---

## 15. System Invariants

### 15.1 Chain Invariants

1. **Append-Only**: Blocks are never modified or removed
2. **Hash Linkage**: Each block references parent by hash
3. **Height Monotonicity**: Block heights strictly increase
4. **Event Uniqueness**: Event IDs are globally unique
5. **Signature Validity**: All signatures are cryptographically valid

### 15.2 MMR Invariants

1. **Leaf Ordering**: Leaves are added in block order
2. **Tree Completeness**: Only complete binary trees (peaks) exist
3. **Root Determinism**: Same leaves produce same root
4. **Proof Soundness**: Valid proofs always verify

### 15.3 Consensus Invariants

1. **Single Leader**: Only one proposer per height
2. **Threshold Finality**: 2/3+1 signatures required
3. **No Forks**: Single canonical chain (given honest majority)
4. **Liveness**: Progress guaranteed with f < n/3 Byzantine

### 15.4 Storage Invariants

1. **Durability**: Committed data survives restart
2. **Consistency**: Reads reflect all prior writes
3. **Atomicity**: Block commits are all-or-nothing

---

## 16. Cryptographic Specifications

### 16.1 Hash Function

| Property | Value |
|----------|-------|
| Algorithm | BLAKE3 |
| Output | 256 bits (32 bytes) |
| Security | 128-bit collision resistance |

### 16.2 Digital Signatures

| Property | Value |
|----------|-------|
| Algorithm | Ed25519 |
| Public Key | 32 bytes |
| Secret Key | 32 bytes |
| Signature | 64 bytes |
| Security | ~128-bit |

### 16.3 Symmetric Encryption (HoloCrypt)

| Property | Value |
|----------|-------|
| Algorithm | AES-256-GCM |
| Key Size | 256 bits |
| Nonce | 96 bits |
| Tag | 128 bits |

### 16.4 Key Derivation

| Property | Value |
|----------|-------|
| Algorithm | HKDF-SHA256 |
| Salt | Application-specific |
| Info | Context string |

---

## 17. Error Taxonomy

### 17.1 Core Errors

```rust
pub enum Error {
    NotFound(String),
    InvalidInput(String),
    InvalidSignature(String),
    InvalidProof(String),
    Storage(String),
    Internal(String),
}
```

### 17.2 Domain-Specific Errors

| Crate | Key Errors |
|-------|------------|
| `moloch-chain` | `InvalidBlock`, `OrphanBlock`, `MempoolFull` |
| `moloch-consensus` | `NotProposer`, `InsufficientVotes` |
| `moloch-net` | `ConnectionFailed`, `ProtocolMismatch` |
| `moloch-anchor` | `ProviderUnavailable`, `InsufficientConfirmations` |
| `moloch-federation` | `ChainNotFound`, `ProofVerificationFailed` |

### 17.3 Error Recovery

| Error Class | Strategy |
|-------------|----------|
| Transient | Retry with backoff |
| Permanent | Return to caller |
| Corruption | Fail-safe, alert operator |

---

## Appendix A: Workspace Structure

```
moloch/
├── moloch-core/          # Core primitives
├── moloch-mmr/           # Merkle Mountain Range
├── moloch-storage/       # Persistence layer
├── moloch-chain/         # Chain state management
├── moloch-consensus/     # PoA consensus
├── moloch-net/           # P2P networking
├── moloch-index/         # Secondary indexes
├── moloch-anchor/        # External anchoring abstraction
├── moloch-anchor-bitcoin/# Bitcoin anchoring
├── moloch-holocrypt/     # Privacy features
├── moloch-light/         # Light client
├── moloch-federation/    # Cross-chain federation
├── moloch-verify/        # Verification framework
├── moloch-api/           # REST/WebSocket API
└── docs/                 # Documentation
```

## Appendix B: Configuration Reference

### B.1 Network Configuration

```rust
NetworkConfig {
    listen_addr: "0.0.0.0:9000",
    chain_id: "moloch-mainnet",
    max_connections: 100,
    connection_timeout: 10s,
    handshake_timeout: 5s,
    keepalive_interval: 30s,
    idle_timeout: 120s,
}
```

### B.2 Consensus Configuration

```rust
ConsensusConfig {
    block_time: 1s,
    max_events_per_block: 1000,
    finality_threshold: 2/3 + 1,
}
```

### B.3 Storage Configuration

```rust
StorageConfig {
    path: "/var/lib/moloch",
    cache_size: 128MB,
    write_buffer_size: 64MB,
}
```

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **Audit Event** | Immutable record of an auditable action |
| **Block** | Collection of events with cryptographic proof |
| **Chain** | Sequence of blocks forming audit history |
| **Commitment** | Hash of chain state for anchoring |
| **Finality** | Guarantee that block cannot be reverted |
| **Light Client** | Node verifying proofs without full data |
| **MMR** | Merkle Mountain Range - append-only tree |
| **PoA** | Proof of Authority consensus mechanism |
| **Proposer** | Validator creating the next block |
| **Threshold** | Minimum signatures for finality |
| **Validator** | Node participating in consensus |

---

**Document End**

*This specification was reverse-engineered from the Moloch codebase. It represents the current implementation as of 2026-01-28.*
