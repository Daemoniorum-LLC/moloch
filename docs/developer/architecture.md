# Moloch Architecture

System design and component overview for the Moloch cryptographic audit chain.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         API Layer                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  REST API   │  │  WebSocket  │  │      gRPC (planned)     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                      Chain Layer                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Chain     │  │  Consensus  │  │       Mempool           │ │
│  │   State     │  │   (Aura)    │  │    (Lock-free)          │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                     Privacy Layer (HoloCrypt)                   │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌─────────────┐  │
│  │ Selective │  │    ZK     │  │ Threshold │  │ Post-Quantum│  │
│  │Encryption │  │  Proofs   │  │   Crypto  │  │   (ML-KEM)  │  │
│  └───────────┘  └───────────┘  └───────────┘  └─────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                     Storage Layer                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  RocksDB    │  │   MMR       │  │       Indexes           │ │
│  │  (Events)   │  │  (Proofs)   │  │  (Actor, Resource, Time)│ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                     Network Layer                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │    P2P      │  │    Sync     │  │      Federation         │ │
│  │  (libp2p)   │  │  Protocol   │  │    (Cross-chain)        │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                     Anchoring Layer                             │
│  ┌───────────────────────┐  ┌─────────────────────────────────┐│
│  │    Bitcoin Anchor     │  │      Ethereum Anchor            ││
│  │    (OP_RETURN)        │  │      (Calldata)                 ││
│  └───────────────────────┘  └─────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Core Data Structures

### AuditEvent

The fundamental unit of the audit chain:

```rust
struct AuditEvent {
    id: EventId,           // BLAKE3 hash of content
    timestamp_ms: u64,     // Unix milliseconds
    event_type: EventType, // Categorized action
    actor: ActorId,        // Who performed the action
    resource: ResourceId,  // What was affected
    outcome: Outcome,      // Success/Failure/Pending
    metadata: Value,       // JSON payload
    signature: Signature,  // Ed25519 signature
}
```

### Block

Batched, signed container of events:

```rust
struct Block {
    height: u64,
    parent_hash: Hash,
    events_root: Hash,    // Merkle root of events
    state_root: Hash,     // State commitment
    sealer_id: SealerId,  // Block producer
    signature: Signature, // Sealer's signature
    events: Vec<AuditEvent>,
}
```

### Merkle Mountain Range (MMR)

Append-only accumulator providing:
- O(1) append
- O(log n) inclusion proofs
- O(log n) consistency proofs
- Compact root representation

## Cryptographic Stack

### Primitives (via Arcanum)

| Function | Algorithm | Performance |
|----------|-----------|-------------|
| Hashing | BLAKE3 | 6M ops/sec |
| Signatures | Ed25519 | 12.8 µs keygen |
| Batch Verify | Ed25519 | 3-8x speedup |
| Post-Quantum | ML-KEM-768 | 51 µs keygen |

### HoloCrypt Features

**Selective Encryption**: Encrypt specific fields while preserving structure:
- Actor ID (encrypted)
- Event type (visible)
- Resource ID (configurable)
- Metadata (encrypted)

**Zero-Knowledge Proofs**:
- Existence proofs: 1.9 µs generation
- Type proofs: 2.0 µs generation
- Verification: 1.5 µs

**Threshold Encryption**:
- Shamir secret sharing
- k-of-n reconstruction
- Key resharing support

**Post-Quantum**:
- ML-KEM-768 (NIST Level 3)
- Hybrid mode available
- 4x slower than Ed25519 (acceptable trade-off)

## Consensus: Aura-style PoA

Simple, deterministic block production:

```
Round N:
1. Leader = validators[N % len(validators)]
2. Leader proposes block
3. Others validate & sign
4. 2/3+ signatures = finalized
5. Advance to round N+1
```

Properties:
- Deterministic proposer selection
- Byzantine fault tolerant (2/3 honest)
- Sub-second finality
- No wasted computation

## Storage Architecture

### RocksDB Column Families

| CF | Key | Value |
|----|-----|-------|
| events | EventId | AuditEvent (rkyv) |
| blocks | Height | Block (rkyv) |
| mmr | Position | Hash |
| state | Key | Value |

### Indexes

| Index | Purpose |
|-------|---------|
| actor_idx | Events by actor ID |
| resource_idx | Events by resource ID |
| time_idx | Events by timestamp range |
| type_idx | Events by event type |

### Zero-Copy Access

Using `rkyv` for storage:
- No deserialization overhead
- Direct memory access
- Archive format compatible with mmap

## Network Protocol

### Message Types

```rust
enum Message {
    // Handshake
    Hello { version, chain_id, head },

    // Gossip
    NewEvent(AuditEvent),
    NewBlock(Block),

    // Sync
    GetBlocks { start, count },
    Blocks(Vec<Block>),

    // Consensus
    Proposal(Block),
    Vote { block_hash, signature },
}
```

### Sync Modes

1. **Fast Sync**: Download blocks, verify MMR
2. **Snap Sync**: Download state snapshot
3. **Warp Sync**: Skip to recent checkpoint

## Cross-Chain Anchoring

### Bitcoin (OP_RETURN)

```
OP_RETURN <MOLOCH_PREFIX> <MMR_ROOT>
```
- 80 bytes available
- ~10 min confirmation
- High security guarantee

### Ethereum (Calldata)

```solidity
function anchor(bytes32 root) external;
```
- Gas-efficient storage
- ~15 sec confirmation
- Smart contract verifiable

## Performance Characteristics

| Operation | Throughput | Latency |
|-----------|------------|---------|
| Event creation | 160K/sec | 6.2 µs |
| Batch signature verify | 800K/sec | 1.25 µs |
| MMR append | 1.6M/sec | 644 ns |
| ZK proof generation | 500K/sec | 1.9 µs |
| Lock-free mempool (8 threads) | 194K/sec | - |

## Design Principles

1. **Immutability**: Events and blocks are append-only
2. **Verifiability**: Every claim is cryptographically provable
3. **Privacy-preserving**: Selective disclosure via ZK proofs
4. **Future-proof**: Post-quantum encryption available
5. **Interoperable**: Cross-chain anchoring for external verification
