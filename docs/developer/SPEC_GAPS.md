# Specification Gap Analysis

**Version:** 0.1.0
**Status:** DRAFT - Pending Review
**Date:** 2026-01-28
**Context:** Dead code audit revealed incomplete specifications

---

## Overview

During code audit, several implementations were found with `#[allow(dead_code)]` annotations. Per SDD methodology, this document analyzes whether these represent:

1. **Spec Gaps** - Functionality needed but not specified (update spec)
2. **Premature Abstractions** - Code without spec backing (remove code)

---

## Gap 1: Mempool Event Expiration

### Current State

**Code:** `moloch-chain/src/concurrent_mempool.rs:49-55`
```rust
#[allow(dead_code)]
struct EventMeta {
    added_at: DateTime<Utc>,
    priority: i64,
}
```

**Roadmap Reference:** Phase 2.3
> "Expiration (TTL for pending events), Size limits with eviction policy"

### Gap Analysis

The roadmap specifies TTL and eviction but doesn't define:
- What is the default TTL?
- What triggers eviction (time, size, or both)?
- What is the eviction order (FIFO, priority-based, age-based)?
- Are there different TTLs per event type or priority?
- What happens to evicted events (dropped silently, error returned, logged)?

### Proposed Specification

```
## 2.3.1 Mempool Expiration Policy

### Configuration
- `ttl_seconds: u64` - Maximum time an event can remain in mempool (default: 3600)
- `max_size: usize` - Maximum number of events (default: 100,000)
- `eviction_batch_size: usize` - Events to evict when limit reached (default: 1000)

### Eviction Triggers
1. **Time-based**: Events older than `ttl_seconds` are evicted on next `take()` or periodic cleanup
2. **Size-based**: When `len() >= max_size`, evict `eviction_batch_size` oldest events before accepting new

### Eviction Order
1. First by age (oldest first)
2. Then by priority (lowest priority first, within same age bucket)

### Behavior
- `add()` returns `Err(MempoolFull)` if eviction cannot free space
- Evicted events are logged at DEBUG level
- Metrics: `mempool_evictions_total` counter

### Test Criteria
- Events older than TTL are not returned by `take()`
- Adding event when full triggers eviction of oldest
- Priority affects eviction order within age bucket
```

### Decision Required

- [ ] Approve specification as written
- [ ] Modify specification (provide feedback)
- [ ] Remove feature (delete `EventMeta`, simplify to FIFO-only)

---

## Gap 2: Bitcoin SPV Verification

### Current State

**Code:** `moloch-anchor-bitcoin/src/tx.rs:277-303`
```rust
#[allow(dead_code)]
pub fn verify_merkle_proof(
    txid: &[u8; 32],
    merkle_root: &[u8; 32],
    proof: &[[u8; 32]],
    index: u32,
) -> bool
```

**Architecture Reference:**
> "Bitcoin (OP_RETURN) ... High security guarantee"

### Gap Analysis

Architecture mentions Bitcoin anchoring provides "high security guarantee" but doesn't specify:
- When is SPV verification performed?
- Who performs it (light client, full node, verifier)?
- What is verified (just merkle proof, or also block headers)?
- What is the trust model (SPV assumptions)?
- How many confirmations are required?

### Proposed Specification

```
## Bitcoin Anchor Verification

### Verification Levels

1. **Commitment Only** (Low Security)
   - Verify commitment hash matches expected
   - No Bitcoin verification
   - Use case: Trust the anchor provider

2. **SPV Verification** (Medium Security)
   - Verify transaction merkle proof against block header
   - Verify block header chain (N confirmations)
   - Use case: Light clients, cross-chain verification

3. **Full Verification** (High Security)
   - Full node validates entire block
   - Use case: Validators, archive nodes

### SPV Verification Flow

```
Input: AnchorProof { tx_id, block_hash, merkle_proof, commitment }

1. Fetch block header for `block_hash` (from Bitcoin node or header relay)
2. Verify `merkle_proof` proves `tx_id` inclusion in `block_header.merkle_root`
3. Verify block has >= `min_confirmations` (default: 6)
4. Parse OP_RETURN from transaction, verify `commitment` matches

Output: VerificationResult { verified: bool, confirmations: u32, block_height: u64 }
```

### Configuration
- `min_confirmations: u32` - Required confirmations (default: 6)
- `header_source: HeaderSource` - Where to fetch headers (BitcoinRpc, Relay, Embedded)

### Error Cases
- `InvalidMerkleProof` - Proof doesn't verify against merkle root
- `InsufficientConfirmations` - Block has fewer than required confirmations
- `CommitmentMismatch` - OP_RETURN data doesn't match expected commitment
- `BlockNotFound` - Cannot fetch block header

### Test Criteria
- Valid proof with 6+ confirmations returns success
- Invalid proof returns `InvalidMerkleProof`
- Valid proof with 3 confirmations returns `InsufficientConfirmations`
```

### Decision Required

- [ ] Approve specification as written
- [ ] Modify specification (provide feedback)
- [ ] Defer feature (remove code, add to future roadmap)

---

## Gap 3: Sync Protocol State Machine

### Current State

**Code:** `moloch-net/src/sync.rs:215-236`
```rust
#[allow(dead_code)]
struct PendingRequest {
    id: MessageId,
    peer: PeerId,
    kind: RequestKind,
    sent_at: Instant,
    retries: u32,
}

#[allow(dead_code)]
enum RequestKind {
    Headers { start: u64, count: u32 },
    Blocks { start: u64, count: u32 },
    Snapshot { height: Option<u64> },
}
```

**Roadmap Reference:** Phase 4.4
> "Fast sync (download blocks, verify MMR), Snap sync (download state snapshot), Catch-up sync (fill gaps), Warp sync (skip to recent checkpoint)"

### Gap Analysis

Roadmap lists sync modes but doesn't specify:
- State machine transitions between modes
- Request/response protocol
- Timeout and retry behavior
- Peer selection strategy
- Progress tracking
- Error recovery

### Proposed Specification

```
## 4.4 Sync Protocol

### Sync Modes

| Mode | Trigger | Data Downloaded | Verification |
|------|---------|-----------------|--------------|
| Fast | height_diff > 1000 | Block headers + bodies | MMR proofs |
| Snap | height_diff > 10000 | State snapshot | Snapshot hash |
| Catch-up | height_diff < 100 | Missing blocks | Full validation |
| Warp | Initial sync | Recent checkpoint | Checkpoint sig |

### State Machine

```
                    ┌─────────┐
                    │  IDLE   │
                    └────┬────┘
                         │ peer reports higher height
                         ▼
                    ┌─────────┐
         ┌─────────│ ASSESS  │─────────┐
         │         └─────────┘         │
    diff < 100              diff > 1000
         │                             │
         ▼                             ▼
    ┌─────────┐                   ┌─────────┐
    │ CATCHUP │                   │  FAST   │
    └────┬────┘                   └────┬────┘
         │                             │
         │ synced                      │ headers complete
         │                             ▼
         │                        ┌─────────┐
         │                        │ BODIES  │
         │                        └────┬────┘
         │                             │ complete
         └──────────┬──────────────────┘
                    ▼
               ┌─────────┐
               │  IDLE   │
               └─────────┘
```

### Request Protocol

1. **Request Lifecycle**
   - Generate unique `MessageId`
   - Record in `pending_requests` with timestamp
   - Send to selected peer
   - Await response or timeout

2. **Timeout Handling**
   - `request_timeout: Duration` (default: 30s)
   - On timeout: increment `retries`, select new peer, resend
   - Max retries: 3, then mark peer as failed

3. **Response Handling**
   - Match response `MessageId` to pending request
   - Validate response (correct range, valid data)
   - Remove from `pending_requests`
   - Process data (apply blocks, update state)

### Peer Selection

1. Prefer peers with:
   - Higher reported height
   - Lower latency
   - Higher success rate
2. Round-robin among qualified peers
3. Blacklist peers with repeated failures (30min cooldown)

### Progress Tracking

```rust
struct SyncProgress {
    mode: SyncMode,
    target_height: u64,
    current_height: u64,
    pending_requests: usize,
    bytes_downloaded: u64,
    started_at: Instant,
}
```

### Test Criteria
- Request timeout triggers retry with different peer
- 3 failed retries blacklists peer
- Mode transitions correctly based on height difference
- Progress accurately reflects sync state
```

### Decision Required

- [ ] Approve specification as written
- [ ] Modify specification (provide feedback)
- [ ] Simplify (implement only Catch-up mode for MVP)

---

## Gap 4: Snapshot Builder

### Current State

**Code:** `moloch-storage/src/snapshot.rs:129-165`
```rust
#[allow(dead_code)]
pub struct SnapshotBuilder<'a, S> {
    storage: &'a S,
    height: Option<u64>,
    include_indexes: bool,
    chain_id: String,
}
```

Builder has setters but no `build()` method.

**Roadmap Reference:** Phase 2.1
> "State snapshots for fast sync"

### Gap Analysis

Roadmap mentions snapshots but doesn't specify:
- Snapshot format
- What data is included
- Compression strategy
- Verification mechanism
- Streaming vs full-load

### Proposed Specification

```
## Snapshot Format

### Header (64 bytes)
| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic: "MSNP" |
| 4 | 4 | Version: 1 |
| 8 | 8 | Height |
| 16 | 32 | Chain ID hash |
| 48 | 8 | Block count |
| 56 | 8 | Total size |

### Body (streaming)
```
[Header 64B]
[Blocks Section]
  - Length (u64)
  - Blocks (rkyv serialized, zstd compressed)
[MMR Section]
  - Length (u64)
  - MMR nodes (rkyv serialized, zstd compressed)
[Index Section] (optional)
  - Length (u64)
  - Indexes (rkyv serialized, zstd compressed)
[Checksum]
  - BLAKE3 hash of all preceding bytes
```

### Builder API

```rust
impl<S: ChainStore> SnapshotBuilder<'_, S> {
    /// Build the snapshot, writing to the provided writer.
    pub fn build<W: Write>(&self, writer: W) -> Result<SnapshotHeader> {
        // 1. Write header placeholder
        // 2. Stream blocks from genesis to height
        // 3. Stream MMR nodes
        // 4. Optionally stream indexes
        // 5. Write checksum
        // 6. Seek back and write final header
    }
}
```

### Verification

1. Verify header magic and version
2. Verify checksum matches content
3. Verify final block hash matches header
4. Verify MMR root matches final block's MMR root

### Test Criteria
- Roundtrip: create snapshot, restore, verify identical state
- Corruption: modified byte detected by checksum
- Streaming: memory usage stays bounded during large snapshot creation
```

### Decision Required

- [ ] Approve specification as written
- [ ] Modify specification (provide feedback)
- [ ] Defer feature (remove builder, implement later)

---

## Premature Abstractions (Recommended Removal)

The following code has no spec backing and should be removed:

### 1. MockTransaction Fields
**Location:** `moloch-anchor/src/mock.rs:121`
- Fields `tx_id`, `submitted_at` stored but never retrieved
- **Action:** Remove unused fields, keep only what tests actually use

### 2. ProviderRegistry
**Location:** `moloch-anchor/src/registry.rs:69`
- Multi-provider abstraction not in any spec
- **Action:** Remove entire struct, use direct provider injection

### 3. MmapStorage
**Location:** `moloch-storage/src/mmap.rs:117`
- Alternative storage backend not in architecture
- **Action:** Remove (RocksDB is specified backend), or spec it first

### 4. MerkleTreeBuffer
**Location:** `moloch-core/src/merkle.rs:250`
- Performance optimization without benchmark requirement
- **Action:** Remove until profiling shows it's needed

### 5. QueuedRequest.queued_at (Scheduler)
**Location:** `moloch-anchor/src/scheduler.rs:168`
- Deadline handling not specified for anchor scheduler
- **Action:** Remove field, or spec deadline behavior first

### 6. PendingRequest (Bridge)
**Location:** `moloch-federation/src/bridge.rs:100`
- Federation request tracking not detailed in spec
- **Action:** Remove until federation protocol is fully specified

---

## Summary

| Item | Classification | Recommended Action |
|------|----------------|-------------------|
| EventMeta (mempool) | Spec Gap | Approve spec, then implement |
| verify_merkle_proof | Spec Gap | Approve spec, then integrate |
| PendingRequest (sync) | Spec Gap | Approve spec, then implement |
| SnapshotBuilder | Spec Gap | Approve spec, then implement |
| MockTransaction fields | Premature | Remove |
| ProviderRegistry | Premature | Remove |
| MmapStorage | Premature | Remove |
| MerkleTreeBuffer | Premature | Remove |
| QueuedRequest.queued_at | Premature | Remove |
| PendingRequest (bridge) | Premature | Remove |

---

## Next Steps

1. Review and approve/modify Gap 1-4 specifications
2. Remove premature abstractions
3. Implement approved specs following Agent-TDD (tests first)
4. Update architecture.md with approved specs
