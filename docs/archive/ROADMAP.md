# Moloch Production Roadmap

**Current State:** ~3,200 lines | Core data structures only | ~10% complete
**Target State:** Production-ready enterprise audit chain with HoloCrypt integration

## Principles

1. **TDD First** - Every feature starts with failing tests
2. **Quick Wins** - Interleave small victories with complex work
3. **Incremental Value** - Each phase delivers usable functionality
4. **No Networking Until Phase 4** - Prove everything works locally first

---

## Phase 1: Foundation Hardening (Quick Wins)
**Goal:** Bulletproof the existing core before adding complexity

### 1.1 Property-Based Testing [QUICK WIN]
```
moloch-core/src/proptest.rs (~200 lines)
```
- [ ] Proptest for `Hash` roundtrip (hex, bytes)
- [ ] Proptest for `Sig` serialization (bincode, JSON)
- [ ] Proptest for `AuditEvent` builder patterns
- [ ] Proptest for `Block` with random event counts (1-1000)
- [ ] Proptest for MMR append/proof (1-10000 leaves)

**TDD Pattern:**
```rust
proptest! {
    #[test]
    fn prop_event_roundtrip(event in arb_audit_event()) {
        let bytes = bincode::serialize(&event)?;
        let restored: AuditEvent = bincode::deserialize(&bytes)?;
        prop_assert_eq!(event.id(), restored.id());
    }
}
```

### 1.2 Error Enrichment [QUICK WIN]
```
moloch-core/src/error.rs (~150 lines)
```
- [ ] Add `thiserror` context to all variants
- [ ] Add `#[from]` for automatic conversion
- [ ] Add error codes for API responses
- [ ] Test error display formatting

### 1.3 Batch Operations [MODERATE]
```
moloch-storage/src/batch.rs (~300 lines)
```
- [ ] `WriteBatch` for atomic multi-key writes
- [ ] `ReadBatch` for efficient bulk reads
- [ ] Transaction support with rollback
- [ ] Benchmark: 10K events/second target

**TDD Pattern:**
```rust
#[test]
fn test_batch_atomic_rollback() {
    let store = RocksStore::temp();
    let batch = store.batch();
    batch.put_event(&event1);
    batch.put_event(&event2);
    // Don't commit - should rollback
    drop(batch);
    assert!(store.get_event(event1.id()).is_none());
}
```

### 1.4 Iterator API [QUICK WIN]
```
moloch-storage/src/iter.rs (~200 lines)
```
- [ ] `EventIterator` - scan events by time range
- [ ] `BlockIterator` - scan blocks by height
- [ ] Reverse iteration support
- [ ] Prefix scanning for resource filtering

---

## Phase 2: Chain Operations
**Goal:** Complete chain management without networking

### 2.1 Chain State Machine [MODERATE]
```
moloch-chain/src/lib.rs
moloch-chain/src/state.rs (~400 lines)
```
- [ ] `ChainState` struct (head, height, validator set)
- [ ] `apply_block()` - validate and append
- [ ] `revert_block()` - for reorgs (PoA shouldn't need this often)
- [ ] State snapshots for fast sync

**TDD Pattern:**
```rust
#[test]
fn test_chain_state_progression() {
    let mut chain = ChainState::genesis(validator_set);
    assert_eq!(chain.height(), 0);

    let block1 = create_valid_block(&chain, &events);
    chain.apply_block(block1)?;
    assert_eq!(chain.height(), 1);
}
```

### 2.2 Validator Registry [MODERATE]
```
moloch-chain/src/validators.rs (~350 lines)
```
- [ ] `ValidatorSet` - ordered list of authorities
- [ ] Validator rotation (add/remove with supermajority)
- [ ] Round-robin block producer selection
- [ ] Slash conditions (double-sign detection)

### 2.3 Mempool [MODERATE]
```
moloch-chain/src/mempool.rs (~400 lines)
```
- [ ] Priority queue by fee/timestamp
- [ ] Duplicate detection (by event ID)
- [ ] Expiration (TTL for pending events)
- [ ] Size limits with eviction policy

### 2.4 Block Producer [COMPLEX]
```
moloch-chain/src/producer.rs (~500 lines)
```
- [ ] Timer-based block production (configurable interval)
- [ ] Batch events from mempool
- [ ] Seal with validator key
- [ ] Empty block handling (skip or minimal)

---

## Phase 3: Query Layer
**Goal:** Rich querying before exposing via API

### 3.1 Index Engine [MODERATE]
```
moloch-index/src/lib.rs
moloch-index/src/indexes.rs (~600 lines)
```
Secondary indexes for:
- [ ] `actor_id -> [event_id]` - events by actor
- [ ] `resource_id -> [event_id]` - events by resource
- [ ] `event_type -> [event_id]` - events by type
- [ ] `timestamp -> [event_id]` - time-range queries
- [ ] Composite indexes for complex queries

**TDD Pattern:**
```rust
#[test]
fn test_actor_index_query() {
    let idx = IndexEngine::new(store);
    idx.index_event(&event);

    let events = idx.events_by_actor(&actor_id, 0..100);
    assert!(events.contains(&event.id()));
}
```

### 3.2 Query Language [MODERATE]
```
moloch-index/src/query.rs (~400 lines)
```
Simple DSL for filtering:
```rust
Query::new()
    .actor(actor_id)
    .resource_type(ResourceKind::Repository)
    .time_range(start..end)
    .event_type(EventType::Push { .. })
    .limit(100)
```

### 3.3 Proof Generator [QUICK WIN]
```
moloch-index/src/proofs.rs (~250 lines)
```
- [ ] Generate inclusion proof for any event
- [ ] Generate consistency proof between heights
- [ ] Batch proof generation
- [ ] Proof serialization (compact binary format)

---

## Phase 4: Networking
**Goal:** Node-to-node communication

### 4.1 Transport Layer [COMPLEX]
```
moloch-net/src/lib.rs
moloch-net/src/transport.rs (~500 lines)
```
- [ ] TCP with TLS 1.3 (rustls)
- [ ] Connection pooling
- [ ] Automatic reconnection
- [ ] Peer identity via Ed25519

### 4.2 Protocol Messages [MODERATE]
```
moloch-net/src/protocol.rs (~400 lines)
```
Message types:
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
    GetEvents { ids },
    Events(Vec<AuditEvent>),

    // Consensus
    Proposal(Block),
    Vote { block_hash, signature },
}
```

### 4.3 Peer Discovery [MODERATE]
```
moloch-net/src/discovery.rs (~300 lines)
```
- [ ] Static peer list (config file)
- [ ] DNS-based discovery
- [ ] Peer exchange protocol
- [ ] Peer scoring (latency, reliability)

### 4.4 Sync Protocol [COMPLEX]
```
moloch-net/src/sync.rs (~600 lines)
```
- [ ] Fast sync (download blocks, verify MMR)
- [ ] Snap sync (download state snapshot)
- [ ] Catch-up sync (fill gaps)
- [ ] Warp sync (skip to recent checkpoint)

---

## Phase 5: Consensus
**Goal:** PoA consensus for validator coordination

### 5.1 Round State Machine [COMPLEX]
```
moloch-consensus/src/lib.rs
moloch-consensus/src/round.rs (~500 lines)
```
Simple PoA (Aura-style):
```
Round N:
1. Leader = validators[N % len(validators)]
2. Leader proposes block
3. Others validate & sign
4. 2/3+ signatures = commit
5. Advance to round N+1
```

### 5.2 Vote Aggregation [MODERATE]
```
moloch-consensus/src/votes.rs (~300 lines)
```
- [ ] Collect votes from validators
- [ ] Aggregate into multi-signature
- [ ] Detect conflicting votes (slashing evidence)
- [ ] Timeout handling

### 5.3 Finality Gadget [MODERATE]
```
moloch-consensus/src/finality.rs (~350 lines)
```
- [ ] Track finalized vs tentative blocks
- [ ] 2/3+ votes = finalized
- [ ] Finality proofs for light clients
- [ ] Finality notifications

---

## Phase 6: API Layer
**Goal:** External access to the chain

### 6.1 REST API [MODERATE]
```
moloch-api/src/rest.rs (~600 lines)
```
Endpoints:
```
POST /v1/events              # Submit event
GET  /v1/events/{id}         # Get event by ID
GET  /v1/events?actor=X      # Query events
GET  /v1/blocks/{height}     # Get block
GET  /v1/blocks/latest       # Get head
GET  /v1/proofs/inclusion    # Get inclusion proof
GET  /v1/proofs/consistency  # Get consistency proof
GET  /v1/status              # Node status
```

### 6.2 gRPC API [MODERATE]
```
moloch-api/src/grpc.rs (~400 lines)
moloch-api/proto/moloch.proto (~200 lines)
```
- [ ] Protobuf definitions
- [ ] Streaming for real-time events
- [ ] Bidirectional for sync protocol

### 6.3 WebSocket Subscriptions [QUICK WIN]
```
moloch-api/src/ws.rs (~300 lines)
```
- [ ] Subscribe to new events
- [ ] Subscribe to new blocks
- [ ] Filter by actor/resource
- [ ] Automatic reconnection

### 6.4 Authentication [MODERATE]
```
moloch-api/src/auth.rs (~350 lines)
```
- [ ] API key authentication
- [ ] JWT tokens
- [ ] Rate limiting per key
- [ ] Audit log of API calls (dogfooding!)

---

## Phase 7: HoloCrypt Integration
**Goal:** Advanced cryptographic features

### 7.1 Encrypted Events [COMPLEX]
```
moloch-holocrypt/src/lib.rs
moloch-holocrypt/src/encrypted.rs (~500 lines)
```
- [ ] Wrap `AuditEvent` in HoloCrypt container
- [ ] Selective field encryption
- [ ] Key management per resource
- [ ] Rotation support

### 7.2 Zero-Knowledge Proofs [COMPLEX]
```
moloch-holocrypt/src/zkp.rs (~400 lines)
```
- [ ] Prove event existence without revealing content
- [ ] Range proofs for numeric fields
- [ ] Set membership proofs
- [ ] Proof aggregation

### 7.3 Threshold Decryption [COMPLEX]
```
moloch-holocrypt/src/threshold.rs (~450 lines)
```
- [ ] FROST key generation ceremony
- [ ] k-of-n decryption
- [ ] Key resharing
- [ ] Emergency recovery

### 7.4 Post-Quantum Upgrade [MODERATE]
```
moloch-holocrypt/src/pqc.rs (~300 lines)
```
- [ ] ML-KEM envelope for event encryption
- [ ] ML-DSA composite signatures
- [ ] Hybrid mode (classical + PQ)
- [ ] Migration path from Ed25519

---

## Phase 8: Operations
**Goal:** Production-ready deployment

### 8.1 CLI Tool [MODERATE]
```
moloch-cli/src/main.rs (~500 lines)
```
Commands:
```bash
moloch init                  # Initialize new chain
moloch start                 # Start node
moloch submit <event.json>   # Submit event
moloch query --actor X       # Query events
moloch prove <event-id>      # Generate proof
moloch verify <proof.json>   # Verify proof
moloch export --range N..M   # Export blocks
moloch import <backup.tar>   # Import backup
```

### 8.2 Metrics & Monitoring [QUICK WIN]
```
moloch-metrics/src/lib.rs (~300 lines)
```
- [ ] Prometheus metrics endpoint
- [ ] Block time histogram
- [ ] Event throughput counter
- [ ] Peer count gauge
- [ ] Storage size gauge

### 8.3 Health Checks [QUICK WIN]
```
moloch-api/src/health.rs (~150 lines)
```
- [ ] Liveness probe
- [ ] Readiness probe
- [ ] Dependency checks (storage, peers)

### 8.4 Configuration [QUICK WIN]
```
moloch-config/src/lib.rs (~250 lines)
```
- [ ] TOML configuration file
- [ ] Environment variable overrides
- [ ] Secrets management (vault integration)
- [ ] Hot reload for non-critical settings

---

## Phase 9: Hardening
**Goal:** Security and reliability

### 9.1 Fuzzing [MODERATE]
```
moloch-fuzz/fuzz_targets/*.rs
```
- [ ] Fuzz protobuf parsing
- [ ] Fuzz event deserialization
- [ ] Fuzz proof verification
- [ ] Fuzz network message parsing

### 9.2 Chaos Testing [MODERATE]
- [ ] Network partition simulation
- [ ] Validator crash recovery
- [ ] Storage corruption recovery
- [ ] Clock skew handling

### 9.3 Security Audit Prep [MODERATE]
- [ ] Threat model document
- [ ] Cryptographic review
- [ ] Dependency audit (cargo-audit)
- [ ] SAST/DAST tooling

---

## Implementation Schedule

### Sprint 1-2: Foundation (Phase 1)
| Task | Type | Est. Lines | Priority |
|------|------|------------|----------|
| Property-based tests | Quick Win | 200 | P0 |
| Error enrichment | Quick Win | 150 | P0 |
| Batch operations | Moderate | 300 | P0 |
| Iterator API | Quick Win | 200 | P1 |

### Sprint 3-4: Chain (Phase 2)
| Task | Type | Est. Lines | Priority |
|------|------|------------|----------|
| Chain state machine | Moderate | 400 | P0 |
| Validator registry | Moderate | 350 | P0 |
| Mempool | Moderate | 400 | P1 |
| Block producer | Complex | 500 | P1 |

### Sprint 5-6: Query (Phase 3)
| Task | Type | Est. Lines | Priority |
|------|------|------------|----------|
| Index engine | Moderate | 600 | P0 |
| Query language | Moderate | 400 | P1 |
| Proof generator | Quick Win | 250 | P0 |

### Sprint 7-9: Networking (Phase 4)
| Task | Type | Est. Lines | Priority |
|------|------|------------|----------|
| Transport layer | Complex | 500 | P0 |
| Protocol messages | Moderate | 400 | P0 |
| Peer discovery | Moderate | 300 | P1 |
| Sync protocol | Complex | 600 | P0 |

### Sprint 10-11: Consensus (Phase 5)
| Task | Type | Est. Lines | Priority |
|------|------|------------|----------|
| Round state machine | Complex | 500 | P0 |
| Vote aggregation | Moderate | 300 | P0 |
| Finality gadget | Moderate | 350 | P1 |

### Sprint 12-13: API (Phase 6)
| Task | Type | Est. Lines | Priority |
|------|------|------------|----------|
| REST API | Moderate | 600 | P0 |
| gRPC API | Moderate | 400 | P1 |
| WebSocket | Quick Win | 300 | P1 |
| Authentication | Moderate | 350 | P0 |

### Sprint 14-16: HoloCrypt (Phase 7)
| Task | Type | Est. Lines | Priority |
|------|------|------------|----------|
| Encrypted events | Complex | 500 | P1 |
| Zero-knowledge proofs | Complex | 400 | P2 |
| Threshold decryption | Complex | 450 | P2 |
| Post-quantum upgrade | Moderate | 300 | P2 |

### Sprint 17-18: Operations (Phase 8)
| Task | Type | Est. Lines | Priority |
|------|------|------------|----------|
| CLI tool | Moderate | 500 | P0 |
| Metrics | Quick Win | 300 | P0 |
| Health checks | Quick Win | 150 | P0 |
| Configuration | Quick Win | 250 | P0 |

### Sprint 19-20: Hardening (Phase 9)
| Task | Type | Est. Lines | Priority |
|------|------|------------|----------|
| Fuzzing | Moderate | 400 | P0 |
| Chaos testing | Moderate | 300 | P1 |
| Security prep | Moderate | 200 | P0 |

---

## Estimated Totals

| Phase | New Lines | Cumulative |
|-------|-----------|------------|
| Current | 3,200 | 3,200 |
| Phase 1: Foundation | 850 | 4,050 |
| Phase 2: Chain | 1,650 | 5,700 |
| Phase 3: Query | 1,250 | 6,950 |
| Phase 4: Networking | 1,800 | 8,750 |
| Phase 5: Consensus | 1,150 | 9,900 |
| Phase 6: API | 1,650 | 11,550 |
| Phase 7: HoloCrypt | 1,650 | 13,200 |
| Phase 8: Operations | 1,200 | 14,400 |
| Phase 9: Hardening | 900 | 15,300 |

**Total:** ~15,300 lines of production code + tests

---

## Success Metrics

### Phase 1 Complete
- [ ] 100% test coverage on core types
- [ ] 10K events/second batch insert

### Phase 3 Complete
- [ ] Query 1M events in <100ms
- [ ] Proof generation <1ms

### Phase 5 Complete
- [ ] 3-node testnet running
- [ ] 1 block/second finality

### Phase 7 Complete
- [ ] ZK proofs verified
- [ ] Threshold key ceremony successful

### Phase 9 Complete
- [ ] 0 critical vulnerabilities
- [ ] 99.9% uptime in stress test

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Consensus bugs | Formal verification of state machine |
| Network attacks | Rate limiting, peer scoring |
| Key compromise | Threshold signatures, rotation |
| Performance | Continuous benchmarking in CI |
| Scope creep | Strict phase gates |

---

## Next Steps

1. **Immediate:** Start Phase 1.1 (property tests) - can be done today
2. **This week:** Complete Phase 1 (foundation hardening)
3. **Next week:** Begin Phase 2 (chain state machine)

The quick wins in Phase 1 build confidence while setting up infrastructure for complex work ahead.
