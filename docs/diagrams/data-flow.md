# Data Flow Diagrams

Detailed data flow diagrams for the Moloch cryptographic audit chain.

## Event Lifecycle

```
                                    ┌─────────────────────────────────────┐
                                    │           CLIENT APPLICATION        │
                                    │                                     │
                                    │  1. Create Event                    │
                                    │     - Set actor, resource, action   │
                                    │     - Add metadata                  │
                                    │     - Sign with Ed25519             │
                                    └──────────────┬──────────────────────┘
                                                   │
                                                   ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                                  API LAYER                                    │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                         REST/WebSocket Handler                          │  │
│  │                                                                         │  │
│  │  2. Validate Request                                                    │  │
│  │     - Check authentication (JWT/API Key)                                │  │
│  │     - Validate event structure                                          │  │
│  │     - Verify signature                                                  │  │
│  │     - Check rate limits                                                 │  │
│  └───────────────────────────────────┬────────────────────────────────────┘  │
└──────────────────────────────────────┼───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                                 CHAIN LAYER                                   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                              MEMPOOL                                     │ │
│  │                                                                          │ │
│  │  3. Queue Event                                                          │ │
│  │     - Deduplicate by EventId                                             │ │
│  │     - Check capacity limits                                              │ │
│  │     - Set TTL timer                                                      │ │
│  │     - Add to priority queue                                              │ │
│  │                                                                          │ │
│  │     ┌──────────┐  ┌──────────┐  ┌──────────┐                            │ │
│  │     │ Event A  │  │ Event B  │  │ Event C  │  ...                       │ │
│  │     └──────────┘  └──────────┘  └──────────┘                            │ │
│  └────────────────────────────────────┬────────────────────────────────────┘ │
│                                       │                                       │
│                                       ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                           BLOCK BUILDER                                  │ │
│  │                                                                          │ │
│  │  4. Build Block (when proposer)                                          │ │
│  │     - Drain events from mempool (max_events_per_block)                   │ │
│  │     - Compute events Merkle root                                         │ │
│  │     - Set parent hash, height, timestamp                                 │ │
│  │     - Sign block header                                                  │ │
│  │                                                                          │ │
│  │     Block N+1:                                                           │ │
│  │     ┌─────────────────────────────────────────────────────────────────┐ │ │
│  │     │ Header: height=N+1, parent=hash(N), events_root, proposer_sig  │ │ │
│  │     │ Events: [Event A, Event B, Event C, ...]                        │ │ │
│  │     └─────────────────────────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────┬────────────────────────────────────┘ │
└───────────────────────────────────────┼──────────────────────────────────────┘
                                        │
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                               CONSENSUS LAYER                                 │
│                                                                               │
│  5. Achieve Finality                                                          │
│     - Broadcast proposal to validators                                        │
│     - Collect signatures (need 2/3 + 1)                                       │
│     - Mark block as finalized                                                 │
│                                                                               │
│     Validator Signatures:                                                     │
│     ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐                           │
│     │ V1 ✓  │  │ V2 ✓  │  │ V3 ✓  │  │ V4 -  │  (3/4 = finalized)          │
│     └────────┘  └────────┘  └────────┘  └────────┘                           │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                               STORAGE LAYER                                   │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                              RocksDB                                     │ │
│  │                                                                          │ │
│  │  6. Persist Block                                                        │ │
│  │     - Write block to 'blocks' column family                              │ │
│  │     - Write each event to 'events' column family                         │ │
│  │     - Update metadata (latest height, etc.)                              │ │
│  │                                                                          │ │
│  │     CF: blocks          CF: events           CF: meta                    │ │
│  │     ┌──────────────┐   ┌───────────────┐    ┌────────────────┐          │ │
│  │     │ height → blk │   │ id → event    │    │ key → value    │          │ │
│  │     └──────────────┘   └───────────────┘    └────────────────┘          │ │
│  └────────────────────────────────────┬────────────────────────────────────┘ │
│                                       │                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                         MERKLE MOUNTAIN RANGE                            │ │
│  │                                                                          │ │
│  │  7. Update MMR                                                           │ │
│  │     - Append block hash as new leaf                                      │ │
│  │     - Compute new peaks and root                                         │ │
│  │     - Store MMR nodes                                                    │ │
│  │                                                                          │ │
│  │     Before:          After:                                              │ │
│  │          2                   6                                           │ │
│  │         / \                 / \                                          │ │
│  │        0   1               2   5                                         │ │
│  │                           / \ / \                                        │ │
│  │                          0  1 3  4                                       │ │
│  └────────────────────────────────────┬────────────────────────────────────┘ │
│                                       │                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                              INDEXES                                     │ │
│  │                                                                          │ │
│  │  8. Update Secondary Indexes                                             │ │
│  │     - Actor index: actor_id → [event_ids]                                │ │
│  │     - Resource index: resource_id → [event_ids]                          │ │
│  │     - Time index: timestamp → [event_ids]                                │ │
│  │     - Type index: event_type → [event_ids]                               │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              ANCHORING LAYER                                  │
│                                                                               │
│  9. External Anchoring (periodic)                                             │
│     - Create commitment from MMR root                                         │
│     - Submit to Bitcoin (OP_RETURN)                                           │
│     - Submit to Ethereum (calldata)                                           │
│     - Track confirmations                                                     │
│                                                                               │
│     ┌─────────────┐           ┌─────────────┐                                │
│     │   Bitcoin   │           │  Ethereum   │                                │
│     │  OP_RETURN  │           │  Contract   │                                │
│     │ [MLCH][root]│           │ anchor(root)│                                │
│     └─────────────┘           └─────────────┘                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Query Data Flow

```
┌────────────────┐
│ Client Query   │
│                │
│ GET /events    │
│ ?actor=alice   │
│ &limit=100     │
└───────┬────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│                        API LAYER                                  │
│                                                                   │
│  1. Parse Query Parameters                                        │
│     - actor: "alice"                                              │
│     - limit: 100                                                  │
│                                                                   │
│  2. Build Query                                                   │
│     Query::new()                                                  │
│         .actor("alice")                                           │
│         .limit(100)                                               │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                       INDEX LAYER                                 │
│                                                                   │
│  3. Index Lookup                                                  │
│     - Hash("alice") → bucket                                      │
│     - Scan bucket for event IDs                                   │
│     - Apply time/type filters if present                          │
│                                                                   │
│     Actor Index:                                                  │
│     ┌─────────────────────────────────────────┐                  │
│     │ hash("alice") → [evt_1, evt_5, evt_9]   │                  │
│     └─────────────────────────────────────────┘                  │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                      STORAGE LAYER                                │
│                                                                   │
│  4. Fetch Events                                                  │
│     - Batch read event IDs from index                             │
│     - Deserialize events (zero-copy with rkyv)                    │
│                                                                   │
│     ┌─────────────────────────────────────────┐                  │
│     │ events CF: evt_1 → AuditEvent           │                  │
│     │            evt_5 → AuditEvent           │                  │
│     │            evt_9 → AuditEvent           │                  │
│     └─────────────────────────────────────────┘                  │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                        API LAYER                                  │
│                                                                   │
│  5. Format Response                                               │
│     - Serialize to JSON                                           │
│     - Add pagination metadata                                     │
│     - Return to client                                            │
│                                                                   │
│     {                                                             │
│       "events": [...],                                            │
│       "total": 3,                                                 │
│       "limit": 100,                                               │
│       "offset": 0                                                 │
│     }                                                             │
└──────────────────────────────────────────────────────────────────┘
```

## Proof Generation Flow

```
┌────────────────────┐
│ Proof Request      │
│                    │
│ GET /proofs/       │
│   inclusion?       │
│   event_id=evt_1   │
└─────────┬──────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────┐
│                        API LAYER                                  │
│                                                                   │
│  1. Lookup Event Location                                         │
│     - Find block containing event                                 │
│     - Find event index within block                               │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                       CHAIN LAYER                                 │
│                                                                   │
│  2. Generate Event Merkle Proof                                   │
│     - Build merkle tree from block events                         │
│     - Extract path from event to events_root                      │
│                                                                   │
│     Events in Block:                                              │
│                     root (events_root)                            │
│                      /              \                             │
│                   H01                H23                          │
│                   / \                / \                          │
│                 H0   H1            H2   H3                        │
│                 │    │             │    │                         │
│               evt_0 evt_1 ◄──── evt_2 evt_3                       │
│                       │                                           │
│                 [target event]                                    │
│                                                                   │
│     Proof path: [H0, H23]                                         │
│     Index: 1                                                      │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                        MMR LAYER                                  │
│                                                                   │
│  3. Generate Block MMR Proof                                      │
│     - Find block's position in MMR                                │
│     - Generate proof from leaf to root                            │
│                                                                   │
│     MMR:                                                          │
│                         14 (root)                                 │
│                        /          \                               │
│                       6            13                             │
│                     /   \         /   \                           │
│                    2     5       9     12                         │
│                   / \   / \     / \   / \                         │
│                  0   1 3   4   7   8 10  11                       │
│                        │                                          │
│                  [block at pos 3]                                 │
│                                                                   │
│     Proof: siblings=[4], peaks=[14-right]                         │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                        API LAYER                                  │
│                                                                   │
│  4. Return Combined Proof                                         │
│                                                                   │
│     {                                                             │
│       "event_id": "evt_1",                                        │
│       "block_height": 2,                                          │
│       "event_proof": {                                            │
│         "path": ["H0", "H23"],                                    │
│         "index": 1,                                               │
│         "root": "events_root"                                     │
│       },                                                          │
│       "mmr_proof": {                                              │
│         "position": 3,                                            │
│         "siblings": ["hash_4"],                                   │
│         "peaks": [...],                                           │
│         "root": "mmr_root"                                        │
│       }                                                           │
│     }                                                             │
└──────────────────────────────────────────────────────────────────┘
```

## Light Client Verification Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          LIGHT CLIENT                                        │
│                                                                              │
│  Stored: [Header N-10, Header N-9, ..., Header N]                           │
│  Trust: Validator set at checkpoint                                          │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  1. Receive Proof for Event                                                  │
│                                                                              │
│     CompactProof {                                                           │
│       event_id,                                                              │
│       block_height: 5,                                                       │
│       block_hash,                                                            │
│       merkle_proof,                                                          │
│       mmr_proof                                                              │
│     }                                                                        │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  2. Verify Block Header                                                      │
│                                                                              │
│     - Lookup header at height 5                                              │
│     - Verify header.hash == proof.block_hash                                 │
│     - Verify header has 2/3+1 validator signatures                           │
│                                                                              │
│     TrustedHeader {                                                          │
│       header: BlockHeader { height: 5, ... },                                │
│       signatures: [(V1, sig1), (V2, sig2), (V3, sig3)],  ◄── ≥ 2/3+1        │
│       mmr_root                                                               │
│     }                                                                        │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  3. Verify Event Merkle Proof                                                │
│                                                                              │
│     - Start with event_id as leaf                                            │
│     - Apply merkle path: hash_pair(leaf, sibling[0]) → ...                   │
│     - Verify computed root == header.events_root                             │
│                                                                              │
│     Computation:                                                             │
│     leaf = event_id                                                          │
│     step1 = hash_pair(leaf, proof[0])       # with sibling                   │
│     step2 = hash_pair(step1, proof[1])      # with sibling                   │
│     ...                                                                      │
│     result == header.events_root  ✓                                          │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  4. Verify MMR Proof (Optional)                                              │
│                                                                              │
│     - Verify block_hash is in MMR at given position                          │
│     - Verify against current tip's mmr_root                                  │
│                                                                              │
│     MMR verification ensures block is part of canonical chain                │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  5. Result                                                                   │
│                                                                              │
│     Event is VERIFIED:                                                       │
│     - Exists in block 5                                                      │
│     - Block 5 is finalized (2/3+1 signatures)                                │
│     - Block 5 is in canonical chain (MMR proof)                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Network Data Flow

```
┌───────────────────────────────────────────────────────────────────────────┐
│                              NODE A (Proposer)                             │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      │ NewBlock
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                            GOSSIP NETWORK                                  │
│                                                                            │
│    ┌──────────┐        ┌──────────┐        ┌──────────┐                   │
│    │  Node B  │◄──────►│  Node C  │◄──────►│  Node D  │                   │
│    └──────────┘        └──────────┘        └──────────┘                   │
│         │                   │                   │                          │
│         └───────────────────┴───────────────────┘                          │
│                             │                                              │
│                    All receive NewBlock                                    │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                           EACH RECEIVING NODE                              │
│                                                                            │
│  1. Validate block                                                         │
│     - Verify proposer signature                                            │
│     - Verify parent exists                                                 │
│     - Verify events merkle root                                            │
│                                                                            │
│  2. If validator, sign and broadcast Vote                                  │
│     - Sign block hash                                                      │
│     - Broadcast Vote message                                               │
│                                                                            │
│  3. Collect votes                                                          │
│     - Wait for 2/3+1 signatures                                            │
│     - Mark block as finalized                                              │
│                                                                            │
│  4. Commit to storage                                                      │
│     - Persist block and events                                             │
│     - Update MMR                                                           │
│     - Update indexes                                                       │
└───────────────────────────────────────────────────────────────────────────┘
```
