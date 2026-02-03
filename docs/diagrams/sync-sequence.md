# Sync Protocol Sequence Diagrams

Sequence diagrams for node synchronization in Moloch.

## Initial Handshake

```
┌──────────────┐                              ┌──────────────┐
│   New Node   │                              │  Existing    │
│   (Client)   │                              │    Peer      │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │         TCP Connect                         │
       │────────────────────────────────────────────►│
       │                                             │
       │         TLS Handshake                       │
       │◄───────────────────────────────────────────►│
       │                                             │
       │         Hello                               │
       │────────────────────────────────────────────►│
       │  {                                          │
       │    version: "1.0.0",                        │
       │    chain_id: "moloch-mainnet",              │
       │    head_height: 0,                          │
       │    head_hash: genesis_hash,                 │
       │    public_key: pk,                          │
       │    signature: sig(nonce)                    │
       │  }                                          │
       │                                             │
       │                                             │──┐
       │                                             │  │ Verify:
       │                                             │  │ - chain_id match
       │                                             │  │ - signature valid
       │                                             │  │ - version compatible
       │                                             │◄─┘
       │                                             │
       │         HelloAck                            │
       │◄────────────────────────────────────────────│
       │  {                                          │
       │    version: "1.0.0",                        │
       │    chain_id: "moloch-mainnet",              │
       │    head_height: 1000,                       │
       │    head_hash: hash_1000,                    │
       │    public_key: pk,                          │
       │    signature: sig(nonce)                    │
       │  }                                          │
       │                                             │
       │──┐                                          │
       │  │ Determine sync strategy:                 │
       │  │ - peer is 1000 blocks ahead              │
       │  │ - need to sync                           │
       │◄─┘                                          │
       │                                             │
       │         CONNECTION ESTABLISHED              │
       │◄═══════════════════════════════════════════►│
```

## Fast Sync (Full Block Download)

```
┌──────────────┐                              ┌──────────────┐
│  Syncing     │                              │   Peer       │
│    Node      │                              │  (Ahead)     │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  Local: height=0                            │
       │  Peer:  height=1000                         │
       │                                             │
       │ ════════════════════════════════════════════════
       │          FAST SYNC: Download full blocks
       │ ════════════════════════════════════════════════
       │                                             │
       │         GetBlocks                           │
       │────────────────────────────────────────────►│
       │  { start: 1, count: 100 }                   │
       │                                             │
       │                                             │──┐
       │                                             │  │ Load blocks
       │                                             │  │ 1-100 from
       │                                             │  │ storage
       │                                             │◄─┘
       │                                             │
       │         Blocks                              │
       │◄────────────────────────────────────────────│
       │  { blocks: [Block1, Block2, ..., Block100] }│
       │                                             │
       │──┐                                          │
       │  │ For each block:                          │
       │  │ - Verify parent hash                     │
       │  │ - Verify proposer signature              │
       │  │ - Verify events merkle root              │
       │  │ - Verify 2/3+1 signatures                │
       │  │ - Commit to storage                      │
       │  │ - Update MMR                             │
       │◄─┘                                          │
       │                                             │
       │         GetBlocks                           │
       │────────────────────────────────────────────►│
       │  { start: 101, count: 100 }                 │
       │                                             │
       │         Blocks                              │
       │◄────────────────────────────────────────────│
       │  { blocks: [Block101, ..., Block200] }      │
       │                                             │
       │         ... (repeat until caught up) ...    │
       │                                             │
       │         GetBlocks                           │
       │────────────────────────────────────────────►│
       │  { start: 901, count: 100 }                 │
       │                                             │
       │         Blocks                              │
       │◄────────────────────────────────────────────│
       │  { blocks: [Block901, ..., Block1000] }     │
       │                                             │
       │──┐                                          │
       │  │ SYNC COMPLETE                            │
       │  │ Local height: 1000                       │
       │◄─┘                                          │
       │                                             │
       │ ════════════════════════════════════════════════
       │          NOW IN SYNC - Switch to gossip
       │ ════════════════════════════════════════════════
```

## Header-First Sync (Light Mode)

```
┌──────────────┐                              ┌──────────────┐
│ Light Client │                              │  Full Node   │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  Checkpoint: height=500, hash=H500          │
       │                                             │
       │ ════════════════════════════════════════════════
       │     HEADER-FIRST SYNC: Download headers only
       │ ════════════════════════════════════════════════
       │                                             │
       │         GetHeaders                          │
       │────────────────────────────────────────────►│
       │  { start: 501, count: 100 }                 │
       │                                             │
       │         Headers                             │
       │◄────────────────────────────────────────────│
       │  {                                          │
       │    headers: [                               │
       │      TrustedHeader {                        │
       │        header: BlockHeader,                 │
       │        signatures: [(pk, sig), ...],        │
       │        mmr_root                             │
       │      },                                     │
       │      ...                                    │
       │    ]                                        │
       │  }                                          │
       │                                             │
       │──┐                                          │
       │  │ For each header:                         │
       │  │ - Verify parent hash linkage             │
       │  │ - Verify 2/3+1 validator signatures      │
       │  │ - Store in HeaderStore                   │
       │◄─┘                                          │
       │                                             │
       │         ... (continue until caught up) ...  │
       │                                             │
       │ ════════════════════════════════════════════════
       │     HEADERS SYNCED - Request proofs on-demand
       │ ════════════════════════════════════════════════
       │                                             │
       │                                             │
       │   (User requests proof for event E)         │
       │                                             │
       │         GetProof                            │
       │────────────────────────────────────────────►│
       │  { event_id: E }                            │
       │                                             │
       │         Proof                               │
       │◄────────────────────────────────────────────│
       │  { CompactProof { ... } }                   │
       │                                             │
       │──┐                                          │
       │  │ Verify proof against stored headers      │
       │◄─┘                                          │
```

## Warp Sync (Checkpoint-Based)

```
┌──────────────┐                              ┌──────────────┐
│   New Node   │                              │    Peer      │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  Has trusted checkpoint at height 10000     │
       │                                             │
       │ ════════════════════════════════════════════════
       │       WARP SYNC: Skip to checkpoint
       │ ════════════════════════════════════════════════
       │                                             │
       │         GetSnapshot                         │
       │────────────────────────────────────────────►│
       │  { height: 10000 }                          │
       │                                             │
       │                                             │──┐
       │                                             │  │ Create snapshot:
       │                                             │  │ - Chain state
       │                                             │  │ - MMR nodes
       │                                             │  │ - Index roots
       │                                             │◄─┘
       │                                             │
       │         Snapshot (chunked)                  │
       │◄────────────────────────────────────────────│
       │  { chunk: 1/N, data: [...] }                │
       │◄────────────────────────────────────────────│
       │  { chunk: 2/N, data: [...] }                │
       │◄────────────────────────────────────────────│
       │  ...                                        │
       │◄────────────────────────────────────────────│
       │  { chunk: N/N, data: [...], proof: ... }    │
       │                                             │
       │──┐                                          │
       │  │ Verify snapshot:                         │
       │  │ - MMR root matches checkpoint            │
       │  │ - State root matches checkpoint          │
       │  │ - Import state                           │
       │◄─┘                                          │
       │                                             │
       │ ════════════════════════════════════════════════
       │      SNAPSHOT LOADED - Continue from 10001
       │ ════════════════════════════════════════════════
       │                                             │
       │         GetBlocks                           │
       │────────────────────────────────────────────►│
       │  { start: 10001, count: 100 }               │
       │                                             │
       │         Blocks                              │
       │◄────────────────────────────────────────────│
       │  { blocks: [...] }                          │
       │                                             │
       │         ... (normal sync continues) ...     │
```

## Parallel Peer Sync

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Syncing     │    │   Peer A     │    │   Peer B     │
│    Node      │    │  (height=1k) │    │  (height=1k) │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       │  Need blocks 1-1000                   │
       │  Split across peers for speed         │
       │                   │                   │
       │ ══════════════════════════════════════════════
       │         PARALLEL DOWNLOAD
       │ ══════════════════════════════════════════════
       │                   │                   │
       │    GetBlocks      │                   │
       │───────────────────►                   │
       │  { start: 1,      │                   │
       │    count: 500 }   │                   │
       │                   │                   │
       │    GetBlocks      │                   │
       │───────────────────┼──────────────────►│
       │                   │  { start: 501,    │
       │                   │    count: 500 }   │
       │                   │                   │
       │    Blocks 1-500   │                   │
       │◄──────────────────│                   │
       │                   │                   │
       │                   │    Blocks 501-1000│
       │◄──────────────────┼───────────────────│
       │                   │                   │
       │──┐                │                   │
       │  │ Merge and validate blocks         │
       │  │ in order (1, 2, 3, ..., 1000)      │
       │◄─┘                │                   │
       │                   │                   │
       │ ══════════════════════════════════════════════
       │     SYNC COMPLETE - 2x faster with 2 peers
       │ ══════════════════════════════════════════════
```

## Gossip Mode (Post-Sync)

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│    Node A    │    │    Node B    │    │    Node C    │
│  (Proposer)  │    │              │    │              │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       │ All nodes in sync at height 1000      │
       │                   │                   │
       │ ══════════════════════════════════════════════
       │              GOSSIP MODE
       │ ══════════════════════════════════════════════
       │                   │                   │
       │──┐                │                   │
       │  │ Build Block 1001                   │
       │◄─┘                │                   │
       │                   │                   │
       │     NewBlock      │                   │
       │───────────────────►                   │
       │  (Block 1001)     │                   │
       │                   │                   │
       │                   │     NewBlock      │
       │                   │───────────────────►
       │                   │   (forward)       │
       │                   │                   │
       │                   │──┐                │──┐
       │                   │  │ Validate       │  │ Validate
       │                   │◄─┘                │◄─┘
       │                   │                   │
       │                   │                   │
       │      Vote         │                   │
       │◄──────────────────│                   │
       │                   │                   │
       │                   │      Vote         │
       │◄──────────────────┼───────────────────│
       │                   │                   │
       │──┐                │                   │
       │  │ 2/3+1 votes    │                   │
       │  │ FINALIZED      │                   │
       │◄─┘                │                   │
       │                   │                   │
       │   Finalized       │                   │
       │───────────────────►                   │
       │  (Block 1001 +    │                   │
       │   signatures)     │───────────────────►
       │                   │                   │
       │                   │──┐                │──┐
       │                   │  │ Commit         │  │ Commit
       │                   │◄─┘                │◄─┘
```

## Fork Resolution

```
┌──────────────┐                              ┌──────────────┐
│    Node A    │                              │    Node B    │
│ (sees fork)  │                              │  (main chain)│
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  Local chain: ... → 99 → 100a               │
       │  Peer  chain: ... → 99 → 100b → 101 → 102   │
       │                                             │
       │  Detect: peer has longer chain with         │
       │          different block at height 100      │
       │                                             │
       │ ════════════════════════════════════════════════
       │              FORK RESOLUTION
       │ ════════════════════════════════════════════════
       │                                             │
       │         GetBlocks                           │
       │────────────────────────────────────────────►│
       │  { start: 100, count: 10 }                  │
       │                                             │
       │         Blocks                              │
       │◄────────────────────────────────────────────│
       │  { blocks: [100b, 101, 102] }               │
       │                                             │
       │──┐                                          │
       │  │ Compare chains:                          │
       │  │                                          │
       │  │ Block 100a:                              │
       │  │   - Signatures: 2 validators             │
       │  │   - NOT finalized                        │
       │  │                                          │
       │  │ Block 100b:                              │
       │  │   - Signatures: 3 validators (2/3+1)    │
       │  │   - FINALIZED                            │
       │  │                                          │
       │  │ Resolution: 100b is canonical            │
       │  │ - Rollback 100a                          │
       │  │ - Apply 100b, 101, 102                   │
       │◄─┘                                          │
       │                                             │
       │──┐                                          │
       │  │ Return 100a events to mempool            │
       │  │ (if not in 100b)                         │
       │◄─┘                                          │
       │                                             │
       │  Chains now match                           │
       │                                             │

Note: Finalized blocks (2/3+1 sigs) cannot be rolled back.
      Fork can only happen with non-finalized blocks.
```

## Status Updates

```
┌──────────────┐                              ┌──────────────┐
│    Node A    │                              │    Node B    │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  Connected, periodic status exchange        │
       │                                             │
       │ ════════════════════════════════════════════════
       │           PERIODIC STATUS (every 30s)
       │ ════════════════════════════════════════════════
       │                                             │
       │         Status                              │
       │────────────────────────────────────────────►│
       │  {                                          │
       │    height: 1005,                            │
       │    head_hash: H1005,                        │
       │    mmr_root: R1005,                         │
       │    peer_count: 4,                           │
       │    syncing: false                           │
       │  }                                          │
       │                                             │
       │         Status                              │
       │◄────────────────────────────────────────────│
       │  {                                          │
       │    height: 1005,                            │
       │    head_hash: H1005,                        │
       │    mmr_root: R1005,                         │
       │    peer_count: 3,                           │
       │    syncing: false                           │
       │  }                                          │
       │                                             │
       │  Heights match, chains consistent           │
       │                                             │
       │          ... 30 seconds later ...           │
       │                                             │
       │         Status                              │
       │────────────────────────────────────────────►│
       │  {                                          │
       │    height: 1010,                            │
       │    head_hash: H1010,                        │
       │    ...                                      │
       │  }                                          │
       │                                             │
       │         Status                              │
       │◄────────────────────────────────────────────│
       │  {                                          │
       │    height: 1008,   ← Node B is behind       │
       │    ...                                      │
       │  }                                          │
       │                                             │
       │  Node B will request blocks 1009, 1010     │
```

## Sync State Machine

```
                        ┌─────────────────┐
                        │   CONNECTING    │
                        │                 │
                        │ TCP + TLS setup │
                        └────────┬────────┘
                                 │
                                 │ Connected
                                 ▼
                        ┌─────────────────┐
                        │   HANDSHAKING   │
                        │                 │
                        │ Hello/HelloAck  │
                        │ exchange        │
                        └────────┬────────┘
                                 │
                                 │ Handshake complete
                                 ▼
                        ┌─────────────────┐
                        │  DETERMINING    │
                        │                 │
                        │ Compare heights │
                        │ Choose strategy │
                        └────────┬────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            │                    │                    │
            ▼ behind             ▼ equal              ▼ ahead
   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
   │    SYNCING      │  │     SYNCED      │  │   PROVIDING     │
   │                 │  │                 │  │                 │
   │ Download blocks │  │ Gossip mode     │  │ Serve requests  │
   │ from peer       │  │ bi-directional  │  │ to peer         │
   └────────┬────────┘  └────────┬────────┘  └────────┬────────┘
            │                    │                    │
            │ caught up          │                    │ peer caught up
            └────────────────────┴────────────────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │     SYNCED      │
                        │                 │
                        │ Normal gossip   │
                        │ operation       │
                        └─────────────────┘
```
