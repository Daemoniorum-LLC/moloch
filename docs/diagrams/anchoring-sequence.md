# Anchoring Protocol Sequence Diagrams

Sequence diagrams for external blockchain anchoring in Moloch.

## Bitcoin Anchoring Flow

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│    Moloch    │    │   Anchor     │    │   Bitcoin    │    │   Bitcoin    │
│    Chain     │    │   Manager    │    │   Provider   │    │   Network    │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │                   │
       │  Block 1000       │                   │                   │
       │  finalized        │                   │                   │
       │                   │                   │                   │
       │ ══════════════════════════════════════════════════════════════
       │              ANCHORING TRIGGER (every N blocks)
       │ ══════════════════════════════════════════════════════════════
       │                   │                   │                   │
       │  Commitment       │                   │                   │
       │──────────────────►│                   │                   │
       │  {                │                   │                   │
       │    chain_id,      │                   │                   │
       │    mmr_root,      │                   │                   │
       │    height: 1000,  │                   │                   │
       │    event_count,   │                   │                   │
       │    timestamp      │                   │                   │
       │  }                │                   │                   │
       │                   │                   │                   │
       │                   │──┐                │                   │
       │                   │  │ Create         │                   │
       │                   │  │ AnchorRequest  │                   │
       │                   │  │ priority=Normal│                   │
       │                   │◄─┘                │                   │
       │                   │                   │                   │
       │                   │  submit()         │                   │
       │                   │──────────────────►│                   │
       │                   │                   │                   │
       │                   │                   │──┐                │
       │                   │                   │  │ Build Bitcoin  │
       │                   │                   │  │ transaction:   │
       │                   │                   │  │                │
       │                   │                   │  │ OP_RETURN:     │
       │                   │                   │  │ [MLCH][hash]   │
       │                   │                   │  │ [chain_id]     │
       │                   │                   │◄─┘                │
       │                   │                   │                   │
       │                   │                   │  sendrawtx        │
       │                   │                   │──────────────────►│
       │                   │                   │                   │
       │                   │                   │  txid             │
       │                   │                   │◄──────────────────│
       │                   │                   │                   │
       │                   │  AnchorTx         │                   │
       │                   │◄──────────────────│                   │
       │                   │  { txid, ... }    │                   │
       │                   │                   │                   │
       │                   │──┐                │                   │
       │                   │  │ Store          │                   │
       │                   │  │ AnchorOperation│                   │
       │                   │  │ status=Pending │                   │
       │                   │◄─┘                │                   │
       │                   │                   │                   │
       │ ══════════════════════════════════════════════════════════════
       │              CONFIRMATION TRACKING
       │ ══════════════════════════════════════════════════════════════
       │                   │                   │                   │
       │                   │  (periodic poll)  │                   │
       │                   │                   │                   │
       │                   │  confirmations()  │                   │
       │                   │──────────────────►│                   │
       │                   │                   │                   │
       │                   │                   │ getrawtx(txid)    │
       │                   │                   │──────────────────►│
       │                   │                   │                   │
       │                   │                   │  { confs: 1 }     │
       │                   │                   │◄──────────────────│
       │                   │                   │                   │
       │                   │  confirmations: 1 │                   │
       │                   │◄──────────────────│                   │
       │                   │                   │                   │
       │                   │  ... ~60 minutes (6 blocks) ...       │
       │                   │                   │                   │
       │                   │  confirmations()  │                   │
       │                   │──────────────────►│                   │
       │                   │                   │                   │
       │                   │                   │ getrawtx(txid)    │
       │                   │                   │──────────────────►│
       │                   │                   │                   │
       │                   │                   │  { confs: 6 }     │
       │                   │                   │◄──────────────────│
       │                   │                   │                   │
       │                   │  confirmations: 6 │                   │
       │                   │◄──────────────────│                   │
       │                   │                   │                   │
       │                   │──┐                │                   │
       │                   │  │ 6 >= required  │                   │
       │                   │  │ status=Confirmed│                  │
       │                   │◄─┘                │                   │
       │                   │                   │                   │
       │ ══════════════════════════════════════════════════════════════
       │              SPV PROOF GENERATION
       │ ══════════════════════════════════════════════════════════════
       │                   │                   │                   │
       │                   │  get_proof()      │                   │
       │                   │──────────────────►│                   │
       │                   │                   │                   │
       │                   │                   │ getblock(hash)    │
       │                   │                   │──────────────────►│
       │                   │                   │                   │
       │                   │                   │  Block data       │
       │                   │                   │◄──────────────────│
       │                   │                   │                   │
       │                   │                   │──┐                │
       │                   │                   │  │ Generate       │
       │                   │                   │  │ Merkle proof   │
       │                   │                   │  │ from tx to     │
       │                   │                   │  │ block root     │
       │                   │                   │◄─┘                │
       │                   │                   │                   │
       │                   │  AnchorProof      │                   │
       │                   │◄──────────────────│                   │
       │                   │  {                │                   │
       │                   │    commitment,    │                   │
       │                   │    tx_id,         │                   │
       │                   │    block_height,  │                   │
       │                   │    spv_proof: {   │                   │
       │                   │      merkle_path, │                   │
       │                   │      tx_index,    │                   │
       │                   │      block_header │                   │
       │                   │    }              │                   │
       │                   │  }                │                   │
       │                   │                   │                   │
       │  ProofBundle      │                   │                   │
       │◄──────────────────│                   │                   │
       │                   │                   │                   │
```

## OP_RETURN Data Format

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BITCOIN OP_RETURN SCRIPT                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   OP_RETURN <44 bytes of anchor data>                                       │
│                                                                              │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │  Byte Range  │  Size  │  Content                                   │    │
│   ├──────────────┼────────┼────────────────────────────────────────────┤    │
│   │  0-3         │ 4      │  Magic: "MLCH" (0x4D4C4348)                │    │
│   │  4-35        │ 32     │  commitment_hash = SHA256(commitment)      │    │
│   │  36-43       │ 8      │  chain_id_hash = SHA256(chain_id)[0:8]    │    │
│   └──────────────┴────────┴────────────────────────────────────────────┘    │
│                                                                              │
│   Total: 44 bytes (within 80-byte OP_RETURN limit)                          │
│                                                                              │
│   Example (hex):                                                             │
│   4D4C4348                                 # "MLCH" magic                    │
│   a1b2c3d4...                              # 32-byte commitment hash         │
│   e5f6a7b8                                 # 8-byte chain ID hash            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

Commitment Hash Computation:
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   commitment = {                                                             │
│     chain_id: "moloch-mainnet",                                             │
│     mmr_root: <32 bytes>,                                                   │
│     height: 1000,                                                           │
│     event_count: 50000,                                                     │
│     timestamp: 1705123456                                                   │
│   }                                                                          │
│                                                                              │
│   commitment_hash = SHA256(serialize(commitment))                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Bitcoin Transaction Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ANCHOR TRANSACTION                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   INPUTS:                                                                    │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │  Input 0: UTXO from wallet                                         │     │
│   │    - Previous txid: <32 bytes>                                     │     │
│   │    - Vout: <4 bytes>                                               │     │
│   │    - Script: P2WPKH witness                                        │     │
│   └───────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│   OUTPUTS:                                                                   │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │  Output 0: OP_RETURN (anchor data)                                 │     │
│   │    - Value: 0 satoshi                                              │     │
│   │    - Script: OP_RETURN <44 bytes>                                  │     │
│   └───────────────────────────────────────────────────────────────────┘     │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │  Output 1: Change (if needed)                                      │     │
│   │    - Value: input - fee                                            │     │
│   │    - Script: P2WPKH to change address                              │     │
│   └───────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│   Size estimate: ~150-170 vbytes                                            │
│   Fee: vsize × fee_rate_sat_vb                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## SPV Proof Verification (Light Client)

```
┌──────────────┐                              ┌──────────────┐
│ Light Client │                              │  SPV Proof   │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  Have: AnchorProof with SpvProof            │
       │                                             │
       │ ══════════════════════════════════════════════════
       │           SPV PROOF VERIFICATION
       │ ══════════════════════════════════════════════════
       │                                             │
       │  Step 1: Verify block header PoW            │
       │                                             │
       │  ┌───────────────────────────────────┐      │
       │  │ Block Header (80 bytes):          │      │
       │  │   version: 4 bytes                │      │
       │  │   prev_block: 32 bytes            │      │
       │  │   merkle_root: 32 bytes           │      │
       │  │   time: 4 bytes                   │      │
       │  │   bits: 4 bytes (difficulty)      │      │
       │  │   nonce: 4 bytes                  │      │
       │  │                                   │      │
       │  │ Verify:                           │      │
       │  │   SHA256d(header) < target        │      │
       │  └───────────────────────────────────┘      │
       │                                             │
       │  Step 2: Rebuild merkle path                │
       │                                             │
       │  ┌───────────────────────────────────┐      │
       │  │           merkle_root             │      │
       │  │              /   \                │      │
       │  │            H01   H23              │      │
       │  │           / \    / \              │      │
       │  │         H0  H1  H2  H3            │      │
       │  │         │   │   │   │             │      │
       │  │        tx0 tx1 tx2 tx3            │      │
       │  │              │                    │      │
       │  │        (anchor tx at index 1)     │      │
       │  │                                   │      │
       │  │ Proof path: [H0, H23]             │      │
       │  │ Index: 1                          │      │
       │  │                                   │      │
       │  │ Verification:                     │      │
       │  │   start = txid (anchor tx)        │      │
       │  │   step1 = SHA256d(H0 || start)    │      │
       │  │   step2 = SHA256d(step1 || H23)   │      │
       │  │   assert step2 == merkle_root     │      │
       │  └───────────────────────────────────┘      │
       │                                             │
       │  Step 3: Verify anchor data                 │
       │                                             │
       │  ┌───────────────────────────────────┐      │
       │  │ Parse OP_RETURN from transaction: │      │
       │  │   - Extract magic "MLCH"          │      │
       │  │   - Extract commitment_hash       │      │
       │  │   - Extract chain_id_hash         │      │
       │  │                                   │      │
       │  │ Verify:                           │      │
       │  │   commitment_hash == expected     │      │
       │  └───────────────────────────────────┘      │
       │                                             │
       │  VERIFIED: Commitment anchored in Bitcoin   │
       │                                             │
```

## Multi-Provider Anchoring

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Anchor     │    │   Bitcoin    │    │  Ethereum    │    │   Solana     │
│   Manager    │    │   Provider   │    │  Provider    │    │  Provider    │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │                   │
       │  Commitment       │                   │                   │
       │  (priority=High)  │                   │                   │
       │                   │                   │                   │
       │ ══════════════════════════════════════════════════════════════
       │           MULTI-CHAIN ANCHORING (parallel)
       │ ══════════════════════════════════════════════════════════════
       │                   │                   │                   │
       │  submit()         │                   │                   │
       │──────────────────►│                   │                   │
       │                   │                   │                   │
       │  submit()         │                   │                   │
       │───────────────────┼──────────────────►│                   │
       │                   │                   │                   │
       │  submit()         │                   │                   │
       │───────────────────┼───────────────────┼──────────────────►│
       │                   │                   │                   │
       │                   │──┐                │──┐                │──┐
       │                   │  │ Build &        │  │ Build &        │  │ Build &
       │                   │  │ broadcast      │  │ broadcast      │  │ broadcast
       │                   │  │ BTC tx         │  │ ETH tx         │  │ SOL tx
       │                   │◄─┘                │◄─┘                │◄─┘
       │                   │                   │                   │
       │  AnchorTx (BTC)   │                   │                   │
       │◄──────────────────│                   │                   │
       │                   │                   │                   │
       │  AnchorTx (ETH)   │                   │                   │
       │◄──────────────────┼───────────────────│                   │
       │                   │                   │                   │
       │  AnchorTx (SOL)   │                   │                   │
       │◄──────────────────┼───────────────────┼───────────────────│
       │                   │                   │                   │
       │──┐                │                   │                   │
       │  │ Store all      │                   │                   │
       │  │ transactions   │                   │                   │
       │  │ in operation   │                   │                   │
       │◄─┘                │                   │                   │
       │                   │                   │                   │
       │ ══════════════════════════════════════════════════════════════
       │           CONFIRMATION TRACKING (different speeds)
       │ ══════════════════════════════════════════════════════════════
       │                   │                   │                   │
       │                   │                   │  (after ~400ms)   │
       │                   │                   │                   │──┐
       │                   │                   │                   │  │ Solana
       │                   │                   │                   │  │ confirmed
       │                   │                   │                   │◄─┘
       │  SOL confirmed    │                   │                   │
       │◄──────────────────┼───────────────────┼───────────────────│
       │                   │                   │                   │
       │                   │                   │  (after ~15s)     │
       │                   │                   │──┐                │
       │                   │                   │  │ Ethereum       │
       │                   │                   │  │ confirmed      │
       │                   │                   │◄─┘                │
       │  ETH confirmed    │                   │                   │
       │◄──────────────────┼───────────────────│                   │
       │                   │                   │                   │
       │                   │  (after ~60min)   │                   │
       │                   │──┐                │                   │
       │                   │  │ Bitcoin        │                   │
       │                   │  │ 6 confs        │                   │
       │                   │◄─┘                │                   │
       │  BTC confirmed    │                   │                   │
       │◄──────────────────│                   │                   │
       │                   │                   │                   │
       │──┐                │                   │                   │
       │  │ ProofBundle    │                   │                   │
       │  │ complete       │                   │                   │
       │  │ (all 3 chains) │                   │                   │
       │◄─┘                │                   │                   │
```

## Provider Selection Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PROVIDER SELECTION STRATEGIES                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SelectionStrategy::All                                                      │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │  Submit to ALL available providers in parallel                     │      │
│  │  Use case: Maximum redundancy, audit requirements                  │      │
│  │  Cost: Highest (pay for all chains)                                │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                                                              │
│  SelectionStrategy::First                                                    │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │  Submit to highest-priority provider only                          │      │
│  │  Use case: Cost-sensitive, single-chain anchor sufficient          │      │
│  │  Fallback: If fails, try next priority                             │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                                                              │
│  SelectionStrategy::Cheapest                                                 │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │  Estimate costs, select lowest                                     │      │
│  │  Use case: Budget-constrained operations                           │      │
│  │  Note: Cost fluctuates with network congestion                     │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                                                              │
│  SelectionStrategy::Fastest                                                  │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │  Select by confirmation time                                       │      │
│  │  Order: Solana (~400ms) > Ethereum (~15s) > Bitcoin (~60min)      │      │
│  │  Use case: Time-sensitive anchoring                                │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                                                              │
│  SelectionStrategy::ByChain(chains)                                          │
│  ┌───────────────────────────────────────────────────────────────────┐      │
│  │  Submit to specified chains only                                   │      │
│  │  Use case: Regulatory requirements, chain-specific needs           │      │
│  │  Example: ByChain(["bitcoin-mainnet", "ethereum-mainnet"])        │      │
│  └───────────────────────────────────────────────────────────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Scheduler and Batching

```
┌──────────────┐                              ┌──────────────┐
│  Commitments │                              │  Scheduler   │
│  (incoming)  │                              │              │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │  Commitment A (priority=Normal)             │
       │────────────────────────────────────────────►│
       │                                             │──┐
       │                                             │  │ Queue in
       │                                             │  │ Normal bucket
       │                                             │◄─┘
       │                                             │
       │  Commitment B (priority=Normal)             │
       │────────────────────────────────────────────►│
       │                                             │──┐
       │                                             │  │ Add to batch
       │                                             │◄─┘
       │                                             │
       │  Commitment C (priority=Critical)           │
       │────────────────────────────────────────────►│
       │                                             │──┐
       │                                             │  │ Critical!
       │                                             │  │ Process
       │                                             │  │ immediately
       │                                             │◄─┘
       │                                             │
       │                                 ┌───────────┴───────────┐
       │                                 │                       │
       │                                 ▼                       ▼
       │                    ┌────────────────────┐  ┌────────────────────┐
       │                    │  Batch (Normal)    │  │  Immediate         │
       │                    │                    │  │  (Critical)        │
       │                    │  [A, B]            │  │                    │
       │                    │                    │  │  [C]               │
       │                    │  Wait for:         │  │                    │
       │                    │  - max_batch_size  │  │  Process now!      │
       │                    │  - max_batch_wait  │  │                    │
       │                    └────────────────────┘  └────────────────────┘
       │                                             │
       │ ══════════════════════════════════════════════════════
       │           BATCH PROCESSING TRIGGERS
       │ ══════════════════════════════════════════════════════
       │                                             │
       │  Trigger conditions:                        │
       │  1. batch.len() >= max_batch_size (e.g. 10) │
       │  2. elapsed >= max_batch_wait (e.g. 5min)   │
       │  3. priority >= Critical                    │
       │                                             │
       │  When triggered:                            │
       │  - Single Bitcoin tx with multiple OP_RETURN│
       │  - Or sequential submissions                │
       │  - Reduces per-commitment cost              │
       │                                             │
```

## Failure and Recovery

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Anchor     │    │   Provider   │    │  External    │
│   Manager    │    │   Registry   │    │  Chain       │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       │  submit()         │                   │
       │──────────────────►│                   │
       │                   │                   │
       │                   │  submit()         │
       │                   │──────────────────►│
       │                   │                   │
       │                   │    ERROR          │
       │                   │◄──────────────────│
       │                   │  (network failure)│
       │                   │                   │
       │                   │──┐                │
       │                   │  │ record_failure │
       │                   │  │ failures++     │
       │                   │◄─┘                │
       │                   │                   │
       │  Retry (attempt 2)│                   │
       │──────────────────►│                   │
       │                   │  submit()         │
       │                   │──────────────────►│
       │                   │                   │
       │                   │    ERROR          │
       │                   │◄──────────────────│
       │                   │                   │
       │                   │  ... failures = 5 │
       │                   │                   │
       │                   │──┐                │
       │                   │  │ Auto-disable   │
       │                   │  │ provider       │
       │                   │◄─┘                │
       │                   │                   │
       │  Provider disabled│                   │
       │◄──────────────────│                   │
       │                   │                   │
       │ ══════════════════════════════════════════════
       │           FAILOVER TO BACKUP PROVIDER
       │ ══════════════════════════════════════════════
       │                   │                   │
       │  Try next provider│                   │
       │  (backup)         │                   │
       │──────────────────►│                   │
       │                   │  submit()         │
       │                   │──────────────────►│ (different chain)
       │                   │                   │
       │                   │  SUCCESS          │
       │                   │◄──────────────────│
       │                   │                   │
       │  AnchorTx         │                   │
       │◄──────────────────│                   │
       │                   │                   │
       │ ══════════════════════════════════════════════
       │           RECOVERY (health check)
       │ ══════════════════════════════════════════════
       │                   │                   │
       │  (later: health   │                   │
       │   check cycle)    │                   │
       │                   │                   │
       │  health_check()   │                   │
       │──────────────────►│                   │
       │                   │  test_connection()│
       │                   │──────────────────►│
       │                   │                   │
       │                   │  SUCCESS          │
       │                   │◄──────────────────│
       │                   │                   │
       │                   │──┐                │
       │                   │  │ Re-enable      │
       │                   │  │ provider       │
       │                   │  │ reset failures │
       │                   │◄─┘                │
       │                   │                   │
       │  Provider restored│                   │
       │◄──────────────────│                   │
```

## Anchoring Lifecycle States

```
                    ┌─────────────────┐
                    │     QUEUED      │
                    │                 │
                    │ In scheduler    │
                    │ waiting batch   │
                    └────────┬────────┘
                             │
                             │ Batch ready / Critical priority
                             ▼
                    ┌─────────────────┐
                    │   SUBMITTING    │
                    │                 │
                    │ Sending to      │
                    │ providers       │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼ all fail       ▼ some succeed   ▼ all succeed
   ┌─────────────────┐      │        ┌─────────────────┐
   │     FAILED      │      │        │    PENDING      │
   │                 │      │        │                 │
   │ Max retries     │      │        │ Waiting for     │
   │ exceeded        │      │        │ confirmations   │
   └─────────────────┘      │        └────────┬────────┘
                            │                 │
                            │                 │ required_confirmations
                            │                 ▼
                            │        ┌─────────────────┐
                            │        │   CONFIRMED     │
                            │        │                 │
                            │        │ Has proofs from │
                            │        │ ≥1 provider     │
                            │        └────────┬────────┘
                            │                 │
                            │                 │ finality_threshold
                            │                 ▼
                            │        ┌─────────────────┐
                            └───────►│   FINALIZED     │
                                     │                 │
                                     │ Cannot be       │
                                     │ reversed        │
                                     └─────────────────┘
```
