# Consensus Protocol Sequence Diagrams

Sequence diagrams for Moloch's Proof-of-Authority (PoA) consensus.

## Normal Block Production

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
│ Validator1 │  │ Validator2 │  │ Validator3 │  │ Validator4 │
│ (Proposer) │  │            │  │            │  │            │
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │               │               │               │
      │ ══════════════════════════════════════════════════════
      │               ROUND N: V1 is proposer (N mod 4 = 1)
      │ ══════════════════════════════════════════════════════
      │               │               │               │
      │──┐            │               │               │
      │  │ Build block from mempool   │               │
      │  │ - Collect pending events   │               │
      │  │ - Compute events_root      │               │
      │  │ - Sign block header        │               │
      │◄─┘            │               │               │
      │               │               │               │
      │   Proposal    │               │               │
      │──────────────►│               │               │
      │   (Block)     │               │               │
      │───────────────┼──────────────►│               │
      │               │               │               │
      │───────────────┼───────────────┼──────────────►│
      │               │               │               │
      │               │──┐            │               │
      │               │  │ Validate:  │               │
      │               │  │ - proposer │               │
      │               │  │ - parent   │               │
      │               │  │ - events   │               │
      │               │◄─┘            │               │
      │               │               │               │
      │               │               │──┐            │
      │               │               │  │ Validate   │
      │               │               │◄─┘            │
      │               │               │               │
      │               │               │               │──┐
      │               │               │               │  │ Validate
      │               │               │               │◄─┘
      │               │               │               │
      │     Vote      │               │               │
      │◄──────────────│               │               │
      │  (sig on hash)│               │               │
      │               │               │               │
      │◄──────────────┼───────────────│               │
      │     Vote      │               │               │
      │               │               │               │
      │◄──────────────┼───────────────┼───────────────│
      │     Vote      │               │               │
      │               │               │               │
      │──┐            │               │               │
      │  │ Collect votes (3/4 ≥ 2/3+1)│               │
      │  │ Block FINALIZED            │               │
      │◄─┘            │               │               │
      │               │               │               │
      │  Finalized    │               │               │
      │──────────────►│               │               │
      │  (block+sigs) │               │               │
      │───────────────┼──────────────►│               │
      │───────────────┼───────────────┼──────────────►│
      │               │               │               │
      │──┐            │──┐            │──┐            │──┐
      │  │ Commit     │  │ Commit     │  │ Commit     │  │ Commit
      │  │ to storage │  │ to storage │  │ to storage │  │ to storage
      │◄─┘            │◄─┘            │◄─┘            │◄─┘
      │               │               │               │
      │ ══════════════════════════════════════════════════════
      │               ROUND N+1: V2 is proposer
      │ ══════════════════════════════════════════════════════
```

## Proposer Rotation

```
Round-Robin Selection:

Round 0:  proposer = validators[0 mod 4] = V1
Round 1:  proposer = validators[1 mod 4] = V2
Round 2:  proposer = validators[2 mod 4] = V3
Round 3:  proposer = validators[3 mod 4] = V4
Round 4:  proposer = validators[4 mod 4] = V1  (cycles back)
...

Timeline:
─────────────────────────────────────────────────────────────────────►
│         │         │         │         │         │         │
│  V1     │  V2     │  V3     │  V4     │  V1     │  V2     │
│ Block 0 │ Block 1 │ Block 2 │ Block 3 │ Block 4 │ Block 5 │
│         │         │         │         │         │         │
◄─ slot ─►◄─ slot ─►◄─ slot ─►◄─ slot ─►◄─ slot ─►◄─ slot ─►
   1s        1s        1s        1s        1s        1s
```

## Missed Slot Handling

```
┌────────────┐  ┌────────────┐  ┌────────────┐
│ Validator1 │  │ Validator2 │  │ Validator3 │
│ (Proposer) │  │ (Backup)   │  │            │
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │               │               │
      │ ══════════════════════════════════════
      │          ROUND N: V1 should propose
      │ ══════════════════════════════════════
      │               │               │
      ╳               │               │
 (V1 offline)         │               │
                      │               │
      │    ...timeout (slot_time)...  │
      │               │               │
      │ ══════════════════════════════════════
      │          ROUND N+1: V2 is proposer
      │ ══════════════════════════════════════
      │               │               │
                      │──┐            │
                      │  │ Build block│
                      │  │ height=N+1 │
                      │  │ (skips N)  │
                      │◄─┘            │
                      │               │
                      │   Proposal    │
                      │──────────────►│
                      │               │
                      │    ...        │
                      │               │

Note: Heights are NOT skipped, only time slots.
      If V1 misses its slot, V2 proposes the next block.
      Block heights remain consecutive: ..., N-1, N, N+1, ...
```

## Byzantine Validator Detection

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
│     V1     │  │     V2     │  │     V3     │  │     V4     │
│ (Proposer) │  │            │  │            │  │(Byzantine) │
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │               │               │               │
      │──────────────────────────────────────────────►│
      │               Proposal (Block A)              │
      │──────────────►│               │               │
      │───────────────┼──────────────►│               │
      │               │               │               │
      │               │               │               │──┐
      │               │               │               │  │ Creates
      │               │               │               │  │ Block A'
      │               │               │               │  │ (conflicting)
      │               │               │               │◄─┘
      │               │               │               │
      │               │◄──────────────┼───────────────│
      │               │  Proposal A'  │               │
      │               │  (same height)│               │
      │               │               │               │
      │               │               │               │
      │               │──┐            │               │
      │               │  │ DETECT:    │               │
      │               │  │ Two blocks │               │
      │               │  │ same height│               │
      │               │  │ from V4    │               │
      │               │  │            │               │
      │               │  │ ACTION:    │               │
      │               │  │ - Log      │               │
      │               │  │ - Report   │               │
      │               │  │ - Ignore A'│               │
      │               │◄─┘            │               │
      │               │               │               │
      │     Vote for original block (A)               │
      │◄──────────────│               │               │
      │◄──────────────┼───────────────│               │
      │               │               │               │
      │──┐            │               │               │
      │  │ Finalize A │               │               │
      │  │ (2/3+1 = 3)│               │               │
      │◄─┘            │               │               │

Byzantine behavior detected but consensus proceeds with honest majority.
```

## Finality Threshold Calculation

```
Given N validators, Byzantine fault tolerance requires:

    Honest validators ≥ 2N/3 + 1

For finality, need signatures from:

    Threshold = floor(2N/3) + 1

Examples:
┌─────────────┬────────────┬──────────────────────┐
│ Validators  │ Threshold  │ Can tolerate         │
├─────────────┼────────────┼──────────────────────┤
│ N = 3       │ 3 (all)    │ 0 Byzantine          │
│ N = 4       │ 3          │ 1 Byzantine          │
│ N = 7       │ 5          │ 2 Byzantine          │
│ N = 10      │ 7          │ 3 Byzantine          │
│ N = 100     │ 67         │ 33 Byzantine         │
└─────────────┴────────────┴──────────────────────┘

Safety: Block finalized only with threshold signatures
Liveness: Progress if < N/3 Byzantine
```

## Validator Set Changes

```
┌────────────────────────────────────────────────────────────────────┐
│                         EPOCH N                                     │
│                                                                     │
│   Validators: [V1, V2, V3, V4]                                     │
│   Threshold: 3                                                      │
│                                                                     │
│   Block 100 ─── Block 101 ─── Block 102 ─── ... ─── Block 199      │
└────────────────────────────────────────────────────────────────────┘
                                                          │
                                                          │ Epoch boundary
                                                          │ (every 100 blocks)
                                                          ▼
┌────────────────────────────────────────────────────────────────────┐
│                         EPOCH N+1                                   │
│                                                                     │
│   ValidatorSetChange in Block 200:                                 │
│   - Remove: V4                                                      │
│   - Add: V5, V6                                                     │
│                                                                     │
│   New Validators: [V1, V2, V3, V5, V6]                             │
│   New Threshold: 4                                                  │
│                                                                     │
│   Block 200 ─── Block 201 ─── Block 202 ─── ... ─── Block 299      │
└────────────────────────────────────────────────────────────────────┘

Validator set changes take effect at epoch boundaries.
Light clients track validators_hash to verify finality.
```

## Message Types

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CONSENSUS MESSAGES                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Proposal                                                            │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ block: Block {                                               │    │
│  │   header: BlockHeader {                                      │    │
│  │     height: u64,                                             │    │
│  │     parent_hash: BlockHash,                                  │    │
│  │     events_root: Hash,                                       │    │
│  │     mmr_root: Hash,                                          │    │
│  │     timestamp: i64,                                          │    │
│  │     proposer: PublicKey,                                     │    │
│  │   },                                                         │    │
│  │   events: Vec<AuditEvent>,                                   │    │
│  │   signature: Sig,  // proposer's signature                   │    │
│  │ }                                                            │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Vote                                                                │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ block_hash: BlockHash,                                       │    │
│  │ height: u64,                                                 │    │
│  │ validator: PublicKey,                                        │    │
│  │ signature: Sig,  // validator's signature on block_hash      │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Finalized                                                           │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ block: Block,                                                │    │
│  │ signatures: Vec<(PublicKey, Sig)>,  // 2/3+1 signatures     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## State Machine

```
                    ┌─────────────────┐
                    │     IDLE        │
                    │                 │
                    │ Waiting for     │
                    │ slot time       │
                    └────────┬────────┘
                             │
                             │ Slot timer fires
                             │
                             ▼
              ┌──────────────────────────────┐
              │       AM I PROPOSER?         │
              └──────────────┬───────────────┘
                             │
            ┌────────────────┴────────────────┐
            │                                 │
            ▼ Yes                             ▼ No
┌───────────────────────┐         ┌───────────────────────┐
│      PROPOSING        │         │   WAITING_PROPOSAL    │
│                       │         │                       │
│ - Build block         │         │ - Wait for proposal   │
│ - Sign header         │         │ - Timeout: next slot  │
│ - Broadcast proposal  │         │                       │
└───────────┬───────────┘         └───────────┬───────────┘
            │                                 │
            │                                 │ Receive proposal
            │                                 ▼
            │                     ┌───────────────────────┐
            │                     │     VALIDATING        │
            │                     │                       │
            │                     │ - Verify proposer     │
            │                     │ - Verify parent       │
            │                     │ - Verify events       │
            │                     │ - Verify signature    │
            │                     └───────────┬───────────┘
            │                                 │
            │                                 │ Valid
            │                                 ▼
            │                     ┌───────────────────────┐
            │                     │       VOTING          │
            │                     │                       │
            │                     │ - Sign block hash     │
            │                     │ - Broadcast vote      │
            │                     └───────────┬───────────┘
            │                                 │
            └─────────────┬───────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   COLLECTING_VOTES    │
              │                       │
              │ - Receive votes       │
              │ - Check threshold     │
              └───────────┬───────────┘
                          │
                          │ 2/3+1 votes collected
                          ▼
              ┌───────────────────────┐
              │      FINALIZING       │
              │                       │
              │ - Create finalized    │
              │   block with sigs     │
              │ - Commit to storage   │
              │ - Update chain state  │
              │ - Broadcast finalized │
              └───────────┬───────────┘
                          │
                          │
                          ▼
                    ┌─────────────────┐
                    │     IDLE        │
                    │                 │
                    │ (next round)    │
                    └─────────────────┘
```
