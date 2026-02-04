# Known Issues & Limitations

**Version:** 0.1.0
**Last Updated:** 2026-02-03

This document exists because we believe in radical transparency. If you find
something not listed here, please open an issue or email security@daemoniorum.com
for security-sensitive findings.

---

## Dependency Advisories

`cargo audit` reports **0 vulnerabilities** and **5 informational warnings**.
None are exploitable in Moloch's usage, but we list them here for completeness.

| Crate | Advisory | Severity | Source | Notes |
|-------|----------|----------|--------|-------|
| `lru` 0.12.5 | [RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002) | Unsound | Transitive via `arcanum-core` | `IterMut` violates Stacked Borrows. Moloch does not call `iter_mut()` on any LRU cache. Fix requires upstream Arcanum update. |
| `bincode` 1.3.3 | [RUSTSEC-2025-0141](https://rustsec.org/advisories/RUSTSEC-2025-0141) | Unmaintained | Direct dependency | bincode v1 is unmaintained. Migration to bincode v2 is a breaking API change tracked for a future release. |
| `atomic-polyfill` 1.0.3 | [RUSTSEC-2023-0089](https://rustsec.org/advisories/RUSTSEC-2023-0089) | Unmaintained | Transitive via `frost-core` -> `heapless` | No action available; awaiting upstream update in FROST threshold library. |
| `derivative` 2.2.0 | [RUSTSEC-2024-0388](https://rustsec.org/advisories/RUSTSEC-2024-0388) | Unmaintained | Transitive via `alloy` -> `ruint` -> `ark-ff` | No action available; pulled in by Ethereum anchoring dependencies. |
| `paste` 1.0.15 | [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436) | Unmaintained | Transitive via `alloy` -> `ruint` -> `ark-ff` | Same dependency chain as `derivative`. |

To verify: `cargo audit` in the repository root.

---

## Incomplete Features (Dead Code Present)

The following features have scaffolding code (`#[allow(dead_code)]`) but are not
yet implemented. They are documented in detail in
[docs/developer/SPEC_GAPS.md](docs/developer/SPEC_GAPS.md).

### Mempool Event Expiration
- **Location:** `moloch-chain/src/concurrent_mempool.rs`
- **Status:** `EventMeta` struct exists with `added_at` and `priority` fields, but TTL-based eviction is not wired up.
- **Impact:** The mempool grows without bound. For production use, external size management is needed until this is implemented.

### Bitcoin SPV Verification
- **Location:** `moloch-anchor-bitcoin/src/tx.rs`
- **Status:** `verify_merkle_proof()` function exists but is not integrated into the anchor verification flow.
- **Impact:** Bitcoin anchor verification currently trusts the RPC provider. SPV-level independent verification is not yet available.

### Sync Protocol State Machine
- **Location:** `moloch-net/src/sync.rs`
- **Status:** `PendingRequest` and `RequestKind` types exist but the state machine (fast sync, snap sync, catch-up, warp sync) is not implemented.
- **Impact:** Node synchronization works for single-node and test scenarios. Multi-node catch-up sync is not production-ready.

### Snapshot Builder
- **Location:** `moloch-storage/src/snapshot.rs`
- **Status:** `SnapshotBuilder` has configuration setters but no `build()` method.
- **Impact:** State snapshots for fast sync cannot be created yet.

---

## Premature Abstractions (Scheduled for Removal)

The following code exists without specification backing and is scheduled for
cleanup. It compiles but serves no functional purpose.

| Location | What | Why It Exists |
|----------|------|---------------|
| `moloch-anchor/src/mock.rs` | Unused `tx_id`, `submitted_at` fields in `MockTransaction` | Speculative fields added during initial development |
| `moloch-anchor/src/registry.rs` | `ProviderRegistry` multi-provider abstraction | Over-engineering; direct provider injection is sufficient |
| `moloch-storage/src/mmap.rs` | `MmapStorage` alternative backend | RocksDB is the specified backend; mmap was exploratory |
| `moloch-core/src/merkle.rs` | `MerkleTreeBuffer` optimization | Premature optimization without benchmark justification |
| `moloch-anchor/src/scheduler.rs` | `queued_at` field in `QueuedRequest` | Deadline handling not specified |
| `moloch-federation/src/bridge.rs` | `PendingRequest` federation tracking | Federation protocol not fully specified |

---

## Cryptographic Caveats

### Zero-Knowledge Proofs
Moloch's ZK proofs are **hash-based commitment schemes** using BLAKE3, not
zkSNARKs or zkSTARKs. This is a deliberate design choice:

- **What they prove:** That a party knows the preimage of a commitment (existence proof), that an event has a specific type (type proof), or that an actor belongs to a set (membership proof).
- **What they do NOT provide:** General-purpose programmable zero-knowledge computation. You cannot write arbitrary ZK circuits.
- **Trust model:** The prover must have access to the original plaintext to generate proofs. Proofs are non-interactive and publicly verifiable.
- **Why this approach:** Sub-2 microsecond proof generation makes them practical for high-throughput audit chains where the alternative is no privacy at all. Full zkSNARK proofs would add 5-6 orders of magnitude latency.

### Post-Quantum Encryption (ML-KEM-768)
- ML-KEM-768 is standardized as [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (August 2024).
- It provides NIST Level 3 security (equivalent to AES-192).
- As a relatively new standard, real-world cryptanalysis is still maturing. We use it as a defense-in-depth layer, not as a sole encryption mechanism.
- Post-quantum encryption is applied via the `QuantumSafeEvent` API and is opt-in, not default.

### Threshold Encryption
- Built on Shamir's Secret Sharing via the FROST protocol (RFC 9591).
- Share distribution is the caller's responsibility. Moloch does not include a secure share transport mechanism.

### Signature Scheme
- Ed25519 only. No support for secp256k1, ECDSA, or other curves.
- Batch verification is available but uses the same underlying curve operations (not aggregate signatures).

---

## Consensus Limitations

Moloch uses **Proof of Authority (Aura-style)** consensus:

- **Permissioned by design.** Validators are configured, not elected. This is intentional for enterprise audit chains where validator identity matters.
- **BFT threshold:** Requires 2/3 + 1 honest validators. A 1/3 Byzantine coalition can halt the chain (liveness failure) but cannot forge events (safety holds).
- **No economic incentives.** There is no staking, slashing, or block rewards. Validators are expected to be organizationally motivated.
- **Single-chain only.** No sharding or parallel execution.

---

## Documentation Gaps

- **19 ignored doc-tests** across the codebase. These are examples in doc comments that require runtime resources (RocksDB, network) and are skipped in CI. They are syntactically valid but not executed.
- **API examples in the README are illustrative.** They show the conceptual API shape but may not match exact function signatures. See the crate-level documentation (`cargo doc --open`) for precise API reference.
- **No `cargo-deny` configuration.** We use `cargo audit` for vulnerability scanning but do not yet have a `deny.toml` for license or duplicate dependency enforcement.

---

## Platform Notes

- **Primary development platform:** Linux (WSL2) with AVX-512 capable CPU.
- **RocksDB required:** The `moloch-storage` crate links against RocksDB. You need RocksDB development headers installed (`librocksdb-dev` on Debian/Ubuntu, `rocksdb` on Homebrew).
- **SIMD performance:** Benchmark numbers in `BENCHMARK_REPORT.md` were captured with `RUSTFLAGS="-C target-cpu=native"` on an AVX-512 capable CPU. Performance on ARM or non-AVX hardware will differ.
- **Allocator:** Benchmarks use `mimalloc`. Production deployments should also use `mimalloc` for best performance; the system allocator works but is measurably slower.

---

## Build Reproducibility

- Rust toolchain is pinned via `rust-toolchain.toml` (channel `1.89`).
- `Cargo.lock` is committed for reproducible builds.
- External dependency on [Arcanum](https://github.com/Daemoniorum-LLC/arcanum) cryptographic library (published to crates.io).

---

## Reporting Issues

- **Security vulnerabilities:** email security@daemoniorum.com (see [SECURITY.md](SECURITY.md))
- **Bugs and feature requests:** [GitHub Issues](https://github.com/Daemoniorum-LLC/moloch/issues)
- **Questions:** [GitHub Discussions](https://github.com/Daemoniorum-LLC/moloch/discussions)
