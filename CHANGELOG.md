# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-19

### Added

- Initial open source release
- Core event and block types with Ed25519 signatures
- Merkle Mountain Range (MMR) accumulator
- RocksDB storage with memory-mapped file support
- Zero-copy serialization via rkyv
- Indexes by actor, resource, time, event type
- Zero-knowledge proofs for event existence and actor membership
- HoloCrypt selective field encryption
- Post-quantum encryption with ML-KEM-768
- Threshold encryption (k-of-n schemes)
- Bitcoin anchoring via OP_RETURN
- Ethereum anchoring via calldata
- REST/WebSocket API with JWT authentication
- Aura-style Proof of Authority consensus
- Light client verification
- Cross-chain federation support
