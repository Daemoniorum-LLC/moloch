//! # Moloch HoloCrypt Integration
//!
//! Advanced cryptographic features for the Moloch audit chain.
//!
//! ## Features
//!
//! - **Encrypted Events**: Wrap AuditEvents in HoloCrypt containers
//! - **Selective Encryption**: Encrypt specific fields while keeping others public
//! - **Zero-Knowledge Proofs**: Prove event properties without revealing content
//! - **Threshold Decryption**: k-of-n access control with FROST
//! - **Post-Quantum Security**: ML-KEM envelope encryption
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    ENCRYPTED AUDIT EVENT                            │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ PUBLIC HEADER                                                  │  │
//! │  │  - Event ID (hash of encrypted content)                        │  │
//! │  │  - Timestamp                                                   │  │
//! │  │  - Actor ID (optional, may be encrypted)                       │  │
//! │  │  - Resource ID (optional, may be encrypted)                    │  │
//! │  │  - Encryption metadata                                         │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ HOLOCRYPT CONTAINER                                            │  │
//! │  │  - Encrypted event payload                                     │  │
//! │  │  - Commitment to plaintext                                     │  │
//! │  │  - Merkle root for selective disclosure                        │  │
//! │  │  - Ed25519 + ML-DSA signature                                  │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! │                                                                      │
//! │  ┌───────────────────────────────────────────────────────────────┐  │
//! │  │ ACCESS CONTROL                                                 │  │
//! │  │  - PQC envelope (ML-KEM-768)                                   │  │
//! │  │  - OR threshold shares (k-of-n FROST)                          │  │
//! │  └───────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod encrypted;
pub mod errors;
pub mod pqc;
pub mod proofs;
pub mod threshold;

pub use encrypted::{
    generate_keypair, EncryptedEvent, EncryptedEventBuilder, EncryptionPolicy, EventOpeningKey,
    EventSealingKey, FieldVisibility,
};
pub use errors::{HoloCryptError, Result};
pub use pqc::{EventPqcKeyPair, HybridEncryption, PqcEvent, QuantumSafeEvent};
pub use proofs::{EventProof, ProofType, PropertyAssertion};
pub use threshold::{KeyShareSet, ThresholdConfig, ThresholdEvent};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::encrypted::{
        EncryptedEvent, EncryptedEventBuilder, EncryptionPolicy, FieldVisibility,
    };
    pub use crate::errors::{HoloCryptError, Result};
    pub use crate::pqc::{HybridEncryption, PqcEvent, QuantumSafeEvent};
    pub use crate::proofs::{EventProof, ProofType, PropertyAssertion};
    pub use crate::threshold::{KeyShareSet, ThresholdConfig, ThresholdEvent};
}
