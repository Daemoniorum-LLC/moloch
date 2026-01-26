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

pub mod agile;
pub mod composite;
pub mod encrypted;
pub mod frost;
pub mod proofs;
pub mod threshold;
pub mod pqc;
pub mod errors;

pub use agile::{
    AgileConfig, AgileEncryptedEvent, SignatureAlgorithm, HashAlgorithm, MigrationInfo,
};
pub use composite::{
    CompositeSigningKey, CompositeVerifyingKey, CompositeSignature,
};
pub use frost::{
    FrostConfig, FrostCoordinator, FrostParticipant, FrostSignature, FrostSignedEvent,
    FrostSigningCeremony, CeremonyState,
};
pub use encrypted::{
    EncryptedEvent, EncryptedEventBuilder, EncryptionPolicy, FieldVisibility,
    generate_keypair, EventSealingKey, EventOpeningKey,
};
pub use proofs::{EventProof, ProofType, PropertyAssertion};
pub use threshold::{ThresholdEvent, KeyShareSet, ThresholdConfig};
pub use pqc::{PqcEvent, HybridEncryption, QuantumSafeEvent, EventPqcKeyPair};
pub use errors::{HoloCryptError, Result};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::agile::{AgileConfig, AgileEncryptedEvent, SignatureAlgorithm, HashAlgorithm};
    pub use crate::composite::{CompositeSigningKey, CompositeVerifyingKey, CompositeSignature};
    pub use crate::encrypted::{EncryptedEvent, EncryptedEventBuilder, EncryptionPolicy, FieldVisibility};
    pub use crate::frost::{FrostConfig, FrostCoordinator, FrostParticipant, FrostSignature, FrostSignedEvent};
    pub use crate::proofs::{EventProof, ProofType, PropertyAssertion};
    pub use crate::threshold::{ThresholdEvent, KeyShareSet, ThresholdConfig};
    pub use crate::pqc::{PqcEvent, HybridEncryption, QuantumSafeEvent};
    pub use crate::errors::{HoloCryptError, Result};
}
