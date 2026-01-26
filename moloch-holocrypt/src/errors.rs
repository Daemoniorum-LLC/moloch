//! Error types for Moloch HoloCrypt integration.

use thiserror::Error;

/// Result type for HoloCrypt operations.
pub type Result<T> = std::result::Result<T, HoloCryptError>;

/// Errors that can occur during HoloCrypt operations.
#[derive(Debug, Error)]
pub enum HoloCryptError {
    /// Failed to encrypt event.
    #[error("encryption failed: {reason}")]
    EncryptionFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Failed to decrypt event.
    #[error("decryption failed: {reason}")]
    DecryptionFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Commitment does not match decrypted data.
    #[error("commitment mismatch - data may have been tampered")]
    CommitmentMismatch,

    /// Merkle proof verification failed.
    #[error("merkle proof verification failed: {reason}")]
    MerkleProofInvalid {
        /// Reason for failure.
        reason: String,
    },

    /// Zero-knowledge proof verification failed.
    #[error("ZK proof verification failed: {reason}")]
    ZkProofInvalid {
        /// Reason for failure.
        reason: String,
    },

    /// Not enough threshold shares provided.
    #[error("insufficient shares: need {required}, got {provided}")]
    InsufficientShares {
        /// Required number of shares.
        required: usize,
        /// Number of shares provided.
        provided: usize,
    },

    /// Failed to reconstruct key from shares.
    #[error("key reconstruction failed: {reason}")]
    KeyReconstructionFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Invalid share provided.
    #[error("invalid share: {reason}")]
    InvalidShare {
        /// Reason for invalidity.
        reason: String,
    },

    /// Post-quantum key encapsulation failed.
    #[error("PQC encapsulation failed: {reason}")]
    PqcEncapsulationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Post-quantum key decapsulation failed.
    #[error("PQC decapsulation failed: {reason}")]
    PqcDecapsulationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Invalid configuration.
    #[error("invalid configuration: {reason}")]
    InvalidConfiguration {
        /// Reason for invalidity.
        reason: String,
    },

    /// Key not found.
    #[error("key not found: {key_id}")]
    KeyNotFound {
        /// Key identifier.
        key_id: String,
    },

    /// Key expired.
    #[error("key expired: {key_id}")]
    KeyExpired {
        /// Key identifier.
        key_id: String,
    },

    /// Unsupported encryption policy.
    #[error("unsupported encryption policy: {policy}")]
    UnsupportedPolicy {
        /// Policy name.
        policy: String,
    },

    /// Field not available for disclosure.
    #[error("field not available: {field}")]
    FieldNotAvailable {
        /// Field name.
        field: String,
    },

    /// Underlying crypto error.
    #[error("crypto error: {reason}")]
    CryptoError {
        /// Reason for failure.
        reason: String,
    },

    /// Event validation failed.
    #[error("event validation failed: {reason}")]
    ValidationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Composite signature verification failed.
    #[error("composite signature invalid: {component} component failed")]
    CompositeSignatureInvalid {
        /// Which component failed.
        component: String,
    },

    /// FROST signing round failed.
    #[error("FROST round {round} failed: {reason}")]
    FrostRoundFailed {
        /// Which round failed.
        round: u8,
        /// Reason for failure.
        reason: String,
    },

    /// Insufficient FROST participants.
    #[error("insufficient FROST participants: need {required}, got {provided}")]
    InsufficientFrostParticipants {
        /// Required number of participants.
        required: u16,
        /// Number of participants provided.
        provided: u16,
    },
}

impl From<arcanum_holocrypt::HoloCryptError> for HoloCryptError {
    fn from(err: arcanum_holocrypt::HoloCryptError) -> Self {
        HoloCryptError::CryptoError {
            reason: err.to_string(),
        }
    }
}

impl From<serde_json::Error> for HoloCryptError {
    fn from(err: serde_json::Error) -> Self {
        HoloCryptError::SerializationError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = HoloCryptError::EncryptionFailed {
            reason: "invalid key".to_string(),
        };
        assert!(err.to_string().contains("encryption failed"));
        assert!(err.to_string().contains("invalid key"));
    }

    #[test]
    fn test_insufficient_shares_error() {
        let err = HoloCryptError::InsufficientShares {
            required: 3,
            provided: 2,
        };
        assert!(err.to_string().contains("need 3"));
        assert!(err.to_string().contains("got 2"));
    }
}
