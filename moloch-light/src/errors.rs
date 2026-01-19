//! Error types for the light client.

use thiserror::Error;

/// Result type for light client operations.
pub type Result<T> = std::result::Result<T, LightClientError>;

/// Errors that can occur in light client operations.
#[derive(Debug, Error)]
pub enum LightClientError {
    /// Header validation failed.
    #[error("invalid header at height {height}: {reason}")]
    InvalidHeader {
        /// Block height.
        height: u64,
        /// Reason for invalidity.
        reason: String,
    },

    /// Proof verification failed.
    #[error("proof verification failed: {0}")]
    InvalidProof(String),

    /// Chain fork detected.
    #[error("chain fork detected at height {height}")]
    ForkDetected {
        /// Height where fork was detected.
        height: u64,
    },

    /// Missing header in chain.
    #[error("missing header at height {0}")]
    MissingHeader(u64),

    /// Checkpoint validation failed.
    #[error("checkpoint validation failed: {0}")]
    InvalidCheckpoint(String),

    /// Sync error.
    #[error("sync error: {0}")]
    SyncError(String),

    /// Network error.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Storage error.
    #[error("storage error: {0}")]
    StorageError(String),

    /// Validator set mismatch.
    #[error("validator set mismatch at height {height}")]
    ValidatorMismatch {
        /// Block height.
        height: u64,
    },

    /// Insufficient signatures for finality.
    #[error("insufficient signatures: got {got}, need {need}")]
    InsufficientSignatures {
        /// Number of signatures received.
        got: usize,
        /// Number of signatures required.
        need: usize,
    },

    /// Core error from moloch-core.
    #[error("core error: {0}")]
    CoreError(#[from] moloch_core::Error),
}
