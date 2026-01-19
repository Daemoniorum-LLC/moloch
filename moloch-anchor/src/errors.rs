//! Error types for the anchor layer.

use thiserror::Error;

/// Result type for anchor operations.
pub type Result<T> = std::result::Result<T, AnchorError>;

/// Errors that can occur during anchoring operations.
#[derive(Debug, Error)]
pub enum AnchorError {
    /// Provider not found.
    #[error("provider not found: {0}")]
    ProviderNotFound(String),

    /// Provider not available.
    #[error("provider not available: {0}")]
    ProviderUnavailable(String),

    /// Provider already registered.
    #[error("provider already registered: {0}")]
    ProviderAlreadyRegistered(String),

    /// Submission failed.
    #[error("anchor submission failed: {0}")]
    SubmissionFailed(String),

    /// Verification failed.
    #[error("anchor verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid commitment.
    #[error("invalid commitment: {0}")]
    InvalidCommitment(String),

    /// Invalid proof.
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    /// Transaction not found.
    #[error("transaction not found: {0}")]
    TransactionNotFound(String),

    /// Insufficient confirmations.
    #[error("insufficient confirmations: got {got}, need {need}")]
    InsufficientConfirmations {
        /// Confirmations received.
        got: u64,
        /// Confirmations required.
        need: u64,
    },

    /// Cost estimation failed.
    #[error("cost estimation failed: {0}")]
    CostEstimationFailed(String),

    /// Network error.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Timeout.
    #[error("operation timed out after {0} seconds")]
    Timeout(u64),

    /// Rate limited.
    #[error("rate limited by provider: {0}")]
    RateLimited(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Core error.
    #[error("core error: {0}")]
    Core(#[from] moloch_core::Error),

    /// No providers available.
    #[error("no anchor providers available")]
    NoProvidersAvailable,

    /// All providers failed.
    #[error("all anchor providers failed")]
    AllProvidersFailed,

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Transaction not found (alias).
    #[error("transaction not found: {0}")]
    TxNotFound(String),
}
