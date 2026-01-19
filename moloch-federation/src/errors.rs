//! Error types for federation operations.

use thiserror::Error;

/// Result type for federation operations.
pub type Result<T> = std::result::Result<T, FederationError>;

/// Errors that can occur in federation operations.
#[derive(Debug, Error)]
pub enum FederationError {
    /// Chain not found in registry.
    #[error("chain not found: {0}")]
    ChainNotFound(String),

    /// Chain already registered.
    #[error("chain already registered: {0}")]
    ChainAlreadyRegistered(String),

    /// Invalid chain configuration.
    #[error("invalid chain config: {0}")]
    InvalidConfig(String),

    /// Bridge connection failed.
    #[error("bridge connection failed: {0}")]
    BridgeConnectionFailed(String),

    /// Proof verification failed.
    #[error("proof verification failed: {0}")]
    ProofVerificationFailed(String),

    /// Event not found on source chain.
    #[error("event not found: {0}")]
    EventNotFound(String),

    /// Cross-chain reference invalid.
    #[error("invalid cross-chain reference: {0}")]
    InvalidReference(String),

    /// Trust level insufficient.
    #[error("insufficient trust level for chain {chain}: required {required:?}, got {actual:?}")]
    InsufficientTrust {
        /// Chain ID.
        chain: String,
        /// Required trust level.
        required: super::TrustLevel,
        /// Actual trust level.
        actual: super::TrustLevel,
    },

    /// Routing error.
    #[error("routing error: {0}")]
    RoutingError(String),

    /// Finality not reached.
    #[error("finality not reached on chain {chain} at height {height}")]
    FinalityNotReached {
        /// Chain ID.
        chain: String,
        /// Block height.
        height: u64,
    },

    /// Light client error.
    #[error("light client error: {0}")]
    LightClient(#[from] moloch_light::LightClientError),

    /// Core error.
    #[error("core error: {0}")]
    Core(#[from] moloch_core::Error),
}
