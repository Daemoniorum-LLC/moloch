//! Error types for Ethereum anchoring.

use thiserror::Error;

/// Result type for Ethereum operations.
pub type Result<T> = std::result::Result<T, EthereumError>;

/// Errors that can occur during Ethereum anchoring.
#[derive(Debug, Error)]
pub enum EthereumError {
    /// RPC connection error.
    #[error("RPC connection failed: {0}")]
    RpcConnection(String),

    /// RPC call error.
    #[error("RPC call failed: {0}")]
    RpcCall(String),

    /// Invalid private key.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Insufficient funds.
    #[error("insufficient funds: need {need} wei, have {have} wei")]
    InsufficientFunds {
        /// Amount needed.
        need: String,
        /// Amount available.
        have: String,
    },

    /// Transaction building error.
    #[error("transaction building failed: {0}")]
    TxBuild(String),

    /// Transaction broadcast error.
    #[error("transaction broadcast failed: {0}")]
    Broadcast(String),

    /// Transaction not found.
    #[error("transaction not found: {0}")]
    TxNotFound(String),

    /// Block not found.
    #[error("block not found: {0}")]
    BlockNotFound(String),

    /// Invalid transaction hash.
    #[error("invalid transaction hash: {0}")]
    InvalidTxHash(String),

    /// Invalid address.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Network mismatch.
    #[error("network mismatch: expected chain {expected}, got {got}")]
    NetworkMismatch {
        /// Expected chain ID.
        expected: u64,
        /// Actual chain ID.
        got: u64,
    },

    /// Wallet error.
    #[error("wallet error: {0}")]
    Wallet(String),

    /// Gas estimation error.
    #[error("gas estimation failed: {0}")]
    GasEstimation(String),

    /// Contract error.
    #[error("contract error: {0}")]
    Contract(String),

    /// Invalid calldata.
    #[error("invalid calldata: {0}")]
    InvalidCalldata(String),

    /// Receipt not found.
    #[error("transaction receipt not found: {0}")]
    ReceiptNotFound(String),

    /// Transaction reverted.
    #[error("transaction reverted: {0}")]
    Reverted(String),

    /// Timeout.
    #[error("operation timed out after {0} seconds")]
    Timeout(u64),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Core error.
    #[error("core error: {0}")]
    Core(#[from] moloch_core::Error),

    /// Anchor error.
    #[error("anchor error: {0}")]
    Anchor(#[from] moloch_anchor::AnchorError),

    /// Hex decode error.
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Alloy transport error.
    #[error("transport error: {0}")]
    Transport(String),

    /// Alloy signer error.
    #[error("signer error: {0}")]
    Signer(String),
}

impl From<alloy::transports::TransportError> for EthereumError {
    fn from(e: alloy::transports::TransportError) -> Self {
        EthereumError::Transport(e.to_string())
    }
}

impl From<alloy::signers::local::LocalSignerError> for EthereumError {
    fn from(e: alloy::signers::local::LocalSignerError) -> Self {
        EthereumError::Signer(e.to_string())
    }
}
