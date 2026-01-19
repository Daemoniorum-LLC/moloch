//! Error types for Bitcoin anchoring.

use thiserror::Error;

/// Result type for Bitcoin operations.
pub type Result<T> = std::result::Result<T, BitcoinError>;

/// Errors that can occur during Bitcoin anchoring.
#[derive(Debug, Error)]
pub enum BitcoinError {
    /// RPC connection error.
    #[error("RPC connection failed: {0}")]
    RpcConnection(String),

    /// RPC call error.
    #[error("RPC call failed: {0}")]
    RpcCall(String),

    /// Authentication error.
    #[error("authentication failed: {0}")]
    Authentication(String),

    /// Insufficient funds.
    #[error("insufficient funds: need {need} sat, have {have} sat")]
    InsufficientFunds {
        /// Amount needed.
        need: u64,
        /// Amount available.
        have: u64,
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

    /// Invalid transaction.
    #[error("invalid transaction: {0}")]
    InvalidTx(String),

    /// Invalid address.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Network mismatch.
    #[error("network mismatch: expected {expected}, got {got}")]
    NetworkMismatch {
        /// Expected network.
        expected: String,
        /// Actual network.
        got: String,
    },

    /// Wallet error.
    #[error("wallet error: {0}")]
    Wallet(String),

    /// Fee estimation error.
    #[error("fee estimation failed: {0}")]
    FeeEstimation(String),

    /// Invalid OP_RETURN data.
    #[error("invalid OP_RETURN data: {0}")]
    InvalidOpReturn(String),

    /// SPV proof error.
    #[error("SPV proof error: {0}")]
    SpvProof(String),

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

    /// Bitcoin library error.
    #[error("bitcoin error: {0}")]
    Bitcoin(String),

    /// Hex decode error.
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<bitcoincore_rpc::Error> for BitcoinError {
    fn from(e: bitcoincore_rpc::Error) -> Self {
        BitcoinError::RpcCall(e.to_string())
    }
}

impl From<bitcoin::consensus::encode::Error> for BitcoinError {
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        BitcoinError::Bitcoin(e.to_string())
    }
}

impl From<bitcoin::address::ParseError> for BitcoinError {
    fn from(e: bitcoin::address::ParseError) -> Self {
        BitcoinError::InvalidAddress(e.to_string())
    }
}
