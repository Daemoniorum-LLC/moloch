//! Error types for Moloch.
//!
//! Provides structured errors with:
//! - Unique error codes for API responses
//! - Source error chaining
//! - Client vs server error categorization

use std::io;
use thiserror::Error;

/// Result type for Moloch operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error codes for API responses.
///
/// Codes are structured as:
/// - 1xxx: Validation errors (client)
/// - 2xxx: Not found errors (client)
/// - 3xxx: Conflict errors (client)
/// - 4xxx: Authentication/authorization (client)
/// - 5xxx: Storage errors (server)
/// - 6xxx: Internal errors (server)
/// - 7xxx: Network errors (server)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    // Validation errors (1xxx)
    InvalidHash = 1001,
    InvalidKey = 1002,
    InvalidSignature = 1003,
    InvalidEvent = 1004,
    InvalidBlock = 1005,
    InvalidProof = 1006,
    InvalidTimestamp = 1007,
    InvalidFormat = 1008,

    // Not found errors (2xxx)
    EventNotFound = 2001,
    BlockNotFound = 2002,
    NodeNotFound = 2003,
    PeakNotFound = 2004,

    // Conflict errors (3xxx)
    DuplicateEvent = 3001,
    DuplicateBlock = 3002,
    ChainFork = 3003,

    // Auth errors (4xxx)
    Unauthorized = 4001,
    Forbidden = 4002,

    // Storage errors (5xxx)
    StorageRead = 5001,
    StorageWrite = 5002,
    StorageCorruption = 5003,
    StorageInit = 5004,

    // Internal errors (6xxx)
    Serialization = 6001,
    Deserialization = 6002,
    Internal = 6003,

    // Network errors (7xxx)
    ConnectionFailed = 7001,
    Timeout = 7002,
    ProtocolError = 7003,
}

impl ErrorCode {
    /// Get the numeric code.
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Check if this is a client error (4xx equivalent).
    pub fn is_client_error(self) -> bool {
        (1000..5000).contains(&self.code())
    }

    /// Check if this is a server error (5xx equivalent).
    pub fn is_server_error(self) -> bool {
        self.code() >= 5000
    }

    /// Check if this error is retryable.
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            ErrorCode::StorageRead
                | ErrorCode::StorageWrite
                | ErrorCode::ConnectionFailed
                | ErrorCode::Timeout
        )
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "E{:04}", self.code())
    }
}

/// Errors that can occur in Moloch.
#[derive(Debug, Error)]
pub enum Error {
    // ========================================================================
    // Validation Errors (client errors)
    // ========================================================================
    /// Invalid hash format or value.
    #[error("[{code}] invalid hash: {message}")]
    InvalidHash {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Invalid cryptographic key.
    #[error("[{code}] invalid key: {message}")]
    InvalidKey {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Signature verification failed.
    #[error("[{code}] signature verification failed")]
    InvalidSignature { code: ErrorCode },

    /// Event validation failed.
    #[error("[{code}] invalid event: {message}")]
    InvalidEvent { code: ErrorCode, message: String },

    /// Block validation failed.
    #[error("[{code}] invalid block: {message}")]
    InvalidBlock { code: ErrorCode, message: String },

    /// Proof verification failed.
    #[error("[{code}] invalid proof: {message}")]
    InvalidProof { code: ErrorCode, message: String },

    // ========================================================================
    // Not Found Errors (client errors)
    // ========================================================================
    /// Item not found.
    #[error("[{code}] not found: {message}")]
    NotFound { code: ErrorCode, message: String },

    // ========================================================================
    // Conflict Errors (client errors)
    // ========================================================================
    /// Duplicate item.
    #[error("[{code}] duplicate: {message}")]
    Duplicate { code: ErrorCode, message: String },

    // ========================================================================
    // Storage Errors (server errors)
    // ========================================================================
    /// Storage operation failed.
    #[error("[{code}] storage error: {message}")]
    Storage {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    // ========================================================================
    // Serialization Errors (server errors)
    // ========================================================================
    /// Serialization/deserialization failed.
    #[error("[{code}] serialization error: {message}")]
    Serialization {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    // ========================================================================
    // Internal Errors (server errors)
    // ========================================================================
    /// Internal error.
    #[error("[{code}] internal error: {message}")]
    Internal { code: ErrorCode, message: String },
}

impl Error {
    /// Get the error code.
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::InvalidHash { code, .. } => *code,
            Error::InvalidKey { code, .. } => *code,
            Error::InvalidSignature { code } => *code,
            Error::InvalidEvent { code, .. } => *code,
            Error::InvalidBlock { code, .. } => *code,
            Error::InvalidProof { code, .. } => *code,
            Error::NotFound { code, .. } => *code,
            Error::Duplicate { code, .. } => *code,
            Error::Storage { code, .. } => *code,
            Error::Serialization { code, .. } => *code,
            Error::Internal { code, .. } => *code,
        }
    }

    /// Check if this is a client error.
    pub fn is_client_error(&self) -> bool {
        self.code().is_client_error()
    }

    /// Check if this is a server error.
    pub fn is_server_error(&self) -> bool {
        self.code().is_server_error()
    }

    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        self.code().is_retryable()
    }
}

// ============================================================================
// Convenience constructors (backward compatible)
// ============================================================================

impl Error {
    /// Create an InvalidHash error.
    pub fn invalid_hash(message: impl Into<String>) -> Self {
        Error::InvalidHash {
            code: ErrorCode::InvalidHash,
            message: message.into(),
            source: None,
        }
    }

    /// Create an InvalidKey error.
    pub fn invalid_key(message: impl Into<String>) -> Self {
        Error::InvalidKey {
            code: ErrorCode::InvalidKey,
            message: message.into(),
            source: None,
        }
    }

    /// Create an InvalidSignature error.
    pub fn invalid_signature() -> Self {
        Error::InvalidSignature {
            code: ErrorCode::InvalidSignature,
        }
    }

    /// Create an InvalidEvent error.
    pub fn invalid_event(message: impl Into<String>) -> Self {
        Error::InvalidEvent {
            code: ErrorCode::InvalidEvent,
            message: message.into(),
        }
    }

    /// Create an InvalidBlock error.
    pub fn invalid_block(message: impl Into<String>) -> Self {
        Error::InvalidBlock {
            code: ErrorCode::InvalidBlock,
            message: message.into(),
        }
    }

    /// Create an InvalidProof error.
    pub fn invalid_proof(message: impl Into<String>) -> Self {
        Error::InvalidProof {
            code: ErrorCode::InvalidProof,
            message: message.into(),
        }
    }

    /// Create a NotFound error for events.
    pub fn event_not_found(message: impl Into<String>) -> Self {
        Error::NotFound {
            code: ErrorCode::EventNotFound,
            message: message.into(),
        }
    }

    /// Create a NotFound error for blocks.
    pub fn block_not_found(message: impl Into<String>) -> Self {
        Error::NotFound {
            code: ErrorCode::BlockNotFound,
            message: message.into(),
        }
    }

    /// Create a NotFound error (generic).
    pub fn not_found(message: impl Into<String>) -> Self {
        Error::NotFound {
            code: ErrorCode::NodeNotFound,
            message: message.into(),
        }
    }

    /// Create a Duplicate error.
    pub fn duplicate(message: impl Into<String>) -> Self {
        Error::Duplicate {
            code: ErrorCode::DuplicateEvent,
            message: message.into(),
        }
    }

    /// Create a Storage error.
    pub fn storage(message: impl Into<String>) -> Self {
        Error::Storage {
            code: ErrorCode::StorageRead,
            message: message.into(),
            source: None,
        }
    }

    /// Create an Internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Error::Internal {
            code: ErrorCode::Internal,
            message: message.into(),
        }
    }
}

// ============================================================================
// From implementations for automatic conversion
// ============================================================================

impl From<bincode::Error> for Error {
    fn from(e: bincode::Error) -> Self {
        Error::Serialization {
            code: ErrorCode::Serialization,
            message: e.to_string(),
            source: Some(Box::new(e)),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization {
            code: ErrorCode::Serialization,
            message: e.to_string(),
            source: Some(Box::new(e)),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Storage {
            code: ErrorCode::StorageRead,
            message: e.to_string(),
            source: Some(Box::new(e)),
        }
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::InvalidHash {
            code: ErrorCode::InvalidHash,
            message: e.to_string(),
            source: Some(Box::new(e)),
        }
    }
}

// ============================================================================
// Legacy constructors for backward compatibility
// ============================================================================

// These allow the old pattern: Error::InvalidHash("message".into())
// to work via From<String> for the message field

/// Helper to maintain backward compatibility with Error::Variant(String) pattern.
#[allow(unused_macros)]
macro_rules! impl_from_string {
    ($variant:ident, $code:expr) => {
        impl From<&str> for $variant {
            fn from(s: &str) -> Self {
                $variant(s.to_string())
            }
        }
    };
}

// For backward compatibility, we provide a way to construct errors from strings
// using the old pattern. This is a transitional measure.

#[doc(hidden)]
pub struct InvalidHashCompat(pub String);
#[doc(hidden)]
pub struct InvalidKeyCompat(pub String);
#[doc(hidden)]
pub struct InvalidEventCompat(pub String);
#[doc(hidden)]
pub struct InvalidBlockCompat(pub String);
#[doc(hidden)]
pub struct InvalidProofCompat(pub String);
#[doc(hidden)]
pub struct StorageCompat(pub String);
#[doc(hidden)]
pub struct NotFoundCompat(pub String);
#[doc(hidden)]
pub struct DuplicateCompat(pub String);
#[doc(hidden)]
pub struct SerializationCompat(pub String);
#[doc(hidden)]
pub struct InternalCompat(pub String);

impl From<InvalidHashCompat> for Error {
    fn from(c: InvalidHashCompat) -> Self {
        Error::invalid_hash(c.0)
    }
}

impl From<InvalidKeyCompat> for Error {
    fn from(c: InvalidKeyCompat) -> Self {
        Error::invalid_key(c.0)
    }
}

impl From<InvalidEventCompat> for Error {
    fn from(c: InvalidEventCompat) -> Self {
        Error::invalid_event(c.0)
    }
}

impl From<InvalidBlockCompat> for Error {
    fn from(c: InvalidBlockCompat) -> Self {
        Error::invalid_block(c.0)
    }
}

impl From<InvalidProofCompat> for Error {
    fn from(c: InvalidProofCompat) -> Self {
        Error::invalid_proof(c.0)
    }
}

impl From<StorageCompat> for Error {
    fn from(c: StorageCompat) -> Self {
        Error::storage(c.0)
    }
}

impl From<NotFoundCompat> for Error {
    fn from(c: NotFoundCompat) -> Self {
        Error::not_found(c.0)
    }
}

impl From<DuplicateCompat> for Error {
    fn from(c: DuplicateCompat) -> Self {
        Error::duplicate(c.0)
    }
}

impl From<SerializationCompat> for Error {
    fn from(c: SerializationCompat) -> Self {
        Error::Serialization {
            code: ErrorCode::Serialization,
            message: c.0,
            source: None,
        }
    }
}

impl From<InternalCompat> for Error {
    fn from(c: InternalCompat) -> Self {
        Error::internal(c.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(ErrorCode::InvalidHash.code(), 1001);
        assert_eq!(ErrorCode::EventNotFound.code(), 2001);
        assert_eq!(ErrorCode::StorageRead.code(), 5001);
    }

    #[test]
    fn test_error_categorization() {
        assert!(ErrorCode::InvalidHash.is_client_error());
        assert!(!ErrorCode::InvalidHash.is_server_error());

        assert!(ErrorCode::StorageRead.is_server_error());
        assert!(!ErrorCode::StorageRead.is_client_error());
    }

    #[test]
    fn test_retryable() {
        assert!(ErrorCode::StorageRead.is_retryable());
        assert!(ErrorCode::Timeout.is_retryable());
        assert!(!ErrorCode::InvalidHash.is_retryable());
    }

    #[test]
    fn test_error_display() {
        let e = Error::invalid_hash("bad hex");
        assert!(e.to_string().contains("E1001"));
        assert!(e.to_string().contains("bad hex"));
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(ErrorCode::InvalidHash.to_string(), "E1001");
        assert_eq!(ErrorCode::Internal.to_string(), "E6003");
    }

    #[test]
    fn test_from_bincode() {
        // Try to deserialize invalid data as a String to trigger bincode error
        let bad_data = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]; // Invalid length prefix
        let bincode_err: bincode::Error = bincode::deserialize::<String>(&bad_data).unwrap_err();
        let err: Error = bincode_err.into();
        assert_eq!(err.code(), ErrorCode::Serialization);
        assert!(err.is_server_error());
    }

    #[test]
    fn test_error_constructors() {
        let e = Error::invalid_event("missing field");
        assert_eq!(e.code(), ErrorCode::InvalidEvent);
        assert!(e.is_client_error());

        let e = Error::storage("disk full");
        assert_eq!(e.code(), ErrorCode::StorageRead);
        assert!(e.is_server_error());
    }
}
