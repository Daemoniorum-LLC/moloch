//! Generic 16-byte identifier type for agent accountability.
//!
//! Provides a base `Id16` type and a `define_id!` macro for creating
//! typed identifier wrappers. This eliminates the duplicated ID
//! generation logic across multiple modules.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// 16-byte random identifier base type.
///
/// All agent module identifiers share this common structure:
/// a 16-byte array generated from a cryptographically secure RNG,
/// with hex encoding for display and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id16(pub [u8; 16]);

impl Id16 {
    /// Generate a new random identifier.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::invalid_input("invalid hex"))?;
        if bytes.len() != 16 {
            return Err(Error::invalid_input("ID must be 16 bytes"));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for Id16 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Macro for defining typed identifiers backed by [`Id16`].
///
/// Each generated type wraps an `Id16` and exposes the same API:
/// `generate()`, `from_bytes()`, `as_bytes()`, `to_hex()`, `from_hex()`,
/// and `Display`.
///
/// # Example
///
/// ```ignore
/// define_id!(MyIdentifier, "my identifier");
/// let id = MyIdentifier::generate();
/// let hex = id.to_hex();
/// let restored = MyIdentifier::from_hex(&hex).unwrap();
/// assert_eq!(id, restored);
/// ```
#[macro_export]
macro_rules! define_id {
    ($name:ident, $desc:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        #[allow(dead_code)]
        pub struct $name(pub [u8; 16]);

        #[allow(dead_code, clippy::wrong_self_convention)]
        impl $name {
            /// Generate a new random identifier.
            pub fn generate() -> Self {
                let inner = $crate::agent::id::Id16::random();
                Self(inner.0)
            }

            /// Create from raw bytes.
            pub fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            /// Get the raw bytes.
            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Convert to hex string.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            #[doc = concat!("Parse a ", $desc, " from a hex string.")]
            pub fn from_hex(s: &str) -> $crate::error::Result<Self> {
                let inner = $crate::agent::id::Id16::from_hex(s)?;
                Ok(Self(inner.0))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.to_hex())
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_id_uniqueness() {
        let id1 = Id16::random();
        let id2 = Id16::random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn random_id_hex_roundtrip() {
        let id = Id16::random();
        let hex = id.to_hex();
        let restored = Id16::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn random_id_display() {
        let id = Id16::random();
        let display = format!("{}", id);
        assert_eq!(display.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn define_id_macro_works() {
        define_id!(TestId, "test identifier");

        let id1 = TestId::generate();
        let id2 = TestId::generate();
        assert_ne!(id1, id2);

        let hex = id1.to_hex();
        let restored = TestId::from_hex(&hex).unwrap();
        assert_eq!(id1, restored);
        assert_eq!(format!("{}", id1).len(), 32);
    }
}
