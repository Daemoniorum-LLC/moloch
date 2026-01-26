//! Commitment types for anchoring.
//!
//! A commitment represents a snapshot of Moloch chain state
//! that will be anchored to an external blockchain.

use moloch_core::Hash;
use serde::{Deserialize, Serialize};

/// A commitment to anchor on an external chain.
///
/// This captures the essential state of the Moloch chain at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    /// Moloch chain identifier.
    pub chain_id: String,
    /// MMR root hash at this commitment.
    pub mmr_root: Hash,
    /// Block height at this commitment.
    pub height: u64,
    /// Total events at this commitment.
    pub event_count: u64,
    /// Unix timestamp of commitment creation.
    pub timestamp: i64,
    /// Optional metadata.
    pub metadata: Option<CommitmentData>,
}

impl Commitment {
    /// Create a new commitment.
    pub fn new(chain_id: impl Into<String>, mmr_root: Hash, height: u64) -> Self {
        Self {
            chain_id: chain_id.into(),
            mmr_root,
            height,
            event_count: 0,
            timestamp: chrono::Utc::now().timestamp(),
            metadata: None,
        }
    }

    /// Create a commitment builder.
    pub fn builder() -> CommitmentBuilder {
        CommitmentBuilder::default()
    }

    /// Compute the commitment hash (what gets anchored).
    pub fn hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend(self.chain_id.as_bytes());
        data.extend(self.mmr_root.as_bytes());
        data.extend(&self.height.to_le_bytes());
        data.extend(&self.event_count.to_le_bytes());
        data.extend(&self.timestamp.to_le_bytes());
        moloch_core::hash(&data)
    }

    /// Serialize to bytes for anchoring.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Compact format: 32 (mmr_root) + 8 (height) + 8 (events) + 8 (timestamp) = 56 bytes
        let mut bytes = Vec::with_capacity(56);
        bytes.extend(self.mmr_root.as_bytes());
        bytes.extend(&self.height.to_le_bytes());
        bytes.extend(&self.event_count.to_le_bytes());
        bytes.extend(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Parse from bytes.
    pub fn from_bytes(chain_id: impl Into<String>, bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 56 {
            return None;
        }

        let mmr_bytes: [u8; 32] = bytes[0..32].try_into().ok()?;
        let mmr_root = Hash::from_bytes(mmr_bytes);
        let height = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
        let event_count = u64::from_le_bytes(bytes[40..48].try_into().ok()?);
        let timestamp = i64::from_le_bytes(bytes[48..56].try_into().ok()?);

        Some(Self {
            chain_id: chain_id.into(),
            mmr_root,
            height,
            event_count,
            timestamp,
            metadata: None,
        })
    }

    /// Size in bytes when serialized.
    pub fn encoded_size(&self) -> usize {
        56 + self
            .metadata
            .as_ref()
            .map(|m| m.encoded_size())
            .unwrap_or(0)
    }
}

/// Builder for commitments.
#[derive(Debug, Default)]
pub struct CommitmentBuilder {
    chain_id: Option<String>,
    mmr_root: Option<Hash>,
    height: Option<u64>,
    event_count: u64,
    timestamp: Option<i64>,
    metadata: Option<CommitmentData>,
}

impl CommitmentBuilder {
    /// Set chain ID.
    pub fn chain_id(mut self, id: impl Into<String>) -> Self {
        self.chain_id = Some(id.into());
        self
    }

    /// Set MMR root.
    pub fn mmr_root(mut self, root: Hash) -> Self {
        self.mmr_root = Some(root);
        self
    }

    /// Set block height.
    pub fn height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }

    /// Set event count.
    pub fn event_count(mut self, count: u64) -> Self {
        self.event_count = count;
        self
    }

    /// Set timestamp.
    pub fn timestamp(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Set metadata.
    pub fn metadata(mut self, data: CommitmentData) -> Self {
        self.metadata = Some(data);
        self
    }

    /// Build the commitment.
    pub fn build(self) -> Option<Commitment> {
        Some(Commitment {
            chain_id: self.chain_id?,
            mmr_root: self.mmr_root?,
            height: self.height?,
            event_count: self.event_count,
            timestamp: self
                .timestamp
                .unwrap_or_else(|| chrono::Utc::now().timestamp()),
            metadata: self.metadata,
        })
    }
}

/// Additional commitment metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentData {
    /// Previous commitment hash (for chaining).
    pub previous: Option<Hash>,
    /// Validator set hash at this commitment.
    pub validators_hash: Option<Hash>,
    /// State root (if different from MMR root).
    pub state_root: Option<Hash>,
    /// Custom application data.
    pub app_data: Option<Vec<u8>>,
}

impl CommitmentData {
    /// Create empty metadata.
    pub fn new() -> Self {
        Self {
            previous: None,
            validators_hash: None,
            state_root: None,
            app_data: None,
        }
    }

    /// Set previous commitment hash.
    pub fn with_previous(mut self, hash: Hash) -> Self {
        self.previous = Some(hash);
        self
    }

    /// Set validators hash.
    pub fn with_validators(mut self, hash: Hash) -> Self {
        self.validators_hash = Some(hash);
        self
    }

    /// Encoded size.
    pub fn encoded_size(&self) -> usize {
        let mut size = 0;
        if self.previous.is_some() {
            size += 32;
        }
        if self.validators_hash.is_some() {
            size += 32;
        }
        if self.state_root.is_some() {
            size += 32;
        }
        if let Some(ref data) = self.app_data {
            size += data.len();
        }
        size
    }
}

impl Default for CommitmentData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_roundtrip() {
        let commitment = Commitment::new("moloch-mainnet", Hash::ZERO, 1000);
        let bytes = commitment.to_bytes();
        let parsed = Commitment::from_bytes("moloch-mainnet", &bytes).unwrap();

        assert_eq!(commitment.mmr_root, parsed.mmr_root);
        assert_eq!(commitment.height, parsed.height);
        assert_eq!(commitment.timestamp, parsed.timestamp);
    }

    #[test]
    fn test_commitment_hash() {
        let c1 = Commitment::new("chain", Hash::ZERO, 100);
        let c2 = Commitment::new("chain", Hash::ZERO, 101);

        // Different heights should produce different hashes
        assert_ne!(c1.hash(), c2.hash());
    }

    #[test]
    fn test_commitment_builder() {
        let commitment = Commitment::builder()
            .chain_id("test")
            .mmr_root(Hash::ZERO)
            .height(500)
            .event_count(10000)
            .build()
            .unwrap();

        assert_eq!(commitment.chain_id, "test");
        assert_eq!(commitment.height, 500);
        assert_eq!(commitment.event_count, 10000);
    }
}
