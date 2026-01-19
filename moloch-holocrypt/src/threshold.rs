//! Threshold decryption for audit events.
//!
//! Enables k-of-n access control where any k participants
//! can collaborate to decrypt an event.
//!
//! Uses Shamir's secret sharing for key splitting and
//! FROST for distributed key generation when needed.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use arcanum_holocrypt::container::threshold::{ThresholdContainer, KeyShare as HoloKeyShare};
use arcanum_threshold::{Share, ShamirScheme};

use moloch_core::event::AuditEvent;

use crate::errors::{HoloCryptError, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// Threshold Configuration
// ═══════════════════════════════════════════════════════════════════════════════

/// Configuration for threshold encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Minimum number of shares required to decrypt (k).
    pub threshold: usize,
    /// Total number of shares (n).
    pub total_shares: usize,
    /// Optional share expiration.
    pub expires_at: Option<DateTime<Utc>>,
    /// Description of the threshold scheme.
    pub description: Option<String>,
}

impl ThresholdConfig {
    /// Create a new threshold configuration.
    pub fn new(threshold: usize, total_shares: usize) -> Result<Self> {
        if threshold == 0 {
            return Err(HoloCryptError::InvalidConfiguration {
                reason: "threshold must be at least 1".to_string(),
            });
        }
        if threshold > total_shares {
            return Err(HoloCryptError::InvalidConfiguration {
                reason: "threshold cannot exceed total shares".to_string(),
            });
        }
        if total_shares > 255 {
            return Err(HoloCryptError::InvalidConfiguration {
                reason: "maximum 255 shares supported".to_string(),
            });
        }

        Ok(Self {
            threshold,
            total_shares,
            expires_at: None,
            description: None,
        })
    }

    /// Create a 2-of-3 configuration.
    pub fn two_of_three() -> Self {
        Self {
            threshold: 2,
            total_shares: 3,
            expires_at: None,
            description: Some("2-of-3 threshold scheme".to_string()),
        }
    }

    /// Create a 3-of-5 configuration.
    pub fn three_of_five() -> Self {
        Self {
            threshold: 3,
            total_shares: 5,
            expires_at: None,
            description: Some("3-of-5 threshold scheme".to_string()),
        }
    }

    /// Create a 5-of-7 configuration.
    pub fn five_of_seven() -> Self {
        Self {
            threshold: 5,
            total_shares: 7,
            expires_at: None,
            description: Some("5-of-7 threshold scheme".to_string()),
        }
    }

    /// Set expiration time.
    pub fn expires_at(mut self, time: DateTime<Utc>) -> Self {
        self.expires_at = Some(time);
        self
    }

    /// Set description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Check if shares have expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() > exp)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Key Share
// ═══════════════════════════════════════════════════════════════════════════════

/// A key share for threshold decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Share index (1-based).
    index: u8,
    /// Share data.
    data: Vec<u8>,
    /// Owner identifier.
    owner_id: Option<String>,
    /// Creation timestamp.
    created_at: DateTime<Utc>,
    /// Share version (for rotation).
    version: u32,
}

impl KeyShare {
    /// Create a new key share.
    pub fn new(index: u8, data: Vec<u8>) -> Self {
        Self {
            index,
            data,
            owner_id: None,
            created_at: Utc::now(),
            version: 1,
        }
    }

    /// Create from HoloCrypt key share.
    pub fn from_holo_share(share: &HoloKeyShare) -> Self {
        Self {
            index: share.index(),
            data: share.data().to_vec(),
            owner_id: None,
            created_at: Utc::now(),
            version: 1,
        }
    }

    /// Convert to HoloCrypt key share.
    pub fn to_holo_share(&self) -> HoloKeyShare {
        HoloKeyShare::new(self.index, self.data.clone())
    }

    /// Get the share index.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Get the share data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Set owner ID.
    pub fn with_owner(mut self, owner_id: impl Into<String>) -> Self {
        self.owner_id = Some(owner_id.into());
        self
    }

    /// Get owner ID.
    pub fn owner_id(&self) -> Option<&str> {
        self.owner_id.as_deref()
    }

    /// Get creation timestamp.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Get version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Key Share Set
// ═══════════════════════════════════════════════════════════════════════════════

/// A set of key shares for threshold decryption.
#[derive(Debug, Clone, Default)]
pub struct KeyShareSet {
    shares: Vec<KeyShare>,
    config: Option<ThresholdConfig>,
}

impl KeyShareSet {
    /// Create a new empty share set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with configuration.
    pub fn with_config(config: ThresholdConfig) -> Self {
        Self {
            shares: Vec::new(),
            config: Some(config),
        }
    }

    /// Add a share to the set.
    pub fn add(&mut self, share: KeyShare) {
        // Avoid duplicates by index
        if !self.shares.iter().any(|s| s.index == share.index) {
            self.shares.push(share);
        }
    }

    /// Get all shares.
    pub fn shares(&self) -> &[KeyShare] {
        &self.shares
    }

    /// Get share count.
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// Check if we have enough shares for threshold.
    pub fn has_threshold(&self) -> bool {
        match &self.config {
            Some(config) => self.shares.len() >= config.threshold,
            None => !self.shares.is_empty(),
        }
    }

    /// Get the threshold requirement.
    pub fn threshold(&self) -> Option<usize> {
        self.config.as_ref().map(|c| c.threshold)
    }

    /// Convert to HoloCrypt key shares.
    pub fn to_holo_shares(&self) -> Vec<HoloKeyShare> {
        self.shares.iter().map(|s| s.to_holo_share()).collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Threshold Event
// ═══════════════════════════════════════════════════════════════════════════════

/// An audit event encrypted with threshold access control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdEvent {
    /// Threshold configuration.
    pub config: ThresholdConfig,
    /// The sealed container (serialized).
    container: Vec<u8>,
    /// Event ID (commitment).
    event_id: [u8; 32],
    /// Merkle root.
    merkle_root: [u8; 32],
    /// Created timestamp.
    created_at: DateTime<Utc>,
}

/// Payload for threshold container.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThresholdPayload {
    event: AuditEvent,
}

impl ThresholdEvent {
    /// Create a threshold-encrypted event.
    pub fn seal(
        event: &AuditEvent,
        config: ThresholdConfig,
    ) -> Result<(Self, Vec<KeyShare>)> {
        if config.is_expired() {
            return Err(HoloCryptError::KeyExpired {
                key_id: "threshold config".to_string(),
            });
        }

        // Wrap event in payload
        let payload = ThresholdPayload {
            event: event.clone(),
        };

        // Create threshold container
        let (container, holo_shares) = ThresholdContainer::seal(
            &payload,
            config.threshold,
            config.total_shares,
        ).map_err(|e| HoloCryptError::EncryptionFailed {
            reason: e.to_string(),
        })?;

        // Convert shares
        let shares: Vec<KeyShare> = holo_shares
            .iter()
            .map(KeyShare::from_holo_share)
            .collect();

        // Serialize container
        let container_bytes = serde_json::to_vec(&container)?;

        Ok((
            Self {
                config,
                container: container_bytes,
                event_id: *container.commitment(),
                merkle_root: *container.merkle_root(),
                created_at: Utc::now(),
            },
            shares,
        ))
    }

    /// Unseal using threshold shares.
    pub fn unseal(&self, shares: &KeyShareSet) -> Result<AuditEvent> {
        // Check expiration
        if self.config.is_expired() {
            return Err(HoloCryptError::KeyExpired {
                key_id: "threshold event".to_string(),
            });
        }

        // Check threshold
        if shares.len() < self.config.threshold {
            return Err(HoloCryptError::InsufficientShares {
                required: self.config.threshold,
                provided: shares.len(),
            });
        }

        // Deserialize container
        let container: ThresholdContainer<ThresholdPayload> =
            serde_json::from_slice(&self.container)?;

        // Convert shares
        let holo_shares = shares.to_holo_shares();

        // Unseal
        let payload = container.unseal(&holo_shares).map_err(|e| {
            HoloCryptError::DecryptionFailed {
                reason: e.to_string(),
            }
        })?;

        Ok(payload.event)
    }

    /// Verify container structure without decrypting.
    pub fn verify_structure(&self) -> Result<()> {
        let container: ThresholdContainer<ThresholdPayload> =
            serde_json::from_slice(&self.container)?;

        container.verify_structure().map_err(|e| {
            HoloCryptError::CryptoError {
                reason: e.to_string(),
            }
        })
    }

    /// Get event ID.
    pub fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }

    /// Get Merkle root.
    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.merkle_root
    }

    /// Get creation timestamp.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Into::into)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Share Distribution
// ═══════════════════════════════════════════════════════════════════════════════

/// Manages share distribution to participants.
#[derive(Debug, Default)]
pub struct ShareDistributor {
    /// Mapping from owner ID to shares.
    assigned: HashMap<String, Vec<KeyShare>>,
}

impl ShareDistributor {
    /// Create a new distributor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign shares to owners.
    pub fn distribute(
        shares: Vec<KeyShare>,
        owners: &[impl AsRef<str>],
    ) -> Result<Self> {
        if shares.len() != owners.len() {
            return Err(HoloCryptError::InvalidConfiguration {
                reason: format!(
                    "share count ({}) must match owner count ({})",
                    shares.len(),
                    owners.len()
                ),
            });
        }

        let mut assigned: HashMap<String, Vec<KeyShare>> = HashMap::new();

        for (share, owner) in shares.into_iter().zip(owners.iter()) {
            let owner_id = owner.as_ref().to_string();
            let share = share.with_owner(&owner_id);
            assigned.entry(owner_id).or_default().push(share);
        }

        Ok(Self { assigned })
    }

    /// Get shares for an owner.
    pub fn get_shares(&self, owner_id: &str) -> Option<&[KeyShare]> {
        self.assigned.get(owner_id).map(|v| v.as_slice())
    }

    /// Get all owners.
    pub fn owners(&self) -> impl Iterator<Item = &str> {
        self.assigned.keys().map(|s| s.as_str())
    }

    /// Collect shares from multiple owners into a share set.
    pub fn collect<'a>(
        &self,
        owner_ids: impl IntoIterator<Item = &'a str>,
    ) -> KeyShareSet {
        let mut set = KeyShareSet::new();

        for owner_id in owner_ids {
            if let Some(shares) = self.get_shares(owner_id) {
                for share in shares {
                    set.add(share.clone());
                }
            }
        }

        set
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Share Refresh (Proactive Secret Sharing)
// ═══════════════════════════════════════════════════════════════════════════════

/// Refresh shares without changing the secret.
///
/// This allows rotating shares to maintain security without
/// re-encrypting the data.
pub struct ShareRefresher;

impl ShareRefresher {
    /// Refresh shares by creating new shares that reconstruct to the same secret.
    ///
    /// Requires threshold shares from the old set.
    pub fn refresh(
        old_shares: &KeyShareSet,
        config: &ThresholdConfig,
    ) -> Result<Vec<KeyShare>> {
        if old_shares.len() < config.threshold {
            return Err(HoloCryptError::InsufficientShares {
                required: config.threshold,
                provided: old_shares.len(),
            });
        }

        // First reconstruct the secret
        let shamir_shares: Vec<Share> = old_shares
            .shares()
            .iter()
            .take(config.threshold)
            .map(|s| Share::new(s.index, s.data.clone()))
            .collect();

        let secret = ShamirScheme::combine(&shamir_shares).map_err(|e| {
            HoloCryptError::KeyReconstructionFailed {
                reason: format!("{:?}", e),
            }
        })?;

        // Create new shares with incremented version
        let new_shamir_shares = ShamirScheme::split(
            &secret,
            config.threshold,
            config.total_shares,
        ).map_err(|e| HoloCryptError::CryptoError {
            reason: format!("share split failed: {:?}", e),
        })?;

        // Convert to KeyShares with new version
        let new_version = old_shares
            .shares()
            .first()
            .map(|s| s.version + 1)
            .unwrap_or(1);

        let new_shares: Vec<KeyShare> = new_shamir_shares
            .into_iter()
            .map(|s| KeyShare {
                index: s.index(),
                data: s.value().to_vec(),
                owner_id: None,
                created_at: Utc::now(),
                version: new_version,
            })
            .collect();

        Ok(new_shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;
    use moloch_core::event::{ActorId, ActorKind, EventType, Outcome, ResourceId, ResourceKind};

    fn make_test_event(key: &SecretKey) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test-repo");

        AuditEvent::builder()
            .now()
            .event_type(EventType::RepoCreated)
            .actor(actor)
            .resource(resource)
            .outcome(Outcome::Success)
            .sign(key)
            .unwrap()
    }

    #[test]
    fn test_threshold_config() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        assert_eq!(config.threshold, 2);
        assert_eq!(config.total_shares, 3);
        assert!(!config.is_expired());
    }

    #[test]
    fn test_threshold_config_presets() {
        let two_of_three = ThresholdConfig::two_of_three();
        assert_eq!(two_of_three.threshold, 2);
        assert_eq!(two_of_three.total_shares, 3);

        let three_of_five = ThresholdConfig::three_of_five();
        assert_eq!(three_of_five.threshold, 3);
        assert_eq!(three_of_five.total_shares, 5);
    }

    #[test]
    fn test_invalid_config() {
        // Threshold > total
        assert!(ThresholdConfig::new(5, 3).is_err());

        // Zero threshold
        assert!(ThresholdConfig::new(0, 3).is_err());

        // Too many shares
        assert!(ThresholdConfig::new(2, 300).is_err());
    }

    #[test]
    fn test_threshold_seal_unseal() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let config = ThresholdConfig::two_of_three();
        let (threshold_event, shares) = ThresholdEvent::seal(&event, config).unwrap();

        assert_eq!(shares.len(), 3);

        // Unseal with 2 shares
        let mut share_set = KeyShareSet::new();
        share_set.add(shares[0].clone());
        share_set.add(shares[1].clone());

        let decrypted = threshold_event.unseal(&share_set).unwrap();
        assert_eq!(event.event_type, decrypted.event_type);
    }

    #[test]
    fn test_different_share_subsets() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let config = ThresholdConfig::two_of_three();
        let (threshold_event, shares) = ThresholdEvent::seal(&event, config).unwrap();

        // Try different pairs
        let pairs = vec![
            vec![0, 1],
            vec![0, 2],
            vec![1, 2],
        ];

        for pair in pairs {
            let mut share_set = KeyShareSet::new();
            share_set.add(shares[pair[0]].clone());
            share_set.add(shares[pair[1]].clone());

            let decrypted = threshold_event.unseal(&share_set).unwrap();
            assert_eq!(event.event_type, decrypted.event_type);
        }
    }

    #[test]
    fn test_insufficient_shares_fails() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let config = ThresholdConfig::two_of_three();
        let (threshold_event, shares) = ThresholdEvent::seal(&event, config).unwrap();

        // Only 1 share
        let mut share_set = KeyShareSet::new();
        share_set.add(shares[0].clone());

        let result = threshold_event.unseal(&share_set);
        assert!(matches!(result, Err(HoloCryptError::InsufficientShares { .. })));
    }

    #[test]
    fn test_share_distribution() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let config = ThresholdConfig::two_of_three();
        let (_, shares) = ThresholdEvent::seal(&event, config).unwrap();

        let owners = vec!["alice", "bob", "charlie"];
        let distributor = ShareDistributor::distribute(shares, &owners).unwrap();

        assert!(distributor.get_shares("alice").is_some());
        assert!(distributor.get_shares("bob").is_some());
        assert!(distributor.get_shares("charlie").is_some());
        assert!(distributor.get_shares("dave").is_none());
    }

    #[test]
    fn test_collect_shares() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let config = ThresholdConfig::two_of_three();
        let (threshold_event, shares) = ThresholdEvent::seal(&event, config).unwrap();

        let owners = vec!["alice", "bob", "charlie"];
        let distributor = ShareDistributor::distribute(shares, &owners).unwrap();

        // Collect from alice and bob
        let share_set = distributor.collect(["alice", "bob"]);
        assert_eq!(share_set.len(), 2);

        let decrypted = threshold_event.unseal(&share_set).unwrap();
        assert_eq!(event.event_type, decrypted.event_type);
    }

    #[test]
    fn test_key_share_serialization() {
        let share = KeyShare::new(1, vec![1, 2, 3, 4, 5])
            .with_owner("alice");

        let bytes = share.to_bytes();
        let restored = KeyShare::from_bytes(&bytes).unwrap();

        assert_eq!(share.index, restored.index);
        assert_eq!(share.data, restored.data);
        assert_eq!(share.owner_id, restored.owner_id);
    }

    #[test]
    fn test_verify_structure() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let config = ThresholdConfig::two_of_three();
        let (threshold_event, _) = ThresholdEvent::seal(&event, config).unwrap();

        // Should verify without shares
        assert!(threshold_event.verify_structure().is_ok());
    }

    #[test]
    fn test_threshold_event_serialization() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let config = ThresholdConfig::two_of_three();
        let (threshold_event, shares) = ThresholdEvent::seal(&event, config).unwrap();

        let bytes = threshold_event.to_bytes();
        let restored = ThresholdEvent::from_bytes(&bytes).unwrap();

        // Unseal restored event
        let mut share_set = KeyShareSet::new();
        share_set.add(shares[0].clone());
        share_set.add(shares[1].clone());

        let decrypted = restored.unseal(&share_set).unwrap();
        assert_eq!(event.event_type, decrypted.event_type);
    }
}
