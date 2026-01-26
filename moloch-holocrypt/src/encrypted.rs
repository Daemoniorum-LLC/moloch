//! Encrypted audit events with selective field encryption.
//!
//! Wraps `AuditEvent` in HoloCrypt containers with configurable
//! field visibility and encryption policies.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use arcanum_holocrypt::container::{HoloCrypt, OpeningKey, SealingKey};
use arcanum_signatures::ed25519::Ed25519VerifyingKey;

use moloch_core::crypto::Hash;
use moloch_core::event::{ActorId, AuditEvent, EventId, EventType, Outcome, ResourceId};

use crate::errors::{HoloCryptError, Result};

// ═══════════════════════════════════════════════════════════════════════════════
// Field Visibility
// ═══════════════════════════════════════════════════════════════════════════════

/// Visibility level for event fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldVisibility {
    /// Field is publicly visible (not encrypted).
    Public,
    /// Field is encrypted but can be selectively disclosed.
    Encrypted,
    /// Field is encrypted and cannot be disclosed (only verifiable via ZK).
    Private,
}

impl Default for FieldVisibility {
    fn default() -> Self {
        Self::Encrypted
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encryption Policy
// ═══════════════════════════════════════════════════════════════════════════════

/// Policy for encrypting event fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionPolicy {
    /// Visibility of the event type field.
    pub event_type: FieldVisibility,
    /// Visibility of the actor field.
    pub actor: FieldVisibility,
    /// Visibility of the resource field.
    pub resource: FieldVisibility,
    /// Visibility of the outcome field.
    pub outcome: FieldVisibility,
    /// Visibility of metadata.
    pub metadata: FieldVisibility,
    /// Visibility of the timestamp.
    pub timestamp: FieldVisibility,
    /// Key ID for encryption (for key rotation).
    pub key_id: Option<String>,
}

impl Default for EncryptionPolicy {
    fn default() -> Self {
        Self {
            // By default, encrypt sensitive fields
            event_type: FieldVisibility::Public,
            actor: FieldVisibility::Encrypted,
            resource: FieldVisibility::Encrypted,
            outcome: FieldVisibility::Public,
            metadata: FieldVisibility::Private,
            timestamp: FieldVisibility::Public,
            key_id: None,
        }
    }
}

impl EncryptionPolicy {
    /// Create a policy where all fields are public (no encryption).
    pub fn all_public() -> Self {
        Self {
            event_type: FieldVisibility::Public,
            actor: FieldVisibility::Public,
            resource: FieldVisibility::Public,
            outcome: FieldVisibility::Public,
            metadata: FieldVisibility::Public,
            timestamp: FieldVisibility::Public,
            key_id: None,
        }
    }

    /// Create a policy where all fields are encrypted.
    pub fn all_encrypted() -> Self {
        Self {
            event_type: FieldVisibility::Encrypted,
            actor: FieldVisibility::Encrypted,
            resource: FieldVisibility::Encrypted,
            outcome: FieldVisibility::Encrypted,
            metadata: FieldVisibility::Encrypted,
            timestamp: FieldVisibility::Encrypted,
            key_id: None,
        }
    }

    /// Create a policy where all fields are private (ZK only).
    pub fn all_private() -> Self {
        Self {
            event_type: FieldVisibility::Private,
            actor: FieldVisibility::Private,
            resource: FieldVisibility::Private,
            outcome: FieldVisibility::Private,
            metadata: FieldVisibility::Private,
            timestamp: FieldVisibility::Private,
            key_id: None,
        }
    }

    /// Set key ID for key rotation.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encryption Keys
// ═══════════════════════════════════════════════════════════════════════════════

/// Keys for encrypting events.
#[derive(Clone)]
pub struct EventSealingKey {
    inner: SealingKey,
    key_id: String,
    created_at: DateTime<Utc>,
}

impl EventSealingKey {
    /// Get the key ID.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

/// Keys for decrypting events.
#[derive(Clone)]
pub struct EventOpeningKey {
    inner: OpeningKey,
    key_id: String,
}

impl EventOpeningKey {
    /// Get the key ID.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the verifying key for signature verification.
    pub fn verifying_key(&self) -> &Ed25519VerifyingKey {
        self.inner.verifying_key()
    }
}

/// Generate a new keypair for event encryption.
pub fn generate_keypair(key_id: impl Into<String>) -> (EventSealingKey, EventOpeningKey) {
    let (sealing, opening) = HoloCrypt::<EncryptedPayload>::generate_keypair();
    let key_id = key_id.into();

    (
        EventSealingKey {
            inner: sealing,
            key_id: key_id.clone(),
            created_at: Utc::now(),
        },
        EventOpeningKey {
            inner: opening,
            key_id,
        },
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypted Payload
// ═══════════════════════════════════════════════════════════════════════════════

/// Internal encrypted payload containing event fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedPayload {
    /// Encrypted event type (if not public).
    event_type: Option<String>,
    /// Encrypted actor (if not public).
    actor: Option<String>,
    /// Encrypted resource (if not public).
    resource: Option<String>,
    /// Encrypted outcome (if not public).
    outcome: Option<String>,
    /// Encrypted metadata (if not public).
    metadata: Option<Vec<u8>>,
    /// Encrypted timestamp (if not public).
    timestamp: Option<i64>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public Header
// ═══════════════════════════════════════════════════════════════════════════════

/// Public header for encrypted events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEventHeader {
    /// Event ID (hash of the encrypted container).
    pub id: [u8; 32],
    /// Public timestamp (if visible).
    pub timestamp: Option<DateTime<Utc>>,
    /// Public event type (if visible).
    pub event_type: Option<String>,
    /// Public actor (if visible).
    pub actor: Option<String>,
    /// Public resource (if visible).
    pub resource: Option<String>,
    /// Public outcome (if visible).
    pub outcome: Option<String>,
    /// Encryption policy used.
    pub policy: EncryptionPolicy,
    /// Key ID used for encryption.
    pub key_id: Option<String>,
    /// Commitment to the full event.
    pub commitment: [u8; 32],
    /// Merkle root of event chunks.
    pub merkle_root: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypted Event
// ═══════════════════════════════════════════════════════════════════════════════

/// An encrypted audit event with selective field visibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEvent {
    /// Public header with visible fields.
    pub header: EncryptedEventHeader,
    /// Original event attestation signature.
    attestation_sig: Vec<u8>,
    /// HoloCrypt container (serialized).
    container: Vec<u8>,
}

impl EncryptedEvent {
    /// Get the event ID.
    pub fn id(&self) -> EventId {
        EventId(Hash::from_bytes(self.header.id))
    }

    /// Get the commitment to the event.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.header.commitment
    }

    /// Get the Merkle root.
    pub fn merkle_root(&self) -> &[u8; 32] {
        &self.header.merkle_root
    }

    /// Get the encryption policy.
    pub fn policy(&self) -> &EncryptionPolicy {
        &self.header.policy
    }

    /// Verify the container structure without decrypting.
    pub fn verify_structure(&self, key: &EventOpeningKey) -> Result<()> {
        let container: HoloCrypt<EncryptedPayload> = serde_json::from_slice(&self.container)?;

        container
            .verify_structure(key.verifying_key())
            .map_err(|e| HoloCryptError::CryptoError {
                reason: e.to_string(),
            })
    }

    /// Decrypt the event using the opening key.
    pub fn decrypt(&self, key: &EventOpeningKey) -> Result<AuditEvent> {
        // Verify key ID matches if specified
        if let Some(ref expected_key) = self.header.key_id {
            if key.key_id() != expected_key {
                return Err(HoloCryptError::KeyNotFound {
                    key_id: expected_key.clone(),
                });
            }
        }

        // Deserialize and unseal the container
        let container: HoloCrypt<EncryptedPayload> = serde_json::from_slice(&self.container)?;

        let payload =
            container
                .unseal(&key.inner)
                .map_err(|e| HoloCryptError::DecryptionFailed {
                    reason: e.to_string(),
                })?;

        // Reconstruct the original event
        self.reconstruct_event(&payload)
    }

    /// Reconstruct the original event from payload and header.
    fn reconstruct_event(&self, payload: &EncryptedPayload) -> Result<AuditEvent> {
        // Get timestamp from either header or payload
        let timestamp = self.header.timestamp.or_else(|| {
            payload
                .timestamp
                .map(|ts| DateTime::from_timestamp_millis(ts).unwrap_or_else(Utc::now))
        });

        // Get event type
        let event_type_str = self
            .header
            .event_type
            .as_ref()
            .or(payload.event_type.as_ref())
            .ok_or_else(|| HoloCryptError::FieldNotAvailable {
                field: "event_type".to_string(),
            })?;

        // Get actor
        let actor_str = self
            .header
            .actor
            .as_ref()
            .or(payload.actor.as_ref())
            .ok_or_else(|| HoloCryptError::FieldNotAvailable {
                field: "actor".to_string(),
            })?;

        // Get resource
        let resource_str = self
            .header
            .resource
            .as_ref()
            .or(payload.resource.as_ref())
            .ok_or_else(|| HoloCryptError::FieldNotAvailable {
                field: "resource".to_string(),
            })?;

        // Get outcome
        let outcome_str = self
            .header
            .outcome
            .as_ref()
            .or(payload.outcome.as_ref())
            .ok_or_else(|| HoloCryptError::FieldNotAvailable {
                field: "outcome".to_string(),
            })?;

        // Get metadata
        let metadata = payload.metadata.clone().unwrap_or_default();

        // Parse the fields back into types
        // Note: In production, these would be properly serialized/deserialized
        let event_type: EventType = serde_json::from_str(event_type_str)
            .map_err(|e| HoloCryptError::SerializationError(format!("event_type: {}", e)))?;

        let actor: ActorId = serde_json::from_str(actor_str)
            .map_err(|e| HoloCryptError::SerializationError(format!("actor: {}", e)))?;

        let resource: ResourceId = serde_json::from_str(resource_str)
            .map_err(|e| HoloCryptError::SerializationError(format!("resource: {}", e)))?;

        let outcome: Outcome = serde_json::from_str(outcome_str)
            .map_err(|e| HoloCryptError::SerializationError(format!("outcome: {}", e)))?;

        // Reconstruct attestation from stored bytes
        let attestation: moloch_core::event::Attestation =
            serde_json::from_slice(&self.attestation_sig).map_err(|e| {
                HoloCryptError::ValidationFailed {
                    reason: format!("invalid attestation: {}", e),
                }
            })?;

        Ok(AuditEvent {
            event_time: timestamp.unwrap_or_else(Utc::now),
            event_type,
            actor,
            resource,
            outcome,
            metadata,
            attestation,
        })
    }

    /// Get public fields as a map.
    pub fn public_fields(&self) -> HashMap<String, String> {
        let mut fields = HashMap::new();

        if let Some(ref ts) = self.header.timestamp {
            fields.insert("timestamp".to_string(), ts.to_rfc3339());
        }
        if let Some(ref et) = self.header.event_type {
            fields.insert("event_type".to_string(), et.clone());
        }
        if let Some(ref actor) = self.header.actor {
            fields.insert("actor".to_string(), actor.clone());
        }
        if let Some(ref resource) = self.header.resource {
            fields.insert("resource".to_string(), resource.clone());
        }
        if let Some(ref outcome) = self.header.outcome {
            fields.insert("outcome".to_string(), outcome.clone());
        }

        fields
    }

    /// Check if a field is publicly visible.
    pub fn is_field_public(&self, field: &str) -> bool {
        match field {
            "timestamp" => self.header.timestamp.is_some(),
            "event_type" => self.header.event_type.is_some(),
            "actor" => self.header.actor.is_some(),
            "resource" => self.header.resource.is_some(),
            "outcome" => self.header.outcome.is_some(),
            _ => false,
        }
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
// Encrypted Event Builder
// ═══════════════════════════════════════════════════════════════════════════════

/// Builder for creating encrypted events.
pub struct EncryptedEventBuilder {
    event: Option<AuditEvent>,
    policy: EncryptionPolicy,
}

impl Default for EncryptedEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptedEventBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            event: None,
            policy: EncryptionPolicy::default(),
        }
    }

    /// Set the event to encrypt.
    pub fn event(mut self, event: AuditEvent) -> Self {
        self.event = Some(event);
        self
    }

    /// Set the encryption policy.
    pub fn policy(mut self, policy: EncryptionPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Set event type visibility.
    pub fn event_type_visibility(mut self, visibility: FieldVisibility) -> Self {
        self.policy.event_type = visibility;
        self
    }

    /// Set actor visibility.
    pub fn actor_visibility(mut self, visibility: FieldVisibility) -> Self {
        self.policy.actor = visibility;
        self
    }

    /// Set resource visibility.
    pub fn resource_visibility(mut self, visibility: FieldVisibility) -> Self {
        self.policy.resource = visibility;
        self
    }

    /// Set outcome visibility.
    pub fn outcome_visibility(mut self, visibility: FieldVisibility) -> Self {
        self.policy.outcome = visibility;
        self
    }

    /// Set metadata visibility.
    pub fn metadata_visibility(mut self, visibility: FieldVisibility) -> Self {
        self.policy.metadata = visibility;
        self
    }

    /// Set timestamp visibility.
    pub fn timestamp_visibility(mut self, visibility: FieldVisibility) -> Self {
        self.policy.timestamp = visibility;
        self
    }

    /// Build the encrypted event.
    pub fn build(self, key: &EventSealingKey) -> Result<EncryptedEvent> {
        let event = self
            .event
            .ok_or_else(|| HoloCryptError::InvalidConfiguration {
                reason: "event not set".to_string(),
            })?;

        // Serialize fields based on visibility
        let event_type_str = serde_json::to_string(&event.event_type)?;
        let actor_str = serde_json::to_string(&event.actor)?;
        let resource_str = serde_json::to_string(&event.resource)?;
        let outcome_str = serde_json::to_string(&event.outcome)?;

        // Build encrypted payload (fields not in header)
        let payload = EncryptedPayload {
            event_type: if self.policy.event_type != FieldVisibility::Public {
                Some(event_type_str.clone())
            } else {
                None
            },
            actor: if self.policy.actor != FieldVisibility::Public {
                Some(actor_str.clone())
            } else {
                None
            },
            resource: if self.policy.resource != FieldVisibility::Public {
                Some(resource_str.clone())
            } else {
                None
            },
            outcome: if self.policy.outcome != FieldVisibility::Public {
                Some(outcome_str.clone())
            } else {
                None
            },
            metadata: if self.policy.metadata != FieldVisibility::Public {
                Some(event.metadata.clone())
            } else {
                None
            },
            timestamp: if self.policy.timestamp != FieldVisibility::Public {
                Some(event.event_time.timestamp_millis())
            } else {
                None
            },
        };

        // Seal the payload in HoloCrypt container
        let container = HoloCrypt::seal(&payload, &key.inner).map_err(|e| {
            HoloCryptError::EncryptionFailed {
                reason: e.to_string(),
            }
        })?;

        // Build public header
        let header = EncryptedEventHeader {
            id: *container.commitment(), // Use commitment as ID
            timestamp: if self.policy.timestamp == FieldVisibility::Public {
                Some(event.event_time)
            } else {
                None
            },
            event_type: if self.policy.event_type == FieldVisibility::Public {
                Some(event_type_str)
            } else {
                None
            },
            actor: if self.policy.actor == FieldVisibility::Public {
                Some(actor_str)
            } else {
                None
            },
            resource: if self.policy.resource == FieldVisibility::Public {
                Some(resource_str)
            } else {
                None
            },
            outcome: if self.policy.outcome == FieldVisibility::Public {
                Some(outcome_str)
            } else {
                None
            },
            policy: self.policy.clone(),
            key_id: Some(key.key_id().to_string()),
            commitment: *container.commitment(),
            merkle_root: *container.merkle_root(),
        };

        // Serialize attestation
        let attestation_sig = serde_json::to_vec(&event.attestation)?;

        // Serialize container
        let container_bytes = serde_json::to_vec(&container)?;

        Ok(EncryptedEvent {
            header,
            attestation_sig,
            container: container_bytes,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Key Manager
// ═══════════════════════════════════════════════════════════════════════════════

/// Manager for encryption keys with rotation support.
#[derive(Default)]
pub struct KeyManager {
    keys: HashMap<String, EventOpeningKey>,
    current_key_id: Option<String>,
}

impl KeyManager {
    /// Create a new key manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key to the manager.
    pub fn add_key(&mut self, key: EventOpeningKey) {
        let key_id = key.key_id().to_string();
        self.keys.insert(key_id.clone(), key);

        // First key becomes current
        if self.current_key_id.is_none() {
            self.current_key_id = Some(key_id);
        }
    }

    /// Set the current key for new encryptions.
    pub fn set_current(&mut self, key_id: &str) -> Result<()> {
        if self.keys.contains_key(key_id) {
            self.current_key_id = Some(key_id.to_string());
            Ok(())
        } else {
            Err(HoloCryptError::KeyNotFound {
                key_id: key_id.to_string(),
            })
        }
    }

    /// Get a key by ID.
    pub fn get_key(&self, key_id: &str) -> Option<&EventOpeningKey> {
        self.keys.get(key_id)
    }

    /// Get the current key ID.
    pub fn current_key_id(&self) -> Option<&str> {
        self.current_key_id.as_deref()
    }

    /// Decrypt an event using the appropriate key.
    pub fn decrypt(&self, encrypted: &EncryptedEvent) -> Result<AuditEvent> {
        let key_id =
            encrypted
                .header
                .key_id
                .as_ref()
                .ok_or_else(|| HoloCryptError::KeyNotFound {
                    key_id: "unknown".to_string(),
                })?;

        let key = self
            .keys
            .get(key_id)
            .ok_or_else(|| HoloCryptError::KeyNotFound {
                key_id: key_id.clone(),
            })?;

        encrypted.decrypt(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;
    use moloch_core::event::{ActorKind, ResourceKind};

    fn make_test_event(key: &SecretKey) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test-repo");

        AuditEvent::builder()
            .now()
            .event_type(EventType::RepoCreated)
            .actor(actor)
            .resource(resource)
            .outcome(Outcome::Success)
            .metadata(serde_json::json!({"action": "test"}))
            .sign(key)
            .unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let (sealing_key, opening_key) = generate_keypair("test-key-1");

        let encrypted = EncryptedEventBuilder::new()
            .event(event.clone())
            .policy(EncryptionPolicy::default())
            .build(&sealing_key)
            .unwrap();

        let decrypted = encrypted.decrypt(&opening_key).unwrap();

        assert_eq!(event.event_type, decrypted.event_type);
        assert_eq!(event.outcome, decrypted.outcome);
    }

    #[test]
    fn test_public_fields_visible() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let (sealing_key, _) = generate_keypair("test-key-2");

        let encrypted = EncryptedEventBuilder::new()
            .event(event)
            .event_type_visibility(FieldVisibility::Public)
            .timestamp_visibility(FieldVisibility::Public)
            .build(&sealing_key)
            .unwrap();

        assert!(encrypted.is_field_public("event_type"));
        assert!(encrypted.is_field_public("timestamp"));
        assert!(!encrypted.is_field_public("actor"));
        assert!(!encrypted.is_field_public("metadata"));
    }

    #[test]
    fn test_all_public_policy() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let (sealing_key, opening_key) = generate_keypair("test-key-3");

        let encrypted = EncryptedEventBuilder::new()
            .event(event.clone())
            .policy(EncryptionPolicy::all_public())
            .build(&sealing_key)
            .unwrap();

        // All fields should be in header
        assert!(encrypted.is_field_public("event_type"));
        assert!(encrypted.is_field_public("actor"));
        assert!(encrypted.is_field_public("resource"));

        // Should still decrypt correctly
        let decrypted = encrypted.decrypt(&opening_key).unwrap();
        assert_eq!(event.event_type, decrypted.event_type);
    }

    #[test]
    fn test_verify_structure() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let (sealing_key, opening_key) = generate_keypair("test-key-4");

        let encrypted = EncryptedEventBuilder::new()
            .event(event)
            .build(&sealing_key)
            .unwrap();

        // Should verify without decrypting
        assert!(encrypted.verify_structure(&opening_key).is_ok());
    }

    #[test]
    fn test_wrong_key_fails() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let (sealing_key, _) = generate_keypair("key-1");
        let (_, wrong_opening_key) = generate_keypair("key-2");

        let encrypted = EncryptedEventBuilder::new()
            .event(event)
            .build(&sealing_key)
            .unwrap();

        // Wrong key should fail
        let result = encrypted.decrypt(&wrong_opening_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_manager() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let (sealing_key, opening_key) = generate_keypair("managed-key");

        let mut manager = KeyManager::new();
        manager.add_key(opening_key);

        let encrypted = EncryptedEventBuilder::new()
            .event(event.clone())
            .build(&sealing_key)
            .unwrap();

        let decrypted = manager.decrypt(&encrypted).unwrap();
        assert_eq!(event.event_type, decrypted.event_type);
    }

    #[test]
    fn test_serialization() {
        let signing_key = SecretKey::generate();
        let event = make_test_event(&signing_key);

        let (sealing_key, opening_key) = generate_keypair("serial-key");

        let encrypted = EncryptedEventBuilder::new()
            .event(event.clone())
            .build(&sealing_key)
            .unwrap();

        let bytes = encrypted.to_bytes();
        let restored = EncryptedEvent::from_bytes(&bytes).unwrap();

        let decrypted = restored.decrypt(&opening_key).unwrap();
        assert_eq!(event.event_type, decrypted.event_type);
    }

    #[test]
    fn test_policy_with_key_id() {
        let policy = EncryptionPolicy::default().with_key_id("rotation-key-v2");
        assert_eq!(policy.key_id, Some("rotation-key-v2".to_string()));
    }
}
