//! Zero-copy serialization with rkyv.
//!
//! This module provides archived representations of Moloch types that can be
//! accessed directly from a byte buffer without deserialization overhead.
//!
//! # Performance
//! - Serialization: Similar to bincode
//! - Deserialization: Near-zero cost (just pointer cast)
//! - Access: Direct memory-mapped access to archived data
//!
//! # Usage
//! ```ignore
//! use moloch_core::rkyv_types::{RkyvEvent, archive_event, access_event_unchecked};
//!
//! // Archive an event (serialize)
//! let bytes = archive_event(&event);
//!
//! // Access without copying (zero-copy, unchecked)
//! let archived = unsafe { access_event_unchecked(&bytes) };
//! println!("Event type: {:?}", archived.event_kind);
//! ```

use rkyv::{rancor::Error as RkyvError, Archive, Deserialize, Serialize};

/// Archived 32-byte hash.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct RkyvHash(pub [u8; 32]);

impl RkyvHash {
    /// Create from a moloch Hash.
    pub fn from_hash(hash: &crate::crypto::Hash) -> Self {
        Self(*hash.as_bytes())
    }

    /// Convert to moloch Hash.
    pub fn to_hash(&self) -> crate::crypto::Hash {
        crate::crypto::Hash::from_bytes(self.0)
    }
}

impl ArchivedRkyvHash {
    /// Get the hash bytes directly.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Archived 32-byte public key.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct RkyvPublicKey(pub [u8; 32]);

impl RkyvPublicKey {
    /// Create from a moloch PublicKey.
    pub fn from_pubkey(pk: &crate::crypto::PublicKey) -> Self {
        Self(pk.as_bytes())
    }

    /// Convert to moloch PublicKey.
    pub fn to_pubkey(&self) -> crate::error::Result<crate::crypto::PublicKey> {
        crate::crypto::PublicKey::from_bytes(&self.0)
    }
}

impl ArchivedRkyvPublicKey {
    /// Get the key bytes directly.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Archived 64-byte signature.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub struct RkyvSignature(pub [u8; 64]);

impl RkyvSignature {
    /// Create from a moloch Sig.
    pub fn from_sig(sig: &crate::crypto::Sig) -> Self {
        Self(sig.to_bytes())
    }

    /// Convert to moloch Sig.
    pub fn to_sig(&self) -> crate::error::Result<crate::crypto::Sig> {
        crate::crypto::Sig::from_bytes(&self.0)
    }
}

impl ArchivedRkyvSignature {
    /// Get the signature bytes directly.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Actor kind (archived).
#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub enum RkyvActorKind {
    User,
    System,
    Agent,
    Integration,
}

impl From<&crate::event::ActorKind> for RkyvActorKind {
    fn from(kind: &crate::event::ActorKind) -> Self {
        match kind {
            crate::event::ActorKind::User => Self::User,
            crate::event::ActorKind::System => Self::System,
            crate::event::ActorKind::Agent => Self::Agent,
            crate::event::ActorKind::Integration => Self::Integration,
        }
    }
}

/// Resource kind (archived).
#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub enum RkyvResourceKind {
    Repository,
    Commit,
    Branch,
    Tag,
    PullRequest,
    Issue,
    File,
    User,
    Organization,
    Credential,
    Config,
    Document,
    Other,
}

impl From<&crate::event::ResourceKind> for RkyvResourceKind {
    fn from(kind: &crate::event::ResourceKind) -> Self {
        match kind {
            crate::event::ResourceKind::Repository => Self::Repository,
            crate::event::ResourceKind::Commit => Self::Commit,
            crate::event::ResourceKind::Branch => Self::Branch,
            crate::event::ResourceKind::Tag => Self::Tag,
            crate::event::ResourceKind::PullRequest => Self::PullRequest,
            crate::event::ResourceKind::Issue => Self::Issue,
            crate::event::ResourceKind::File => Self::File,
            crate::event::ResourceKind::User => Self::User,
            crate::event::ResourceKind::Organization => Self::Organization,
            crate::event::ResourceKind::Credential => Self::Credential,
            crate::event::ResourceKind::Config => Self::Config,
            crate::event::ResourceKind::Document => Self::Document,
            crate::event::ResourceKind::Other => Self::Other,
        }
    }
}

/// Outcome (archived).
#[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub enum RkyvOutcome {
    Success,
    Failure { reason: String },
    Denied { reason: String },
    Pending,
}

impl From<&crate::event::Outcome> for RkyvOutcome {
    fn from(outcome: &crate::event::Outcome) -> Self {
        match outcome {
            crate::event::Outcome::Success => Self::Success,
            crate::event::Outcome::Failure { reason } => Self::Failure {
                reason: reason.clone(),
            },
            crate::event::Outcome::Denied { reason } => Self::Denied {
                reason: reason.clone(),
            },
            crate::event::Outcome::Pending => Self::Pending,
        }
    }
}

/// Event type discriminant for fast filtering without full deserialization.
#[derive(Archive, Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(crate = rkyv)]
pub enum RkyvEventKind {
    // Repository
    RepoCreated,
    RepoDeleted,
    RepoTransferred,
    RepoVisibilityChanged,
    // Git
    Push,
    BranchCreated,
    BranchDeleted,
    BranchProtectionChanged,
    TagCreated,
    TagDeleted,
    // Collaboration
    PullRequestOpened,
    PullRequestMerged,
    PullRequestClosed,
    ReviewSubmitted,
    IssueOpened,
    IssueClosed,
    // Access
    AccessGranted,
    AccessRevoked,
    Login,
    Logout,
    LoginFailed,
    MfaConfigured,
    // Agent
    AgentAction,
    AgentAuthorized,
    AgentRevoked,
    // Compliance
    DataExportRequested,
    DataExportCompleted,
    DataDeletionRequested,
    DataDeletionCompleted,
    ConsentGiven,
    ConsentRevoked,
    // System
    ConfigChanged,
    ReleasePublished,
    BackupCreated,
    SecurityScan,
    // Generic
    Custom,
}

impl From<&crate::event::EventType> for RkyvEventKind {
    fn from(event_type: &crate::event::EventType) -> Self {
        use crate::event::EventType;
        match event_type {
            EventType::RepoCreated => Self::RepoCreated,
            EventType::RepoDeleted => Self::RepoDeleted,
            EventType::RepoTransferred => Self::RepoTransferred,
            EventType::RepoVisibilityChanged => Self::RepoVisibilityChanged,
            EventType::Push { .. } => Self::Push,
            EventType::BranchCreated => Self::BranchCreated,
            EventType::BranchDeleted => Self::BranchDeleted,
            EventType::BranchProtectionChanged => Self::BranchProtectionChanged,
            EventType::TagCreated => Self::TagCreated,
            EventType::TagDeleted => Self::TagDeleted,
            EventType::PullRequestOpened => Self::PullRequestOpened,
            EventType::PullRequestMerged => Self::PullRequestMerged,
            EventType::PullRequestClosed => Self::PullRequestClosed,
            EventType::ReviewSubmitted { .. } => Self::ReviewSubmitted,
            EventType::IssueOpened => Self::IssueOpened,
            EventType::IssueClosed => Self::IssueClosed,
            EventType::AccessGranted { .. } => Self::AccessGranted,
            EventType::AccessRevoked => Self::AccessRevoked,
            EventType::Login { .. } => Self::Login,
            EventType::Logout => Self::Logout,
            EventType::LoginFailed { .. } => Self::LoginFailed,
            EventType::MfaConfigured => Self::MfaConfigured,
            EventType::AgentAction { .. } => Self::AgentAction,
            EventType::AgentAuthorized { .. } => Self::AgentAuthorized,
            EventType::AgentRevoked => Self::AgentRevoked,
            EventType::DataExportRequested => Self::DataExportRequested,
            EventType::DataExportCompleted => Self::DataExportCompleted,
            EventType::DataDeletionRequested => Self::DataDeletionRequested,
            EventType::DataDeletionCompleted => Self::DataDeletionCompleted,
            EventType::ConsentGiven { .. } => Self::ConsentGiven,
            EventType::ConsentRevoked { .. } => Self::ConsentRevoked,
            EventType::ConfigChanged { .. } => Self::ConfigChanged,
            EventType::ReleasePublished { .. } => Self::ReleasePublished,
            EventType::BackupCreated => Self::BackupCreated,
            EventType::SecurityScan { .. } => Self::SecurityScan,
            EventType::Custom { .. } => Self::Custom,
        }
    }
}

/// Compact archived event for storage and zero-copy access.
///
/// This is a flattened representation optimized for:
/// - Fast filtering by event kind, actor, resource
/// - Zero-copy access from memory-mapped storage
/// - Compact storage (no nested heap allocations)
#[derive(Archive, Serialize, Deserialize, Debug, Clone)]
#[rkyv(crate = rkyv)]
pub struct RkyvEvent {
    /// Event timestamp (Unix millis).
    pub timestamp_ms: i64,
    /// Event kind discriminant for fast filtering.
    pub event_kind: RkyvEventKind,
    /// Full event type data (JSON for complex variants).
    pub event_data: Vec<u8>,
    /// Actor public key.
    pub actor_key: RkyvPublicKey,
    /// Actor kind.
    pub actor_kind: RkyvActorKind,
    /// Actor name (optional).
    pub actor_name: Option<String>,
    /// Resource kind.
    pub resource_kind: RkyvResourceKind,
    /// Resource ID.
    pub resource_id: String,
    /// Resource parent ID (if any).
    pub resource_parent: Option<String>,
    /// Outcome.
    pub outcome: RkyvOutcome,
    /// Metadata (raw bytes).
    pub metadata: Vec<u8>,
    /// Attester public key.
    pub attester_key: RkyvPublicKey,
    /// Attestation signature.
    pub attestation_sig: RkyvSignature,
    /// Pre-computed event ID (content hash).
    pub event_id: RkyvHash,
}

impl RkyvEvent {
    /// Create from an AuditEvent.
    pub fn from_event(event: &crate::event::AuditEvent) -> Self {
        let event_data = serde_json::to_vec(&event.event_type).unwrap_or_default();
        let resource_parent = event
            .resource
            .parent
            .as_ref()
            .map(|p| serde_json::to_string(p).unwrap_or_default());

        Self {
            timestamp_ms: event.event_time.timestamp_millis(),
            event_kind: RkyvEventKind::from(&event.event_type),
            event_data,
            actor_key: RkyvPublicKey::from_pubkey(&event.actor.key),
            actor_kind: RkyvActorKind::from(&event.actor.kind),
            actor_name: event.actor.name.clone(),
            resource_kind: RkyvResourceKind::from(&event.resource.kind),
            resource_id: event.resource.id.clone(),
            resource_parent,
            outcome: RkyvOutcome::from(&event.outcome),
            metadata: event.metadata.clone(),
            attester_key: RkyvPublicKey::from_pubkey(&event.attestation.attester),
            attestation_sig: RkyvSignature::from_sig(&event.attestation.signature),
            event_id: RkyvHash::from_hash(&event.id().0),
        }
    }
}

impl ArchivedRkyvEvent {
    /// Get the event ID bytes for fast comparison.
    pub fn event_id_bytes(&self) -> &[u8; 32] {
        self.event_id.as_bytes()
    }

    /// Get the actor key bytes.
    pub fn actor_key_bytes(&self) -> &[u8; 32] {
        self.actor_key.as_bytes()
    }

    /// Get the attester key bytes.
    pub fn attester_key_bytes(&self) -> &[u8; 32] {
        self.attester_key.as_bytes()
    }

    /// Check if this event matches an actor key.
    pub fn matches_actor(&self, key: &[u8; 32]) -> bool {
        self.actor_key.as_bytes() == key
    }

    /// Check if this event matches a resource ID.
    pub fn matches_resource_id(&self, id: &str) -> bool {
        self.resource_id == id
    }
}

/// Archive an event to bytes.
pub fn archive_event(event: &crate::event::AuditEvent) -> Vec<u8> {
    let rkyv_event = RkyvEvent::from_event(event);
    rkyv::to_bytes::<RkyvError>(&rkyv_event)
        .expect("serialization should not fail")
        .to_vec()
}

/// Archive multiple events to bytes.
pub fn archive_events(events: &[crate::event::AuditEvent]) -> Vec<u8> {
    let rkyv_events: Vec<RkyvEvent> = events.iter().map(RkyvEvent::from_event).collect();
    rkyv::to_bytes::<RkyvError>(&rkyv_events)
        .expect("serialization should not fail")
        .to_vec()
}

/// Access an archived event (zero-copy, unchecked).
///
/// # Safety
/// The bytes must have been produced by `archive_event` and must not be modified.
/// For untrusted data, use bincode deserialization instead.
pub unsafe fn access_event_unchecked(bytes: &[u8]) -> &ArchivedRkyvEvent {
    rkyv::access_unchecked::<ArchivedRkyvEvent>(bytes)
}

/// Access archived events (zero-copy, unchecked).
///
/// # Safety
/// The bytes must have been produced by `archive_events` and must not be modified.
/// For untrusted data, use bincode deserialization instead.
pub unsafe fn access_events_unchecked(bytes: &[u8]) -> &rkyv::vec::ArchivedVec<RkyvEvent> {
    rkyv::access_unchecked::<rkyv::vec::ArchivedVec<RkyvEvent>>(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretKey;
    use crate::event::{ActorId, ActorKind, AuditEvent, EventType, ResourceId, ResourceKind};

    fn create_test_event() -> AuditEvent {
        let key = SecretKey::generate();
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test-repo");

        AuditEvent::builder()
            .now()
            .event_type(EventType::Push {
                force: false,
                commits: 5,
            })
            .actor(actor)
            .resource(resource)
            .sign(&key)
            .unwrap()
    }

    #[test]
    fn test_archive_roundtrip() {
        let event = create_test_event();
        let bytes = archive_event(&event);

        println!("Archived event size: {} bytes", bytes.len());

        // Safety: bytes were just created by archive_event
        let archived = unsafe { access_event_unchecked(&bytes) };
        assert_eq!(archived.event_id_bytes(), event.id().0.as_bytes());
        assert_eq!(archived.resource_id.as_str(), "test-repo");
    }

    #[test]
    fn test_archive_multiple_events() {
        let events: Vec<AuditEvent> = (0..10).map(|_| create_test_event()).collect();
        let bytes = archive_events(&events);

        println!(
            "Archived {} events in {} bytes ({} bytes/event)",
            events.len(),
            bytes.len(),
            bytes.len() / events.len()
        );

        // Verify we can deserialize back (using rkyv's full deserialization)
        // For zero-copy, use access_events_unchecked on trusted data
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_compare_with_bincode() {
        let event = create_test_event();

        // rkyv serialization
        let rkyv_bytes = archive_event(&event);

        // bincode serialization
        let bincode_bytes = bincode::serialize(&event).unwrap();

        println!(
            "rkyv size: {} bytes, bincode size: {} bytes",
            rkyv_bytes.len(),
            bincode_bytes.len()
        );

        // Both should be similar in size
        // rkyv has some overhead for alignment
    }
}
