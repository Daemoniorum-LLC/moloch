//! Secondary indexes for efficient event queries.
//!
//! Provides O(1) lookup by:
//! - Actor ID
//! - Resource ID
//! - Event type
//! - Timestamp range
//!
//! Indexes are stored alongside the main chain data in the storage backend.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use moloch_core::{
    ActorId, AuditEvent, EventId, EventType, Hash, ResourceId, ResourceKind, Result,
};
use moloch_storage::ChainStore;

/// Configuration for the index engine.
#[derive(Debug, Clone)]
pub struct IndexConfig {
    /// Enable actor index.
    pub index_actors: bool,
    /// Enable resource index.
    pub index_resources: bool,
    /// Enable event type index.
    pub index_event_types: bool,
    /// Enable timestamp index.
    pub index_timestamps: bool,
    /// Maximum events to return in a single query.
    pub max_results: usize,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            index_actors: true,
            index_resources: true,
            index_event_types: true,
            index_timestamps: true,
            max_results: 10_000,
        }
    }
}

/// A key for the event type index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventTypeKey {
    RepoCreated,
    RepoDeleted,
    RepoTransferred,
    RepoVisibilityChanged,
    Push,
    BranchCreated,
    BranchDeleted,
    BranchProtectionChanged,
    TagCreated,
    TagDeleted,
    PullRequestOpened,
    PullRequestMerged,
    PullRequestClosed,
    ReviewSubmitted,
    IssueOpened,
    IssueClosed,
    AccessGranted,
    AccessRevoked,
    Login,
    Logout,
    LoginFailed,
    MfaConfigured,
    AgentAction,
    AgentAuthorized,
    AgentRevoked,
    DataExportRequested,
    DataExportCompleted,
    DataDeletionRequested,
    DataDeletionCompleted,
    ConsentGiven,
    ConsentRevoked,
    ConfigChanged,
    ReleasePublished,
    BackupCreated,
    SecurityScan,
    Custom(String),
}

impl From<&EventType> for EventTypeKey {
    fn from(et: &EventType) -> Self {
        match et {
            EventType::RepoCreated => EventTypeKey::RepoCreated,
            EventType::RepoDeleted => EventTypeKey::RepoDeleted,
            EventType::RepoTransferred => EventTypeKey::RepoTransferred,
            EventType::RepoVisibilityChanged => EventTypeKey::RepoVisibilityChanged,
            EventType::Push { .. } => EventTypeKey::Push,
            EventType::BranchCreated => EventTypeKey::BranchCreated,
            EventType::BranchDeleted => EventTypeKey::BranchDeleted,
            EventType::BranchProtectionChanged => EventTypeKey::BranchProtectionChanged,
            EventType::TagCreated => EventTypeKey::TagCreated,
            EventType::TagDeleted => EventTypeKey::TagDeleted,
            EventType::PullRequestOpened => EventTypeKey::PullRequestOpened,
            EventType::PullRequestMerged => EventTypeKey::PullRequestMerged,
            EventType::PullRequestClosed => EventTypeKey::PullRequestClosed,
            EventType::ReviewSubmitted { .. } => EventTypeKey::ReviewSubmitted,
            EventType::IssueOpened => EventTypeKey::IssueOpened,
            EventType::IssueClosed => EventTypeKey::IssueClosed,
            EventType::AccessGranted { .. } => EventTypeKey::AccessGranted,
            EventType::AccessRevoked => EventTypeKey::AccessRevoked,
            EventType::Login { .. } => EventTypeKey::Login,
            EventType::Logout => EventTypeKey::Logout,
            EventType::LoginFailed { .. } => EventTypeKey::LoginFailed,
            EventType::MfaConfigured => EventTypeKey::MfaConfigured,
            EventType::AgentAction { .. } => EventTypeKey::AgentAction,
            EventType::AgentAuthorized { .. } => EventTypeKey::AgentAuthorized,
            EventType::AgentRevoked => EventTypeKey::AgentRevoked,
            EventType::DataExportRequested => EventTypeKey::DataExportRequested,
            EventType::DataExportCompleted => EventTypeKey::DataExportCompleted,
            EventType::DataDeletionRequested => EventTypeKey::DataDeletionRequested,
            EventType::DataDeletionCompleted => EventTypeKey::DataDeletionCompleted,
            EventType::ConsentGiven { .. } => EventTypeKey::ConsentGiven,
            EventType::ConsentRevoked { .. } => EventTypeKey::ConsentRevoked,
            EventType::ConfigChanged { .. } => EventTypeKey::ConfigChanged,
            EventType::ReleasePublished { .. } => EventTypeKey::ReleasePublished,
            EventType::BackupCreated => EventTypeKey::BackupCreated,
            EventType::SecurityScan { .. } => EventTypeKey::SecurityScan,
            EventType::Custom { name } => EventTypeKey::Custom(name.clone()),
        }
    }
}

/// A key for the resource index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceKey {
    /// Resource kind.
    pub kind: ResourceKind,
    /// Resource ID.
    pub id: String,
}

impl From<&ResourceId> for ResourceKey {
    fn from(r: &ResourceId) -> Self {
        Self {
            kind: r.kind,
            id: r.id.clone(),
        }
    }
}

/// A timestamped event reference for time-range queries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimestampedEvent {
    /// Timestamp in milliseconds since epoch.
    pub timestamp_ms: i64,
    /// Event ID.
    pub event_id: EventId,
}

/// In-memory secondary indexes for events.
///
/// These indexes live alongside the main storage and provide fast lookups.
/// In a production system, these would be persisted to RocksDB column families.
#[derive(Debug)]
pub struct IndexEngine<S: ChainStore> {
    /// The underlying storage.
    storage: S,
    /// Configuration.
    config: IndexConfig,
    /// Actor ID -> Event IDs
    actor_index: RwLock<HashMap<Hash, HashSet<EventId>>>,
    /// Resource -> Event IDs
    resource_index: RwLock<HashMap<ResourceKey, HashSet<EventId>>>,
    /// Event Type -> Event IDs
    event_type_index: RwLock<HashMap<EventTypeKey, HashSet<EventId>>>,
    /// Timestamp -> Event IDs (sorted by time)
    timestamp_index: RwLock<BTreeMap<i64, HashSet<EventId>>>,
    /// Resource Kind -> Event IDs
    resource_kind_index: RwLock<HashMap<ResourceKind, HashSet<EventId>>>,
}

impl<S: ChainStore> IndexEngine<S> {
    /// Create a new index engine with the given storage.
    pub fn new(storage: S, config: IndexConfig) -> Self {
        Self {
            storage,
            config,
            actor_index: RwLock::new(HashMap::new()),
            resource_index: RwLock::new(HashMap::new()),
            event_type_index: RwLock::new(HashMap::new()),
            timestamp_index: RwLock::new(BTreeMap::new()),
            resource_kind_index: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults(storage: S) -> Self {
        Self::new(storage, IndexConfig::default())
    }

    /// Get the underlying storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Index an event.
    ///
    /// This adds the event to all enabled secondary indexes.
    pub fn index_event(&self, event: &AuditEvent) -> Result<()> {
        let event_id = event.id();

        // Index by actor
        if self.config.index_actors {
            let actor_hash = event.actor.id();
            let mut idx = self.actor_index.write().unwrap();
            idx.entry(actor_hash).or_default().insert(event_id);
        }

        // Index by resource
        if self.config.index_resources {
            let resource_key = ResourceKey::from(&event.resource);
            let mut idx = self.resource_index.write().unwrap();
            idx.entry(resource_key).or_default().insert(event_id);

            // Also index by resource kind
            let mut kind_idx = self.resource_kind_index.write().unwrap();
            kind_idx
                .entry(event.resource.kind)
                .or_default()
                .insert(event_id);
        }

        // Index by event type
        if self.config.index_event_types {
            let type_key = EventTypeKey::from(&event.event_type);
            let mut idx = self.event_type_index.write().unwrap();
            idx.entry(type_key).or_default().insert(event_id);
        }

        // Index by timestamp
        if self.config.index_timestamps {
            let ts = event.event_time.timestamp_millis();
            let mut idx = self.timestamp_index.write().unwrap();
            idx.entry(ts).or_default().insert(event_id);
        }

        Ok(())
    }

    /// Index multiple events.
    pub fn index_events(&self, events: &[AuditEvent]) -> Result<()> {
        for event in events {
            self.index_event(event)?;
        }
        Ok(())
    }

    /// Remove an event from indexes.
    pub fn unindex_event(&self, event: &AuditEvent) {
        let event_id = event.id();

        // Remove from actor index
        if self.config.index_actors {
            let actor_hash = event.actor.id();
            let mut idx = self.actor_index.write().unwrap();
            if let Some(set) = idx.get_mut(&actor_hash) {
                set.remove(&event_id);
                if set.is_empty() {
                    idx.remove(&actor_hash);
                }
            }
        }

        // Remove from resource index
        if self.config.index_resources {
            let resource_key = ResourceKey::from(&event.resource);
            let mut idx = self.resource_index.write().unwrap();
            if let Some(set) = idx.get_mut(&resource_key) {
                set.remove(&event_id);
                if set.is_empty() {
                    idx.remove(&resource_key);
                }
            }

            let mut kind_idx = self.resource_kind_index.write().unwrap();
            if let Some(set) = kind_idx.get_mut(&event.resource.kind) {
                set.remove(&event_id);
                if set.is_empty() {
                    kind_idx.remove(&event.resource.kind);
                }
            }
        }

        // Remove from event type index
        if self.config.index_event_types {
            let type_key = EventTypeKey::from(&event.event_type);
            let mut idx = self.event_type_index.write().unwrap();
            if let Some(set) = idx.get_mut(&type_key) {
                set.remove(&event_id);
                if set.is_empty() {
                    idx.remove(&type_key);
                }
            }
        }

        // Remove from timestamp index
        if self.config.index_timestamps {
            let ts = event.event_time.timestamp_millis();
            let mut idx = self.timestamp_index.write().unwrap();
            if let Some(set) = idx.get_mut(&ts) {
                set.remove(&event_id);
                if set.is_empty() {
                    idx.remove(&ts);
                }
            }
        }
    }

    /// Query events by actor.
    pub fn events_by_actor(&self, actor: &ActorId) -> Vec<EventId> {
        let actor_hash = actor.id();
        let idx = self.actor_index.read().unwrap();
        idx.get(&actor_hash)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Query events by actor hash directly.
    pub fn events_by_actor_hash(&self, actor_hash: &Hash) -> Vec<EventId> {
        let idx = self.actor_index.read().unwrap();
        idx.get(actor_hash)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Query events by resource.
    pub fn events_by_resource(&self, resource: &ResourceId) -> Vec<EventId> {
        let key = ResourceKey::from(resource);
        let idx = self.resource_index.read().unwrap();
        idx.get(&key)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Query events by resource kind.
    pub fn events_by_resource_kind(&self, kind: ResourceKind) -> Vec<EventId> {
        let idx = self.resource_kind_index.read().unwrap();
        idx.get(&kind)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Query events by event type.
    pub fn events_by_type(&self, event_type: &EventType) -> Vec<EventId> {
        let key = EventTypeKey::from(event_type);
        self.events_by_type_key(&key)
    }

    /// Query events by event type key.
    pub fn events_by_type_key(&self, key: &EventTypeKey) -> Vec<EventId> {
        let idx = self.event_type_index.read().unwrap();
        idx.get(key)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Query events in a time range.
    ///
    /// Returns events ordered by timestamp (ascending).
    pub fn events_in_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<TimestampedEvent> {
        let start_ms = start.timestamp_millis();
        let end_ms = end.timestamp_millis();

        let idx = self.timestamp_index.read().unwrap();
        let mut results = Vec::new();

        for (&ts, events) in idx.range(start_ms..=end_ms) {
            for &event_id in events {
                results.push(TimestampedEvent {
                    timestamp_ms: ts,
                    event_id,
                });
            }
        }

        // Sort by timestamp
        results.sort();
        results
    }

    /// Query events in a time range, returning just IDs.
    pub fn event_ids_in_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<EventId> {
        self.events_in_time_range(start, end)
            .into_iter()
            .map(|te| te.event_id)
            .collect()
    }

    /// Intersect two sets of event IDs.
    pub fn intersect(&self, a: &[EventId], b: &[EventId]) -> Vec<EventId> {
        let set_b: HashSet<_> = b.iter().collect();
        a.iter().filter(|id| set_b.contains(id)).copied().collect()
    }

    /// Union two sets of event IDs.
    pub fn union(&self, a: &[EventId], b: &[EventId]) -> Vec<EventId> {
        let mut set: HashSet<_> = a.iter().copied().collect();
        set.extend(b.iter().copied());
        set.into_iter().collect()
    }

    /// Get index statistics.
    pub fn stats(&self) -> IndexStats {
        let actor_count = self.actor_index.read().unwrap().len();
        let resource_count = self.resource_index.read().unwrap().len();
        let event_type_count = self.event_type_index.read().unwrap().len();
        let timestamp_count = self.timestamp_index.read().unwrap().len();

        let total_actor_events: usize = self
            .actor_index
            .read()
            .unwrap()
            .values()
            .map(|s| s.len())
            .sum();

        IndexStats {
            unique_actors: actor_count,
            unique_resources: resource_count,
            unique_event_types: event_type_count,
            unique_timestamps: timestamp_count,
            total_indexed_events: total_actor_events,
        }
    }

    /// Clear all indexes.
    pub fn clear(&self) {
        self.actor_index.write().unwrap().clear();
        self.resource_index.write().unwrap().clear();
        self.event_type_index.write().unwrap().clear();
        self.timestamp_index.write().unwrap().clear();
        self.resource_kind_index.write().unwrap().clear();
    }

    /// Rebuild indexes from storage.
    ///
    /// This scans all blocks and re-indexes their events.
    pub fn rebuild(&self) -> Result<u64> {
        self.clear();

        let mut count = 0u64;
        let latest = self.storage.latest_height()?;

        if let Some(height) = latest {
            for h in 0..=height {
                if let Some(block) = self.storage.get_block(h)? {
                    for event in &block.events {
                        self.index_event(event)?;
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }
}

/// Index statistics.
#[derive(Debug, Clone)]
pub struct IndexStats {
    /// Number of unique actors indexed.
    pub unique_actors: usize,
    /// Number of unique resources indexed.
    pub unique_resources: usize,
    /// Number of unique event types indexed.
    pub unique_event_types: usize,
    /// Number of unique timestamps indexed.
    pub unique_timestamps: usize,
    /// Total number of indexed event references.
    pub total_indexed_events: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use moloch_core::{
        crypto::SecretKey,
        event::{ActorKind, Outcome},
    };
    use moloch_storage::RocksStorage;
    use std::sync::Arc;

    fn test_event(key: &SecretKey, resource_id: &str) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, resource_id);

        AuditEvent::builder()
            .now()
            .event_type(EventType::Push {
                force: false,
                commits: 1,
            })
            .actor(actor)
            .resource(resource)
            .sign(key)
            .unwrap()
    }

    fn test_engine() -> IndexEngine<RocksStorage> {
        let storage = RocksStorage::open_temp().unwrap();
        IndexEngine::with_defaults(storage)
    }

    #[test]
    fn test_index_event() {
        let engine = test_engine();
        let key = SecretKey::generate();
        let event = test_event(&key, "test-repo");

        engine.index_event(&event).unwrap();

        let stats = engine.stats();
        assert_eq!(stats.unique_actors, 1);
        assert_eq!(stats.unique_resources, 1);
        assert_eq!(stats.unique_event_types, 1);
        assert_eq!(stats.total_indexed_events, 1);
    }

    #[test]
    fn test_query_by_actor() {
        let engine = test_engine();
        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();

        let event1 = test_event(&key1, "repo1");
        let event2 = test_event(&key1, "repo2");
        let event3 = test_event(&key2, "repo3");

        engine.index_event(&event1).unwrap();
        engine.index_event(&event2).unwrap();
        engine.index_event(&event3).unwrap();

        // Query by actor 1
        let actor1 = ActorId::new(key1.public_key(), ActorKind::User);
        let results = engine.events_by_actor(&actor1);
        assert_eq!(results.len(), 2);
        assert!(results.contains(&event1.id()));
        assert!(results.contains(&event2.id()));

        // Query by actor 2
        let actor2 = ActorId::new(key2.public_key(), ActorKind::User);
        let results = engine.events_by_actor(&actor2);
        assert_eq!(results.len(), 1);
        assert!(results.contains(&event3.id()));
    }

    #[test]
    fn test_query_by_resource() {
        let engine = test_engine();
        let key = SecretKey::generate();

        let event1 = test_event(&key, "repo-a");
        let event2 = test_event(&key, "repo-b");

        engine.index_event(&event1).unwrap();
        engine.index_event(&event2).unwrap();

        let resource = ResourceId::new(ResourceKind::Repository, "repo-a");
        let results = engine.events_by_resource(&resource);
        assert_eq!(results.len(), 1);
        assert!(results.contains(&event1.id()));
    }

    #[test]
    fn test_query_by_resource_kind() {
        let engine = test_engine();
        let key = SecretKey::generate();

        // Create events with different resource kinds
        let actor = ActorId::new(key.public_key(), ActorKind::User);

        let event1 = AuditEvent::builder()
            .now()
            .event_type(EventType::Push {
                force: false,
                commits: 1,
            })
            .actor(actor.clone())
            .resource(ResourceId::new(ResourceKind::Repository, "repo1"))
            .sign(&key)
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1));

        let event2 = AuditEvent::builder()
            .now()
            .event_type(EventType::IssueOpened)
            .actor(actor.clone())
            .resource(ResourceId::new(ResourceKind::Issue, "issue1"))
            .sign(&key)
            .unwrap();

        engine.index_event(&event1).unwrap();
        engine.index_event(&event2).unwrap();

        let repo_events = engine.events_by_resource_kind(ResourceKind::Repository);
        assert_eq!(repo_events.len(), 1);
        assert!(repo_events.contains(&event1.id()));

        let issue_events = engine.events_by_resource_kind(ResourceKind::Issue);
        assert_eq!(issue_events.len(), 1);
        assert!(issue_events.contains(&event2.id()));
    }

    #[test]
    fn test_query_by_event_type() {
        let engine = test_engine();
        let key = SecretKey::generate();
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test");

        let push_event = AuditEvent::builder()
            .now()
            .event_type(EventType::Push {
                force: false,
                commits: 1,
            })
            .actor(actor.clone())
            .resource(resource.clone())
            .sign(&key)
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1));

        let create_event = AuditEvent::builder()
            .now()
            .event_type(EventType::BranchCreated)
            .actor(actor)
            .resource(resource)
            .sign(&key)
            .unwrap();

        engine.index_event(&push_event).unwrap();
        engine.index_event(&create_event).unwrap();

        let push_results = engine.events_by_type_key(&EventTypeKey::Push);
        assert_eq!(push_results.len(), 1);
        assert!(push_results.contains(&push_event.id()));

        let branch_results = engine.events_by_type_key(&EventTypeKey::BranchCreated);
        assert_eq!(branch_results.len(), 1);
        assert!(branch_results.contains(&create_event.id()));
    }

    #[test]
    fn test_query_by_time_range() {
        let engine = test_engine();
        let key = SecretKey::generate();

        let event1 = test_event(&key, "repo1");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let event2 = test_event(&key, "repo2");

        let start = Utc::now() - Duration::seconds(1);

        engine.index_event(&event1).unwrap();
        engine.index_event(&event2).unwrap();

        let end = Utc::now() + Duration::seconds(1);

        let results = engine.events_in_time_range(start, end);
        assert_eq!(results.len(), 2);

        // Verify ordering (earlier first)
        assert!(results[0].timestamp_ms <= results[1].timestamp_ms);
    }

    #[test]
    fn test_unindex_event() {
        let engine = test_engine();
        let key = SecretKey::generate();
        let event = test_event(&key, "test-repo");

        engine.index_event(&event).unwrap();
        assert_eq!(engine.stats().total_indexed_events, 1);

        engine.unindex_event(&event);
        assert_eq!(engine.stats().total_indexed_events, 0);
    }

    #[test]
    fn test_intersect() {
        let engine = test_engine();
        let key = SecretKey::generate();

        let event1 = test_event(&key, "repo1");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event2 = test_event(&key, "repo2");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event3 = test_event(&key, "repo3");

        let set_a = vec![event1.id(), event2.id()];
        let set_b = vec![event2.id(), event3.id()];

        let intersection = engine.intersect(&set_a, &set_b);
        assert_eq!(intersection.len(), 1);
        assert!(intersection.contains(&event2.id()));
    }

    #[test]
    fn test_union() {
        let engine = test_engine();
        let key = SecretKey::generate();

        let event1 = test_event(&key, "repo1");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event2 = test_event(&key, "repo2");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event3 = test_event(&key, "repo3");

        let set_a = vec![event1.id(), event2.id()];
        let set_b = vec![event2.id(), event3.id()];

        let union_set = engine.union(&set_a, &set_b);
        assert_eq!(union_set.len(), 3);
    }

    #[test]
    fn test_clear() {
        let engine = test_engine();
        let key = SecretKey::generate();

        engine.index_event(&test_event(&key, "repo1")).unwrap();
        engine.index_event(&test_event(&key, "repo2")).unwrap();

        assert!(engine.stats().total_indexed_events > 0);

        engine.clear();
        assert_eq!(engine.stats().total_indexed_events, 0);
    }
}
