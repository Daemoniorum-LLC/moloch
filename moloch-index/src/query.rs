//! Query DSL for filtering events.
//!
//! Provides a fluent builder API for constructing queries:
//!
//! ```ignore
//! Query::new()
//!     .actor(actor_id)
//!     .resource_kind(ResourceKind::Repository)
//!     .time_range(start..end)
//!     .event_type(EventTypeKey::Push)
//!     .limit(100)
//! ```

use std::ops::Range;

use chrono::{DateTime, Utc};
use moloch_core::{ActorId, AuditEvent, EventId, Hash, ResourceId, ResourceKind, Result};
use moloch_storage::ChainStore;

use crate::indexes::{EventTypeKey, IndexEngine, ResourceKey};

/// A query builder for filtering events.
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// Filter by actor (hash).
    actor_hash: Option<Hash>,
    /// Filter by resource.
    resource: Option<ResourceKey>,
    /// Filter by resource kind.
    resource_kind: Option<ResourceKind>,
    /// Filter by event type.
    event_type: Option<EventTypeKey>,
    /// Filter by time range.
    time_range: Option<Range<DateTime<Utc>>>,
    /// Maximum results to return.
    limit: Option<usize>,
    /// Offset for pagination.
    offset: usize,
    /// Sort order.
    order: SortOrder,
}

/// Sort order for query results.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SortOrder {
    /// Oldest first.
    #[default]
    Ascending,
    /// Newest first.
    Descending,
}

impl Query {
    /// Create a new empty query.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by actor.
    pub fn actor(mut self, actor: &ActorId) -> Self {
        self.actor_hash = Some(actor.id());
        self
    }

    /// Filter by actor hash directly.
    pub fn actor_hash(mut self, hash: Hash) -> Self {
        self.actor_hash = Some(hash);
        self
    }

    /// Filter by resource.
    pub fn resource(mut self, resource: &ResourceId) -> Self {
        self.resource = Some(ResourceKey::from(resource));
        self
    }

    /// Filter by resource kind.
    pub fn resource_kind(mut self, kind: ResourceKind) -> Self {
        self.resource_kind = Some(kind);
        self
    }

    /// Filter by event type.
    pub fn event_type(mut self, event_type: EventTypeKey) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Filter by time range.
    pub fn time_range(mut self, range: Range<DateTime<Utc>>) -> Self {
        self.time_range = Some(range);
        self
    }

    /// Filter events after a given time.
    pub fn after(mut self, time: DateTime<Utc>) -> Self {
        let end = self
            .time_range
            .as_ref()
            .map(|r| r.end)
            .unwrap_or(Utc::now());
        self.time_range = Some(time..end);
        self
    }

    /// Filter events before a given time.
    pub fn before(mut self, time: DateTime<Utc>) -> Self {
        let start = self
            .time_range
            .as_ref()
            .map(|r| r.start)
            .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());
        self.time_range = Some(start..time);
        self
    }

    /// Set maximum number of results.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset for pagination.
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    /// Set sort order to ascending (oldest first).
    pub fn ascending(mut self) -> Self {
        self.order = SortOrder::Ascending;
        self
    }

    /// Set sort order to descending (newest first).
    pub fn descending(mut self) -> Self {
        self.order = SortOrder::Descending;
        self
    }

    /// Check if this query has any filters.
    pub fn has_filters(&self) -> bool {
        self.actor_hash.is_some()
            || self.resource.is_some()
            || self.resource_kind.is_some()
            || self.event_type.is_some()
            || self.time_range.is_some()
    }

    /// Execute the query against an index engine.
    pub fn execute<S: ChainStore>(&self, engine: &IndexEngine<S>) -> Result<QueryResult> {
        let mut result_sets: Vec<Vec<EventId>> = Vec::new();

        // Collect matching event IDs from each filter
        if let Some(ref actor_hash) = self.actor_hash {
            result_sets.push(engine.events_by_actor_hash(actor_hash));
        }

        if let Some(ref resource) = self.resource {
            let resource_id = ResourceId::new(resource.kind, &resource.id);
            result_sets.push(engine.events_by_resource(&resource_id));
        }

        if let Some(kind) = self.resource_kind {
            result_sets.push(engine.events_by_resource_kind(kind));
        }

        if let Some(ref event_type) = self.event_type {
            result_sets.push(engine.events_by_type_key(event_type));
        }

        if let Some(ref time_range) = self.time_range {
            result_sets.push(engine.event_ids_in_time_range(time_range.start, time_range.end));
        }

        // If no filters, we need to get all events (expensive!)
        // In practice, you should always have at least one filter
        let mut event_ids = if result_sets.is_empty() {
            // Return empty - queries without filters should use pagination
            Vec::new()
        } else if result_sets.len() == 1 {
            result_sets.remove(0)
        } else {
            // Intersect all result sets
            let mut intersection = result_sets.remove(0);
            for set in result_sets {
                intersection = engine.intersect(&intersection, &set);
            }
            intersection
        };

        // Get total before pagination
        let total = event_ids.len();

        // Sort by loading events and checking timestamps
        // For now, we'll just use the order they come in
        // A production system would store timestamps in the index

        // Apply offset
        if self.offset > 0 && self.offset < event_ids.len() {
            event_ids = event_ids.into_iter().skip(self.offset).collect();
        } else if self.offset >= event_ids.len() {
            event_ids = Vec::new();
        }

        // Apply limit
        if let Some(limit) = self.limit {
            event_ids.truncate(limit);
        }

        Ok(QueryResult {
            event_ids,
            total,
            offset: self.offset,
            limit: self.limit,
        })
    }
}

/// Result of a query execution.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// Matching event IDs.
    pub event_ids: Vec<EventId>,
    /// Total number of matching events (before pagination).
    pub total: usize,
    /// Offset used.
    pub offset: usize,
    /// Limit used.
    pub limit: Option<usize>,
}

impl QueryResult {
    /// Check if there are more results available.
    pub fn has_more(&self) -> bool {
        self.offset + self.event_ids.len() < self.total
    }

    /// Get the number of results returned.
    pub fn count(&self) -> usize {
        self.event_ids.len()
    }

    /// Check if no results were found.
    pub fn is_empty(&self) -> bool {
        self.event_ids.is_empty()
    }

    /// Load the actual events from storage.
    pub fn load_events<S: ChainStore>(&self, engine: &IndexEngine<S>) -> Result<Vec<AuditEvent>> {
        let mut events = Vec::with_capacity(self.event_ids.len());
        for id in &self.event_ids {
            if let Some(event) = engine.storage().get_event(id)? {
                events.push(event);
            }
        }
        Ok(events)
    }
}

/// Composite query with multiple conditions combined with AND/OR.
#[derive(Debug, Clone)]
pub enum CompositeQuery {
    /// Simple query.
    Simple(Query),
    /// All conditions must match (AND).
    And(Vec<CompositeQuery>),
    /// Any condition must match (OR).
    Or(Vec<CompositeQuery>),
    /// Negate the condition (NOT).
    Not(Box<CompositeQuery>),
}

impl CompositeQuery {
    /// Create from a simple query.
    pub fn simple(query: Query) -> Self {
        CompositeQuery::Simple(query)
    }

    /// Combine with AND.
    pub fn and(queries: Vec<CompositeQuery>) -> Self {
        CompositeQuery::And(queries)
    }

    /// Combine with OR.
    pub fn or(queries: Vec<CompositeQuery>) -> Self {
        CompositeQuery::Or(queries)
    }

    /// Negate a query.
    pub fn not(query: CompositeQuery) -> Self {
        CompositeQuery::Not(Box::new(query))
    }

    /// Execute the composite query.
    pub fn execute<S: ChainStore>(&self, engine: &IndexEngine<S>) -> Result<QueryResult> {
        match self {
            CompositeQuery::Simple(q) => q.execute(engine),
            CompositeQuery::And(queries) => {
                let results: Vec<_> = queries
                    .iter()
                    .map(|q| q.execute(engine))
                    .collect::<Result<Vec<_>>>()?;

                if results.is_empty() {
                    return Ok(QueryResult {
                        event_ids: Vec::new(),
                        total: 0,
                        offset: 0,
                        limit: None,
                    });
                }

                let mut intersection: Vec<_> = results[0].event_ids.clone();
                for r in &results[1..] {
                    intersection = engine.intersect(&intersection, &r.event_ids);
                }

                let total = intersection.len();
                Ok(QueryResult {
                    event_ids: intersection,
                    total,
                    offset: 0,
                    limit: None,
                })
            }
            CompositeQuery::Or(queries) => {
                let results: Vec<_> = queries
                    .iter()
                    .map(|q| q.execute(engine))
                    .collect::<Result<Vec<_>>>()?;

                let mut union_set = Vec::new();
                for r in results {
                    union_set = engine.union(&union_set, &r.event_ids);
                }

                let total = union_set.len();
                Ok(QueryResult {
                    event_ids: union_set,
                    total,
                    offset: 0,
                    limit: None,
                })
            }
            CompositeQuery::Not(_inner) => {
                // NOT requires scanning all events, which is expensive
                // For now, return an error
                Err(moloch_core::Error::internal(
                    "NOT queries require full scan and are not supported",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use moloch_core::{
        crypto::SecretKey,
        event::{ActorKind, EventType},
    };
    use moloch_storage::RocksStorage;

    fn test_event(key: &SecretKey, resource_id: &str, event_type: EventType) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, resource_id);

        AuditEvent::builder()
            .now()
            .event_type(event_type)
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
    fn test_query_by_actor() {
        let engine = test_engine();
        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();

        let event1 = test_event(
            &key1,
            "repo1",
            EventType::Push {
                force: false,
                commits: 1,
            },
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event2 = test_event(&key1, "repo2", EventType::BranchCreated);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event3 = test_event(
            &key2,
            "repo3",
            EventType::Push {
                force: false,
                commits: 2,
            },
        );

        engine.index_event(&event1).unwrap();
        engine.index_event(&event2).unwrap();
        engine.index_event(&event3).unwrap();

        let actor1 = ActorId::new(key1.public_key(), ActorKind::User);
        let result = Query::new().actor(&actor1).execute(&engine).unwrap();

        assert_eq!(result.count(), 2);
        assert!(result.event_ids.contains(&event1.id()));
        assert!(result.event_ids.contains(&event2.id()));
    }

    #[test]
    fn test_query_by_event_type() {
        let engine = test_engine();
        let key = SecretKey::generate();

        let event1 = test_event(
            &key,
            "repo1",
            EventType::Push {
                force: false,
                commits: 1,
            },
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event2 = test_event(&key, "repo2", EventType::BranchCreated);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event3 = test_event(
            &key,
            "repo3",
            EventType::Push {
                force: true,
                commits: 3,
            },
        );

        engine.index_event(&event1).unwrap();
        engine.index_event(&event2).unwrap();
        engine.index_event(&event3).unwrap();

        let result = Query::new()
            .event_type(crate::indexes::EventTypeKey::Push)
            .execute(&engine)
            .unwrap();

        assert_eq!(result.count(), 2);
        assert!(result.event_ids.contains(&event1.id()));
        assert!(result.event_ids.contains(&event3.id()));
    }

    #[test]
    fn test_query_combined_filters() {
        let engine = test_engine();
        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();

        let event1 = test_event(
            &key1,
            "repo1",
            EventType::Push {
                force: false,
                commits: 1,
            },
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event2 = test_event(&key1, "repo2", EventType::BranchCreated);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event3 = test_event(
            &key2,
            "repo3",
            EventType::Push {
                force: false,
                commits: 2,
            },
        );

        engine.index_event(&event1).unwrap();
        engine.index_event(&event2).unwrap();
        engine.index_event(&event3).unwrap();

        // Query by actor AND event type
        let actor1 = ActorId::new(key1.public_key(), ActorKind::User);
        let result = Query::new()
            .actor(&actor1)
            .event_type(crate::indexes::EventTypeKey::Push)
            .execute(&engine)
            .unwrap();

        assert_eq!(result.count(), 1);
        assert!(result.event_ids.contains(&event1.id()));
    }

    #[test]
    fn test_query_with_limit() {
        let engine = test_engine();
        let key = SecretKey::generate();

        for i in 0..10 {
            let event = test_event(
                &key,
                &format!("repo{}", i),
                EventType::Push {
                    force: false,
                    commits: 1,
                },
            );
            engine.index_event(&event).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let result = Query::new()
            .event_type(crate::indexes::EventTypeKey::Push)
            .limit(5)
            .execute(&engine)
            .unwrap();

        assert_eq!(result.count(), 5);
        assert_eq!(result.total, 10);
        assert!(result.has_more());
    }

    #[test]
    fn test_query_with_offset() {
        let engine = test_engine();
        let key = SecretKey::generate();

        for i in 0..10 {
            let event = test_event(
                &key,
                &format!("repo{}", i),
                EventType::Push {
                    force: false,
                    commits: 1,
                },
            );
            engine.index_event(&event).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let result = Query::new()
            .event_type(crate::indexes::EventTypeKey::Push)
            .offset(5)
            .limit(3)
            .execute(&engine)
            .unwrap();

        assert_eq!(result.count(), 3);
        assert_eq!(result.total, 10);
        assert_eq!(result.offset, 5);
    }

    #[test]
    fn test_query_time_range() {
        let engine = test_engine();
        let key = SecretKey::generate();

        let start = Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(10));

        let event = test_event(
            &key,
            "repo1",
            EventType::Push {
                force: false,
                commits: 1,
            },
        );
        engine.index_event(&event).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        let end = Utc::now();

        let result = Query::new()
            .time_range(start..end)
            .execute(&engine)
            .unwrap();

        assert_eq!(result.count(), 1);
    }

    #[test]
    fn test_composite_query_or() {
        let engine = test_engine();
        let key = SecretKey::generate();

        let event1 = test_event(
            &key,
            "repo1",
            EventType::Push {
                force: false,
                commits: 1,
            },
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event2 = test_event(&key, "repo2", EventType::BranchCreated);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event3 = test_event(&key, "repo3", EventType::TagCreated);

        engine.index_event(&event1).unwrap();
        engine.index_event(&event2).unwrap();
        engine.index_event(&event3).unwrap();

        // Push OR BranchCreated
        let q = CompositeQuery::or(vec![
            CompositeQuery::simple(Query::new().event_type(crate::indexes::EventTypeKey::Push)),
            CompositeQuery::simple(
                Query::new().event_type(crate::indexes::EventTypeKey::BranchCreated),
            ),
        ]);

        let result = q.execute(&engine).unwrap();
        assert_eq!(result.count(), 2);
    }

    #[test]
    fn test_has_filters() {
        assert!(!Query::new().has_filters());
        assert!(Query::new().actor_hash(Hash::ZERO).has_filters());
        assert!(Query::new()
            .resource_kind(ResourceKind::Repository)
            .has_filters());
    }

    #[test]
    fn test_query_result_has_more() {
        // Got 10 of 100, there are more
        let result = QueryResult {
            event_ids: (0..10).map(|_| EventId(Hash::ZERO)).collect(),
            total: 100,
            offset: 0,
            limit: Some(10),
        };
        assert!(result.has_more());
        assert_eq!(result.count(), 10);

        // Got 10 of 10, no more
        let result = QueryResult {
            event_ids: (0..10).map(|_| EventId(Hash::ZERO)).collect(),
            total: 10,
            offset: 0,
            limit: Some(10),
        };
        assert!(!result.has_more());

        // Got 0 of 0, no more
        let result = QueryResult {
            event_ids: vec![],
            total: 0,
            offset: 0,
            limit: Some(10),
        };
        assert!(!result.has_more());
    }
}
