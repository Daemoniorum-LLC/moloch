//! Mempool for pending audit events.
//!
//! The mempool holds events waiting to be included in blocks:
//! - Priority queue (by timestamp)
//! - Duplicate detection
//! - Expiration (TTL)
//! - Size limits with eviction

use moloch_core::{AuditEvent, EventId, Result};
use chrono::{DateTime, Duration, Utc};
use std::collections::{BinaryHeap, HashMap};
use std::cmp::Ordering;

/// Configuration for the mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of events in the pool.
    pub max_size: usize,
    /// Time-to-live for events (after which they're evicted).
    pub ttl: Duration,
    /// Maximum size of a single event in bytes.
    pub max_event_size: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10_000,
            ttl: Duration::hours(24),
            max_event_size: 1024 * 1024, // 1MB
        }
    }
}

/// An entry in the mempool.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The event.
    pub event: AuditEvent,
    /// When the event was added to the mempool.
    pub added_at: DateTime<Utc>,
    /// Priority (lower = higher priority, based on event timestamp).
    priority: i64,
}

impl MempoolEntry {
    fn new(event: AuditEvent) -> Self {
        // Use event timestamp for priority (earlier = higher priority)
        let priority = event.event_time.timestamp_millis();
        Self {
            event,
            added_at: Utc::now(),
            priority,
        }
    }

    /// Check if this entry has expired.
    pub fn is_expired(&self, ttl: Duration) -> bool {
        Utc::now() - self.added_at > ttl
    }

    /// Get the event ID.
    pub fn id(&self) -> EventId {
        self.event.id()
    }
}

// For BinaryHeap: we want min-heap by priority (earliest timestamp first)
impl PartialEq for MempoolEntry {
    fn eq(&self, other: &Self) -> bool {
        self.event.id() == other.event.id()
    }
}

impl Eq for MempoolEntry {}

impl PartialOrd for MempoolEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MempoolEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering: lower priority value = higher priority in heap
        other.priority.cmp(&self.priority)
    }
}

/// Mempool for pending events.
#[derive(Debug)]
pub struct Mempool {
    /// Configuration.
    config: MempoolConfig,
    /// Priority queue of entries.
    queue: BinaryHeap<MempoolEntry>,
    /// Index for O(1) duplicate detection.
    index: HashMap<EventId, i64>,
}

impl Mempool {
    /// Create a new mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            queue: BinaryHeap::new(),
            index: HashMap::new(),
        }
    }

    /// Create a mempool with default configuration.
    pub fn default_config() -> Self {
        Self::new(MempoolConfig::default())
    }

    /// Get the number of events in the pool.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Check if the pool is full.
    pub fn is_full(&self) -> bool {
        self.queue.len() >= self.config.max_size
    }

    /// Check if an event is already in the pool.
    pub fn contains(&self, id: &EventId) -> bool {
        self.index.contains_key(id)
    }

    /// Add an event to the pool.
    ///
    /// Returns `Ok(true)` if added, `Ok(false)` if duplicate.
    /// Returns `Err` if the event is invalid or too large.
    pub fn add(&mut self, event: AuditEvent) -> Result<bool> {
        let id = event.id();

        // Check for duplicate
        if self.contains(&id) {
            return Ok(false);
        }

        // Check event size
        let size = bincode::serialize(&event).map(|b| b.len()).unwrap_or(0);
        if size > self.config.max_event_size {
            return Err(moloch_core::Error::invalid_event(format!(
                "event too large: {} bytes exceeds limit {}",
                size, self.config.max_event_size
            )));
        }

        // Validate event signature
        event.validate()?;

        // Evict oldest if at capacity
        if self.is_full() {
            self.evict_one();
        }

        // Add to pool
        let entry = MempoolEntry::new(event);
        self.index.insert(id, entry.priority);
        self.queue.push(entry);

        Ok(true)
    }

    /// Remove expired events.
    ///
    /// Returns the number of events removed.
    pub fn evict_expired(&mut self) -> usize {
        let ttl = self.config.ttl;
        let before = self.len();

        // Collect expired IDs
        let expired: Vec<EventId> = self
            .queue
            .iter()
            .filter(|e| e.is_expired(ttl))
            .map(|e| e.id())
            .collect();

        // Remove from index
        for id in &expired {
            self.index.remove(id);
        }

        // Rebuild queue without expired entries
        let old_queue = std::mem::take(&mut self.queue);
        self.queue = old_queue.into_iter().filter(|e| !e.is_expired(ttl)).collect();

        before - self.len()
    }

    /// Evict one event (the oldest by added_at time).
    fn evict_one(&mut self) {
        // Find oldest entry
        if let Some(oldest) = self.queue.iter().min_by_key(|e| e.added_at) {
            let id = oldest.id();
            self.index.remove(&id);

            // Rebuild queue without this entry
            let old_queue = std::mem::take(&mut self.queue);
            self.queue = old_queue.into_iter().filter(|e| e.id() != id).collect();
        }
    }

    /// Take up to `n` events from the pool for block production.
    ///
    /// Events are taken in priority order (earliest timestamp first).
    /// The events are removed from the pool.
    pub fn take(&mut self, n: usize) -> Vec<AuditEvent> {
        let mut events = Vec::with_capacity(n.min(self.len()));

        while events.len() < n {
            match self.queue.pop() {
                Some(entry) => {
                    self.index.remove(&entry.id());
                    events.push(entry.event);
                }
                None => break,
            }
        }

        events
    }

    /// Peek at the next event without removing it.
    pub fn peek(&self) -> Option<&AuditEvent> {
        self.queue.peek().map(|e| &e.event)
    }

    /// Remove specific events (after they're included in a block).
    ///
    /// Returns the number of events removed.
    pub fn remove(&mut self, ids: &[EventId]) -> usize {
        let mut removed = 0;

        for id in ids {
            if self.index.remove(id).is_some() {
                removed += 1;
            }
        }

        if removed > 0 {
            // Rebuild queue without removed entries
            let id_set: std::collections::HashSet<_> = ids.iter().collect();
            let old_queue = std::mem::take(&mut self.queue);
            self.queue = old_queue
                .into_iter()
                .filter(|e| !id_set.contains(&e.id()))
                .collect();
        }

        removed
    }

    /// Clear all events from the pool.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.index.clear();
    }

    /// Get mempool statistics.
    pub fn stats(&self) -> MempoolStats {
        MempoolStats {
            size: self.len(),
            capacity: self.config.max_size,
            oldest_age_ms: self
                .queue
                .iter()
                .map(|e| (Utc::now() - e.added_at).num_milliseconds())
                .max()
                .unwrap_or(0),
        }
    }
}

/// Mempool statistics.
#[derive(Debug, Clone)]
pub struct MempoolStats {
    /// Current number of events.
    pub size: usize,
    /// Maximum capacity.
    pub capacity: usize,
    /// Age of oldest event in milliseconds.
    pub oldest_age_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::{
        crypto::SecretKey,
        event::{ActorId, ActorKind, EventType, ResourceId, ResourceKind},
    };

    fn test_event(key: &SecretKey) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test");

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

    #[test]
    fn test_mempool_add() {
        let mut pool = Mempool::default_config();
        let key = SecretKey::generate();
        let event = test_event(&key);
        let id = event.id();

        assert!(pool.add(event).unwrap());
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&id));
    }

    #[test]
    fn test_mempool_duplicate() {
        let mut pool = Mempool::default_config();
        let key = SecretKey::generate();
        let event = test_event(&key);

        assert!(pool.add(event.clone()).unwrap());
        assert!(!pool.add(event).unwrap()); // Duplicate
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_mempool_take() {
        let mut pool = Mempool::default_config();
        let key = SecretKey::generate();

        // Add 5 events
        for _ in 0..5 {
            let event = test_event(&key);
            pool.add(event).unwrap();
        }

        assert_eq!(pool.len(), 5);

        // Take 3
        let taken = pool.take(3);
        assert_eq!(taken.len(), 3);
        assert_eq!(pool.len(), 2);

        // Take remaining
        let taken = pool.take(10);
        assert_eq!(taken.len(), 2);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_mempool_remove() {
        let mut pool = Mempool::default_config();
        let key = SecretKey::generate();

        let event1 = test_event(&key);
        // Small delay or different resource to ensure different IDs
        std::thread::sleep(std::time::Duration::from_millis(1));
        let event2 = test_event(&key);
        let id1 = event1.id();
        let id2 = event2.id();

        // Ensure they have different IDs
        assert_ne!(id1, id2, "events should have different IDs");

        assert!(pool.add(event1).unwrap());
        assert!(pool.add(event2).unwrap());
        assert_eq!(pool.len(), 2);

        let removed = pool.remove(&[id1]);
        assert_eq!(removed, 1);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&id1));
        assert!(pool.contains(&id2));
    }

    #[test]
    fn test_mempool_capacity() {
        let config = MempoolConfig {
            max_size: 3,
            ..Default::default()
        };
        let mut pool = Mempool::new(config);
        let key = SecretKey::generate();

        // Add 5 events to a pool with capacity 3
        for _ in 0..5 {
            let event = test_event(&key);
            pool.add(event).unwrap();
        }

        // Should have evicted to stay at capacity
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn test_mempool_clear() {
        let mut pool = Mempool::default_config();
        let key = SecretKey::generate();

        for _ in 0..5 {
            pool.add(test_event(&key)).unwrap();
        }

        pool.clear();
        assert!(pool.is_empty());
    }

    #[test]
    fn test_mempool_stats() {
        let mut pool = Mempool::default_config();
        let key = SecretKey::generate();

        for _ in 0..5 {
            pool.add(test_event(&key)).unwrap();
        }

        let stats = pool.stats();
        assert_eq!(stats.size, 5);
        assert_eq!(stats.capacity, 10_000);
    }

    #[test]
    fn test_mempool_priority_order() {
        let mut pool = Mempool::default_config();
        let key = SecretKey::generate();

        // Add events - they should come out in timestamp order
        let mut events = Vec::new();
        for _ in 0..3 {
            let event = test_event(&key);
            events.push(event.clone());
            pool.add(event).unwrap();
        }

        // Take all and verify order (earliest timestamp first)
        let taken = pool.take(3);
        assert_eq!(taken.len(), 3);

        // Events should be in order by timestamp
        for i in 1..taken.len() {
            assert!(taken[i - 1].event_time <= taken[i].event_time);
        }
    }
}
