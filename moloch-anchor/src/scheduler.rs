//! Anchor scheduling for batching and timing commitments.
//!
//! The scheduler manages when and how commitments are anchored,
//! supporting batching, rate limiting, and priority queuing.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::commitment::Commitment;
use crate::errors::Result;

/// Priority level for anchoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnchorPriority {
    /// Low priority - can wait for batching.
    Low = 0,
    /// Normal priority - standard processing.
    Normal = 1,
    /// High priority - process soon.
    High = 2,
    /// Critical - process immediately.
    Critical = 3,
}

impl Default for AnchorPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// A request to anchor a commitment.
#[derive(Debug, Clone)]
pub struct AnchorRequest {
    /// The commitment to anchor.
    pub commitment: Commitment,
    /// Priority level.
    pub priority: AnchorPriority,
    /// Target chains (empty = all available).
    pub target_chains: Vec<String>,
    /// Minimum confirmations required.
    pub min_confirmations: u64,
    /// Maximum cost in USD (0 = no limit).
    pub max_cost_usd: f64,
    /// Request timestamp.
    pub requested_at: Instant,
}

impl AnchorRequest {
    /// Create a new anchor request.
    pub fn new(commitment: Commitment) -> Self {
        Self {
            commitment,
            priority: AnchorPriority::Normal,
            target_chains: Vec::new(),
            min_confirmations: 1,
            max_cost_usd: 0.0,
            requested_at: Instant::now(),
        }
    }

    /// Set priority.
    pub fn with_priority(mut self, priority: AnchorPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set target chains.
    pub fn with_chains(mut self, chains: Vec<String>) -> Self {
        self.target_chains = chains;
        self
    }

    /// Set minimum confirmations.
    pub fn with_confirmations(mut self, confirmations: u64) -> Self {
        self.min_confirmations = confirmations;
        self
    }

    /// Set maximum cost.
    pub fn with_max_cost(mut self, max_usd: f64) -> Self {
        self.max_cost_usd = max_usd;
        self
    }
}

/// Scheduler configuration.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum batch size.
    pub max_batch_size: usize,
    /// Maximum batch wait time.
    pub max_batch_wait: Duration,
    /// Minimum interval between anchors per chain.
    pub min_anchor_interval: Duration,
    /// Queue capacity.
    pub queue_capacity: usize,
    /// Enable batching.
    pub batching_enabled: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            max_batch_wait: Duration::from_secs(60),
            min_anchor_interval: Duration::from_secs(10),
            queue_capacity: 10000,
            batching_enabled: true,
        }
    }
}

/// A batch of commitments to anchor together.
#[derive(Debug, Clone)]
pub struct AnchorBatch {
    /// Commitments in this batch.
    pub commitments: Vec<Commitment>,
    /// Combined priority (highest of all requests).
    pub priority: AnchorPriority,
    /// Target chain for this batch.
    pub chain_id: String,
    /// Batch creation time.
    pub created_at: Instant,
}

impl AnchorBatch {
    /// Create a new batch for a chain.
    pub fn new(chain_id: impl Into<String>) -> Self {
        Self {
            commitments: Vec::new(),
            priority: AnchorPriority::Low,
            chain_id: chain_id.into(),
            created_at: Instant::now(),
        }
    }

    /// Add a commitment to the batch.
    pub fn add(&mut self, commitment: Commitment, priority: AnchorPriority) {
        self.commitments.push(commitment);
        if priority > self.priority {
            self.priority = priority;
        }
    }

    /// Check if batch is empty.
    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }

    /// Get batch size.
    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    /// Check if batch should be processed (full or timed out).
    pub fn should_process(&self, max_size: usize, max_wait: Duration) -> bool {
        self.commitments.len() >= max_size
            || self.created_at.elapsed() >= max_wait
            || self.priority >= AnchorPriority::Critical
    }
}

/// Pending request in the queue.
struct QueuedRequest {
    request: AnchorRequest,
    queued_at: Instant,
}

/// Anchor scheduler for managing commitment timing and batching.
pub struct AnchorScheduler {
    /// Configuration.
    config: SchedulerConfig,
    /// Priority queues (one per priority level).
    queues: [Mutex<VecDeque<QueuedRequest>>; 4],
    /// Current batches by chain.
    batches: Mutex<std::collections::HashMap<String, AnchorBatch>>,
    /// Total queued count.
    queued_count: std::sync::atomic::AtomicUsize,
}

impl AnchorScheduler {
    /// Create a new scheduler with default config.
    pub fn new() -> Self {
        Self::with_config(SchedulerConfig::default())
    }

    /// Create a scheduler with custom config.
    pub fn with_config(config: SchedulerConfig) -> Self {
        Self {
            config,
            queues: [
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
                Mutex::new(VecDeque::new()),
            ],
            batches: Mutex::new(std::collections::HashMap::new()),
            queued_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Submit a request to the scheduler.
    pub fn submit(&self, request: AnchorRequest) -> Result<()> {
        let priority = request.priority as usize;
        let queued = QueuedRequest {
            request,
            queued_at: Instant::now(),
        };

        self.queues[priority].lock().push_back(queued);
        self.queued_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }

    /// Get the next request to process (respects priority).
    pub fn next(&self) -> Option<AnchorRequest> {
        // Check queues from highest to lowest priority
        for priority in (0..4).rev() {
            let mut queue = self.queues[priority].lock();
            if let Some(queued) = queue.pop_front() {
                self.queued_count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                return Some(queued.request);
            }
        }
        None
    }

    /// Get multiple requests for batch processing.
    pub fn next_batch(&self, max_count: usize) -> Vec<AnchorRequest> {
        let mut requests = Vec::new();

        // Collect from highest to lowest priority
        for priority in (0..4).rev() {
            let mut queue = self.queues[priority].lock();
            while requests.len() < max_count {
                if let Some(queued) = queue.pop_front() {
                    self.queued_count
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    requests.push(queued.request);
                } else {
                    break;
                }
            }
            if requests.len() >= max_count {
                break;
            }
        }

        requests
    }

    /// Add a commitment to a chain's batch.
    pub fn add_to_batch(&self, chain_id: &str, commitment: Commitment, priority: AnchorPriority) {
        let mut batches = self.batches.lock();
        batches
            .entry(chain_id.to_string())
            .or_insert_with(|| AnchorBatch::new(chain_id))
            .add(commitment, priority);
    }

    /// Get ready batches (full or timed out).
    pub fn get_ready_batches(&self) -> Vec<AnchorBatch> {
        let mut batches = self.batches.lock();
        let mut ready = Vec::new();

        let chains: Vec<_> = batches.keys().cloned().collect();
        for chain_id in chains {
            if let Some(batch) = batches.get(&chain_id) {
                if batch.should_process(self.config.max_batch_size, self.config.max_batch_wait) {
                    if let Some(batch) = batches.remove(&chain_id) {
                        ready.push(batch);
                    }
                }
            }
        }

        ready
    }

    /// Force flush all batches.
    pub fn flush_batches(&self) -> Vec<AnchorBatch> {
        let mut batches = self.batches.lock();
        let result: Vec<_> = batches.drain().map(|(_, b)| b).collect();
        result
    }

    /// Get current queue depth.
    pub fn queue_depth(&self) -> usize {
        self.queued_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get queue depth by priority.
    pub fn queue_depth_by_priority(&self) -> [usize; 4] {
        [
            self.queues[0].lock().len(),
            self.queues[1].lock().len(),
            self.queues[2].lock().len(),
            self.queues[3].lock().len(),
        ]
    }

    /// Get pending batch count.
    pub fn pending_batch_count(&self) -> usize {
        self.batches.lock().len()
    }

    /// Check if scheduler is empty.
    pub fn is_empty(&self) -> bool {
        self.queue_depth() == 0 && self.pending_batch_count() == 0
    }

    /// Clear all queues and batches.
    pub fn clear(&self) {
        for queue in &self.queues {
            queue.lock().clear();
        }
        self.batches.lock().clear();
        self.queued_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for AnchorScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle for submitting requests to a background scheduler.
pub struct SchedulerHandle {
    sender: mpsc::Sender<AnchorRequest>,
}

impl SchedulerHandle {
    /// Create a new scheduler handle.
    pub fn new(sender: mpsc::Sender<AnchorRequest>) -> Self {
        Self { sender }
    }

    /// Submit a request.
    pub async fn submit(&self, request: AnchorRequest) -> Result<()> {
        self.sender
            .send(request)
            .await
            .map_err(|_| crate::errors::AnchorError::Internal("Scheduler channel closed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::Hash;

    #[test]
    fn test_priority_ordering() {
        assert!(AnchorPriority::Critical > AnchorPriority::High);
        assert!(AnchorPriority::High > AnchorPriority::Normal);
        assert!(AnchorPriority::Normal > AnchorPriority::Low);
    }

    #[test]
    fn test_scheduler_priority() {
        let scheduler = AnchorScheduler::new();

        // Submit in mixed order
        scheduler
            .submit(
                AnchorRequest::new(Commitment::new("chain", Hash::ZERO, 1))
                    .with_priority(AnchorPriority::Low),
            )
            .unwrap();

        scheduler
            .submit(
                AnchorRequest::new(Commitment::new("chain", Hash::ZERO, 2))
                    .with_priority(AnchorPriority::Critical),
            )
            .unwrap();

        scheduler
            .submit(
                AnchorRequest::new(Commitment::new("chain", Hash::ZERO, 3))
                    .with_priority(AnchorPriority::Normal),
            )
            .unwrap();

        // Should get Critical first
        let req = scheduler.next().unwrap();
        assert_eq!(req.commitment.height, 2);

        // Then Normal
        let req = scheduler.next().unwrap();
        assert_eq!(req.commitment.height, 3);

        // Then Low
        let req = scheduler.next().unwrap();
        assert_eq!(req.commitment.height, 1);

        // Then empty
        assert!(scheduler.next().is_none());
    }

    #[test]
    fn test_batching() {
        let scheduler = AnchorScheduler::new();

        scheduler.add_to_batch(
            "bitcoin",
            Commitment::new("chain", Hash::ZERO, 1),
            AnchorPriority::Normal,
        );
        scheduler.add_to_batch(
            "bitcoin",
            Commitment::new("chain", Hash::ZERO, 2),
            AnchorPriority::High,
        );
        scheduler.add_to_batch(
            "ethereum",
            Commitment::new("chain", Hash::ZERO, 3),
            AnchorPriority::Normal,
        );

        assert_eq!(scheduler.pending_batch_count(), 2);

        let batches = scheduler.flush_batches();
        assert_eq!(batches.len(), 2);

        let btc_batch = batches.iter().find(|b| b.chain_id == "bitcoin").unwrap();
        assert_eq!(btc_batch.len(), 2);
        assert_eq!(btc_batch.priority, AnchorPriority::High);
    }

    #[test]
    fn test_queue_depth() {
        let scheduler = AnchorScheduler::new();

        for i in 0..10 {
            scheduler
                .submit(AnchorRequest::new(Commitment::new("chain", Hash::ZERO, i)))
                .unwrap();
        }

        assert_eq!(scheduler.queue_depth(), 10);

        scheduler.next_batch(3);
        assert_eq!(scheduler.queue_depth(), 7);

        scheduler.clear();
        assert_eq!(scheduler.queue_depth(), 0);
    }
}
