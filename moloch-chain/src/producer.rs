//! Block producer for creating new blocks.
//!
//! The block producer:
//! - Batches events from the mempool
//! - Creates blocks at configured intervals
//! - Seals blocks with the validator key

use moloch_core::{
    block::{BlockBuilder, SealerId},
    crypto::SecretKey,
    AuditEvent, Block, Result,
};
use moloch_storage::ChainStore;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::mempool::Mempool;
use crate::state::ChainState;

/// Configuration for the block producer.
#[derive(Debug, Clone)]
pub struct ProducerConfig {
    /// Interval between block production attempts.
    pub block_interval: Duration,
    /// Maximum events to include per block.
    pub max_events_per_block: usize,
    /// Minimum events to produce a non-empty block.
    pub min_events_for_block: usize,
    /// Whether to produce empty blocks.
    pub produce_empty_blocks: bool,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            block_interval: Duration::from_secs(1),
            max_events_per_block: 10_000,
            min_events_for_block: 1,
            produce_empty_blocks: false,
        }
    }
}

/// Block producer that creates blocks from mempool events.
pub struct BlockProducer<S: ChainStore> {
    /// The chain state.
    chain: ChainState<S>,
    /// The mempool of pending events.
    mempool: Mempool,
    /// Producer configuration.
    config: ProducerConfig,
    /// The validator key for sealing blocks.
    key: SecretKey,
    /// Our sealer ID.
    sealer: SealerId,
}

impl<S: ChainStore + Send + Sync + 'static> BlockProducer<S> {
    /// Create a new block producer.
    pub fn new(
        chain: ChainState<S>,
        mempool: Mempool,
        config: ProducerConfig,
        key: SecretKey,
    ) -> Self {
        let sealer = SealerId::new(key.public_key());
        Self {
            chain,
            mempool,
            config,
            key,
            sealer,
        }
    }

    /// Get the chain state.
    pub fn chain(&self) -> &ChainState<S> {
        &self.chain
    }

    /// Get mutable chain state.
    pub fn chain_mut(&mut self) -> &mut ChainState<S> {
        &mut self.chain
    }

    /// Get the mempool.
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// Get mutable mempool.
    pub fn mempool_mut(&mut self) -> &mut Mempool {
        &mut self.mempool
    }

    /// Add an event to the mempool.
    pub fn submit_event(&mut self, event: AuditEvent) -> Result<bool> {
        self.mempool.add(event)
    }

    /// Check if we are the leader for the next block.
    pub fn is_our_turn(&self) -> bool {
        let next_height = self.chain.next_height();
        self.chain
            .validators()
            .leader_for_height(next_height)
            .map(|leader| leader == &self.sealer)
            .unwrap_or(false)
    }

    /// Try to produce a block.
    ///
    /// Returns `Some(block)` if a block was produced, `None` if:
    /// - It's not our turn
    /// - No events and `produce_empty_blocks` is false
    pub fn try_produce(&mut self) -> Result<Option<Block>> {
        // Check if it's our turn
        if !self.is_our_turn() {
            debug!("Not our turn to produce block");
            return Ok(None);
        }

        // Get events from mempool
        let events = self.mempool.take(self.config.max_events_per_block);

        // Check if we should produce
        if events.is_empty() && !self.config.produce_empty_blocks {
            debug!("No events in mempool, skipping block");
            return Ok(None);
        }

        if events.len() < self.config.min_events_for_block && !self.config.produce_empty_blocks {
            // Put events back
            for event in events {
                let _ = self.mempool.add(event);
            }
            return Ok(None);
        }

        // Build block
        let mut builder = BlockBuilder::new(self.sealer.clone());

        // Set parent if not genesis
        if let Some(header) = self.chain.head() {
            builder = builder.parent(header.clone());
        }

        builder = builder.events(events);
        let block = builder.seal(&self.key);

        info!(
            height = block.header.height,
            events = block.events.len(),
            "Produced block"
        );

        // Apply to chain
        self.chain
            .apply_block(block.clone())
            .map_err(|e| moloch_core::Error::internal(e.to_string()))?;

        Ok(Some(block))
    }

    /// Produce a block (convenience method that assumes it's our turn).
    ///
    /// Use this for testing or when you've already verified it's your turn.
    pub fn produce(&mut self) -> Result<Block> {
        // Get events from mempool
        let events = self.mempool.take(self.config.max_events_per_block);

        // Build block
        let mut builder = BlockBuilder::new(self.sealer.clone());

        if let Some(header) = self.chain.head() {
            builder = builder.parent(header.clone());
        }

        builder = builder.events(events);
        let block = builder.seal(&self.key);

        // Apply to chain
        self.chain
            .apply_block(block.clone())
            .map_err(|e| moloch_core::Error::internal(e.to_string()))?;

        Ok(block)
    }

    /// Run the block producer loop.
    ///
    /// This runs forever, producing blocks at the configured interval.
    /// Produced blocks are sent to the provided channel.
    pub async fn run(mut self, mut shutdown: mpsc::Receiver<()>, blocks_tx: mpsc::Sender<Block>) {
        let mut ticker = interval(self.config.block_interval);

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    info!("Block producer shutting down");
                    break;
                }
                _ = ticker.tick() => {
                    // Evict expired events periodically
                    let evicted = self.mempool.evict_expired();
                    if evicted > 0 {
                        debug!(evicted, "Evicted expired events");
                    }

                    // Try to produce a block
                    match self.try_produce() {
                        Ok(Some(block)) => {
                            if blocks_tx.send(block).await.is_err() {
                                warn!("Block receiver dropped");
                                break;
                            }
                        }
                        Ok(None) => {
                            // No block produced
                        }
                        Err(e) => {
                            warn!("Failed to produce block: {}", e);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::MempoolConfig;
    use crate::state::ChainConfig;
    use crate::validators::ValidatorSet;
    use moloch_core::event::{ActorId, ActorKind, EventType, ResourceId, ResourceKind};
    use moloch_storage::RocksStorage;
    use std::sync::Arc;

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

    fn test_producer() -> BlockProducer<RocksStorage> {
        let storage = Arc::new(RocksStorage::open_temp().unwrap());
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());
        let validators = ValidatorSet::new(vec![sealer]);

        let chain = ChainState::new(storage, validators, ChainConfig::default()).unwrap();
        let mempool = Mempool::new(MempoolConfig::default());
        let config = ProducerConfig::default();

        BlockProducer::new(chain, mempool, config, key)
    }

    #[test]
    fn test_producer_submit_event() {
        let mut producer = test_producer();
        let event = test_event(&producer.key);

        assert!(producer.submit_event(event).unwrap());
        assert_eq!(producer.mempool().len(), 1);
    }

    #[test]
    fn test_producer_is_our_turn() {
        let producer = test_producer();
        // With single validator, it's always our turn
        assert!(producer.is_our_turn());
    }

    #[test]
    fn test_producer_produce_genesis() {
        let mut producer = test_producer();

        // Submit an event
        let event = test_event(&producer.key);
        producer.submit_event(event).unwrap();

        // Produce genesis block
        let block = producer.produce().unwrap();
        assert_eq!(block.header.height, 0);
        assert_eq!(block.events.len(), 1);
        assert_eq!(producer.chain().height(), Some(0));
    }

    #[test]
    fn test_producer_produce_sequence() {
        let mut producer = test_producer();

        // Produce 3 blocks
        for i in 0..3 {
            let event = test_event(&producer.key);
            producer.submit_event(event).unwrap();
            let block = producer.produce().unwrap();
            assert_eq!(block.header.height, i);
        }

        assert_eq!(producer.chain().height(), Some(2));
    }

    #[test]
    fn test_producer_try_produce_no_events() {
        let mut producer = test_producer();

        // No events, should not produce (produce_empty_blocks is false)
        let result = producer.try_produce().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_producer_try_produce_with_events() {
        let mut producer = test_producer();

        let event = test_event(&producer.key);
        producer.submit_event(event).unwrap();

        let result = producer.try_produce().unwrap();
        assert!(result.is_some());

        let block = result.unwrap();
        assert_eq!(block.events.len(), 1);
    }

    #[test]
    fn test_producer_empty_blocks() {
        let storage = Arc::new(RocksStorage::open_temp().unwrap());
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());
        let validators = ValidatorSet::new(vec![sealer]);

        let chain = ChainState::new(storage, validators, ChainConfig::default()).unwrap();
        let mempool = Mempool::new(MempoolConfig::default());
        let config = ProducerConfig {
            produce_empty_blocks: true,
            ..Default::default()
        };

        let mut producer = BlockProducer::new(chain, mempool, config, key);

        // Should produce empty block
        let result = producer.try_produce().unwrap();
        assert!(result.is_some());

        let block = result.unwrap();
        assert!(block.events.is_empty());
    }

    #[test]
    fn test_producer_batch_events() {
        let storage = Arc::new(RocksStorage::open_temp().unwrap());
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());
        let validators = ValidatorSet::new(vec![sealer]);

        let chain = ChainState::new(storage, validators, ChainConfig::default()).unwrap();
        let mempool = Mempool::new(MempoolConfig::default());
        let config = ProducerConfig {
            max_events_per_block: 5,
            ..Default::default()
        };

        let mut producer = BlockProducer::new(chain, mempool, config, key.clone());

        // Submit 10 events
        for _ in 0..10 {
            let event = test_event(&key);
            producer.submit_event(event).unwrap();
        }

        // First block should have 5 events
        let block1 = producer.produce().unwrap();
        assert_eq!(block1.events.len(), 5);

        // Second block should have remaining 5
        let block2 = producer.produce().unwrap();
        assert_eq!(block2.events.len(), 5);

        // No more events
        assert!(producer.mempool().is_empty());
    }

    #[test]
    fn test_producer_not_our_turn() {
        let storage = Arc::new(RocksStorage::open_temp().unwrap());
        let our_key = SecretKey::generate();
        let other_key = SecretKey::generate();

        // Only the other validator is in the set
        let other_sealer = SealerId::new(other_key.public_key());
        let validators = ValidatorSet::new(vec![other_sealer]);

        let chain = ChainState::new(storage, validators, ChainConfig::default()).unwrap();
        let mempool = Mempool::new(MempoolConfig::default());
        let config = ProducerConfig::default();

        let mut producer = BlockProducer::new(chain, mempool, config, our_key.clone());

        // Submit an event
        let event = test_event(&our_key);
        producer.submit_event(event).unwrap();

        // Not our turn
        assert!(!producer.is_our_turn());

        // try_produce should return None
        let result = producer.try_produce().unwrap();
        assert!(result.is_none());

        // Events should still be in mempool
        assert_eq!(producer.mempool().len(), 1);
    }
}
