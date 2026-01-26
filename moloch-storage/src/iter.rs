//! Iterator API for efficient traversal of stored data.
//!
//! Provides lazy iterators for:
//! - Blocks by height range
//! - Events within blocks
//! - MMR nodes

use moloch_core::{AuditEvent, Block, Hash, Result};

use crate::traits::{BlockStore, ChainStore};

/// Iterator over blocks in a height range.
///
/// # Example
///
/// ```ignore
/// use moloch_storage::{RocksStorage, BlockIterator};
///
/// let storage = RocksStorage::open("./data")?;
///
/// // Iterate over blocks 0-99
/// for result in BlockIterator::range(&storage, 0, 100) {
///     let block = result?;
///     println!("Block {}: {} events", block.header.height, block.events.len());
/// }
/// ```
pub struct BlockIterator<'a, S: BlockStore> {
    store: &'a S,
    current: u64,
    end: u64,
}

impl<'a, S: BlockStore> BlockIterator<'a, S> {
    /// Create an iterator over blocks in [start, end).
    pub fn range(store: &'a S, start: u64, end: u64) -> Self {
        Self {
            store,
            current: start,
            end,
        }
    }

    /// Create an iterator from start to latest block.
    pub fn from(store: &'a S, start: u64) -> Result<Self> {
        let end = store.latest_height()?.map_or(0, |h| h + 1);
        Ok(Self {
            store,
            current: start,
            end,
        })
    }

    /// Create an iterator over all blocks.
    pub fn all(store: &'a S) -> Result<Self> {
        Self::from(store, 0)
    }
}

impl<'a, S: BlockStore> Iterator for BlockIterator<'a, S> {
    type Item = Result<Block>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.end {
            return None;
        }

        let height = self.current;
        self.current += 1;

        match self.store.get_block(height) {
            Ok(Some(block)) => Some(Ok(block)),
            Ok(None) => {
                // Skip missing blocks (shouldn't happen in a healthy chain)
                self.next()
            }
            Err(e) => Some(Err(e)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.end - self.current) as usize;
        (0, Some(remaining))
    }
}

/// Iterator over events within a block range.
///
/// # Example
///
/// ```ignore
/// use moloch_storage::{RocksStorage, EventIterator};
///
/// let storage = RocksStorage::open("./data")?;
///
/// // Iterate over all events in blocks 0-99
/// for result in EventIterator::in_blocks(&storage, 0, 100) {
///     let (height, event) = result?;
///     println!("Event {} in block {}", event.id(), height);
/// }
/// ```
pub struct EventIterator<'a, S: BlockStore> {
    block_iter: BlockIterator<'a, S>,
    current_block: Option<Block>,
    event_index: usize,
}

impl<'a, S: BlockStore> EventIterator<'a, S> {
    /// Create an iterator over events in blocks [start, end).
    pub fn in_blocks(store: &'a S, start: u64, end: u64) -> Self {
        Self {
            block_iter: BlockIterator::range(store, start, end),
            current_block: None,
            event_index: 0,
        }
    }

    /// Create an iterator over all events.
    pub fn all(store: &'a S) -> Result<Self> {
        Ok(Self {
            block_iter: BlockIterator::all(store)?,
            current_block: None,
            event_index: 0,
        })
    }
}

impl<'a, S: BlockStore> Iterator for EventIterator<'a, S> {
    /// Returns (block_height, event) pairs.
    type Item = Result<(u64, AuditEvent)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // If we have a current block with remaining events, return the next one
            if let Some(ref block) = self.current_block {
                if self.event_index < block.events.len() {
                    let event = block.events[self.event_index].clone();
                    let height = block.header.height;
                    self.event_index += 1;
                    return Some(Ok((height, event)));
                }
            }

            // Move to next block
            match self.block_iter.next()? {
                Ok(block) => {
                    self.current_block = Some(block);
                    self.event_index = 0;
                    // Loop to get first event from this block
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

/// Iterator over MMR nodes in a position range.
pub struct MmrNodeIterator<'a, S: ChainStore> {
    store: &'a S,
    current: u64,
    end: u64,
}

impl<'a, S: ChainStore> MmrNodeIterator<'a, S> {
    /// Create an iterator over MMR nodes in [start, end).
    pub fn range(store: &'a S, start: u64, end: u64) -> Self {
        Self {
            store,
            current: start,
            end,
        }
    }

    /// Create an iterator over all MMR nodes.
    pub fn all(store: &'a S) -> Result<Self> {
        let end = store.mmr_size()?;
        Ok(Self {
            store,
            current: 0,
            end,
        })
    }
}

impl<'a, S: ChainStore> Iterator for MmrNodeIterator<'a, S> {
    /// Returns (position, hash) pairs for non-empty nodes.
    type Item = Result<(u64, Hash)>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.current < self.end {
            let pos = self.current;
            self.current += 1;

            match self.store.get_mmr_node(pos) {
                Ok(Some(hash)) => return Some(Ok((pos, hash))),
                Ok(None) => continue, // Skip empty positions
                Err(e) => return Some(Err(e)),
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.end - self.current) as usize;
        (0, Some(remaining))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::RocksStorage;
    use moloch_core::{
        block::{BlockBuilder, SealerId},
        crypto::SecretKey,
        event::{ActorId, ActorKind, EventType, ResourceId, ResourceKind},
        AuditEvent,
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
    fn test_block_iterator_range() {
        let storage = RocksStorage::open_temp().unwrap();
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());

        // Create 5 blocks
        let mut parent = None;
        for _ in 0..5 {
            let mut builder = BlockBuilder::new(sealer.clone());
            if let Some(p) = parent.take() {
                builder = builder.parent(p);
            }
            let block = builder.events(vec![test_event(&key)]).seal(&key);
            parent = Some(block.header.clone());
            storage.put_block(&block).unwrap();
        }

        // Iterate over blocks 1-3
        let blocks: Vec<_> = BlockIterator::range(&storage, 1, 4)
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].header.height, 1);
        assert_eq!(blocks[1].header.height, 2);
        assert_eq!(blocks[2].header.height, 3);
    }

    #[test]
    fn test_block_iterator_all() {
        let storage = RocksStorage::open_temp().unwrap();
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());

        // Create 3 blocks
        let mut parent = None;
        for _ in 0..3 {
            let mut builder = BlockBuilder::new(sealer.clone());
            if let Some(p) = parent.take() {
                builder = builder.parent(p);
            }
            let block = builder.events(vec![test_event(&key)]).seal(&key);
            parent = Some(block.header.clone());
            storage.put_block(&block).unwrap();
        }

        let blocks: Vec<_> = BlockIterator::all(&storage)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(blocks.len(), 3);
    }

    #[test]
    fn test_event_iterator() {
        let storage = RocksStorage::open_temp().unwrap();
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());

        // Create blocks with different event counts
        let genesis = BlockBuilder::new(sealer.clone())
            .events(vec![test_event(&key), test_event(&key)])
            .seal(&key);
        storage.put_block(&genesis).unwrap();

        let block1 = BlockBuilder::new(sealer.clone())
            .parent(genesis.header.clone())
            .events(vec![test_event(&key)])
            .seal(&key);
        storage.put_block(&block1).unwrap();

        let block2 = BlockBuilder::new(sealer)
            .parent(block1.header.clone())
            .events(vec![test_event(&key), test_event(&key), test_event(&key)])
            .seal(&key);
        storage.put_block(&block2).unwrap();

        // Count all events
        let events: Vec<_> = EventIterator::all(&storage)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(events.len(), 6); // 2 + 1 + 3

        // Events from blocks 0-1 only
        let events: Vec<_> = EventIterator::in_blocks(&storage, 0, 2)
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(events.len(), 3); // 2 + 1
    }

    #[test]
    fn test_mmr_node_iterator() {
        let storage = RocksStorage::open_temp().unwrap();

        // Store some MMR nodes (with gaps)
        storage.put_mmr_node(0, moloch_core::hash(b"n0")).unwrap();
        storage.put_mmr_node(1, moloch_core::hash(b"n1")).unwrap();
        storage.put_mmr_node(2, moloch_core::hash(b"n2")).unwrap();
        storage.set_mmr_meta(5, 3).unwrap();

        // Iterate all nodes (only 3 will be found, 2 positions empty)
        let nodes: Vec<_> = MmrNodeIterator::all(&storage)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].0, 0);
        assert_eq!(nodes[1].0, 1);
        assert_eq!(nodes[2].0, 2);
    }

    #[test]
    fn test_empty_iterator() {
        let storage = RocksStorage::open_temp().unwrap();

        // Empty storage
        let blocks: Vec<_> = BlockIterator::all(&storage)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert!(blocks.is_empty());

        let events: Vec<_> = EventIterator::all(&storage)
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert!(events.is_empty());
    }
}
