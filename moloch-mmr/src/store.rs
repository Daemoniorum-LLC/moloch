//! Storage traits and implementations for MMR.

use std::collections::HashMap;

use moloch_core::{Hash, Result};

/// Trait for MMR node storage.
///
/// The MMR stores nodes by position. Positions are assigned as follows:
/// - Leaves are at positions 0, 1, 3, 4, 7, 8, 10, 11, ...
/// - Parents are at positions 2, 5, 6, 9, 13, 14, ...
///
/// The pattern follows the MMR structure where position = 2^height - 1 + offset.
pub trait MmrStore: Clone {
    /// Get a node by position.
    fn get(&self, pos: u64) -> Result<Option<Hash>>;

    /// Insert a node at a position.
    fn insert(&mut self, pos: u64, hash: Hash) -> Result<()>;

    /// Get the current size (total node count).
    fn size(&self) -> u64;

    /// Set the size (used during initialization).
    fn set_size(&mut self, size: u64);
}

/// In-memory MMR store (for testing and small datasets).
#[derive(Clone, Default)]
pub struct MemStore {
    nodes: HashMap<u64, Hash>,
    size: u64,
}

impl MemStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all nodes (for debugging).
    pub fn nodes(&self) -> &HashMap<u64, Hash> {
        &self.nodes
    }
}

impl MmrStore for MemStore {
    fn get(&self, pos: u64) -> Result<Option<Hash>> {
        Ok(self.nodes.get(&pos).copied())
    }

    fn insert(&mut self, pos: u64, hash: Hash) -> Result<()> {
        self.nodes.insert(pos, hash);
        if pos >= self.size {
            self.size = pos + 1;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn set_size(&mut self, size: u64) {
        self.size = size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::hash;

    #[test]
    fn test_mem_store() {
        let mut store = MemStore::new();

        let h1 = hash(b"test1");
        let h2 = hash(b"test2");

        store.insert(0, h1).unwrap();
        store.insert(1, h2).unwrap();

        assert_eq!(store.get(0).unwrap(), Some(h1));
        assert_eq!(store.get(1).unwrap(), Some(h2));
        assert_eq!(store.get(2).unwrap(), None);
        assert_eq!(store.size(), 2);
    }
}
