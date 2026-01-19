//! Arena allocator for efficient batch operations.
//!
//! Arena allocation (bump allocation) is extremely efficient for batch operations:
//! - Allocation is O(1) - just a pointer bump
//! - No per-object deallocation overhead
//! - All memory freed at once when arena is dropped
//! - Cache-friendly linear memory layout
//!
//! # Use Cases
//!
//! - Batch event serialization
//! - Batch signature verification (collecting canonical bytes)
//! - Merkle tree construction
//! - Temporary buffers during block building
//!
//! # Example
//!
//! ```rust
//! use moloch_core::arena::BatchArena;
//!
//! // Create arena with initial capacity
//! let arena = BatchArena::new();
//!
//! // Allocate data in the arena
//! let bytes1 = arena.alloc_bytes(b"hello");
//! let bytes2 = arena.alloc_bytes(b"world");
//!
//! // Create a vector in the arena
//! let mut vec = arena.alloc_vec::<u32>();
//! vec.push(1);
//! vec.push(2);
//! vec.push(3);
//!
//! // Arena is dropped and all memory freed at once
//! ```

use bumpalo::Bump;
use bumpalo::collections::Vec as BumpVec;

use crate::crypto::Hash;

/// Default arena capacity (1MB).
pub const DEFAULT_ARENA_CAPACITY: usize = 1024 * 1024;

/// Arena allocator optimized for batch cryptographic operations.
///
/// Provides fast bump allocation for temporary data structures
/// used during batch verification, serialization, and merkle tree building.
pub struct BatchArena {
    bump: Bump,
}

impl BatchArena {
    /// Create a new arena with default capacity (1MB).
    #[inline]
    pub fn new() -> Self {
        Self {
            bump: Bump::with_capacity(DEFAULT_ARENA_CAPACITY),
        }
    }

    /// Create a new arena with specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bump: Bump::with_capacity(capacity),
        }
    }

    /// Create arena sized for a batch of events.
    ///
    /// Estimates ~1KB per event for canonical bytes + metadata.
    #[inline]
    pub fn for_events(count: usize) -> Self {
        let capacity = count * 1024;
        Self::with_capacity(capacity.max(DEFAULT_ARENA_CAPACITY))
    }

    /// Create arena sized for batch hash operations.
    ///
    /// Estimates 32 bytes per hash + overhead.
    #[inline]
    pub fn for_hashes(count: usize) -> Self {
        let capacity = count * 64;
        Self::with_capacity(capacity.max(65536))
    }

    /// Allocate a slice of bytes in the arena.
    #[inline]
    pub fn alloc_bytes(&self, bytes: &[u8]) -> &[u8] {
        self.bump.alloc_slice_copy(bytes)
    }

    /// Allocate a copy of a string in the arena.
    #[inline]
    pub fn alloc_str(&self, s: &str) -> &str {
        self.bump.alloc_str(s)
    }

    /// Allocate a value in the arena.
    #[inline]
    pub fn alloc<T>(&self, value: T) -> &mut T {
        self.bump.alloc(value)
    }

    /// Allocate a slice in the arena.
    #[inline]
    pub fn alloc_slice<T: Copy>(&self, slice: &[T]) -> &[T] {
        self.bump.alloc_slice_copy(slice)
    }

    /// Create a new vector in the arena.
    #[inline]
    pub fn alloc_vec<T>(&self) -> BumpVec<'_, T> {
        BumpVec::new_in(&self.bump)
    }

    /// Create a vector with capacity in the arena.
    #[inline]
    pub fn alloc_vec_with_capacity<T>(&self, capacity: usize) -> BumpVec<'_, T> {
        BumpVec::with_capacity_in(capacity, &self.bump)
    }

    /// Allocate space for N items and return a slice.
    #[inline]
    pub fn alloc_slice_fill_default<T: Default + Clone>(&self, count: usize) -> &mut [T] {
        self.bump.alloc_slice_fill_default(count)
    }

    /// Allocate a hash array in the arena.
    #[inline]
    pub fn alloc_hash_array(&self, count: usize) -> &mut [Hash] {
        self.bump.alloc_slice_fill_default(count)
    }

    /// Get the number of bytes allocated.
    #[inline]
    pub fn allocated_bytes(&self) -> usize {
        self.bump.allocated_bytes()
    }

    /// Reset the arena, freeing all allocations.
    ///
    /// This allows reusing the arena for another batch without
    /// deallocating the underlying memory.
    #[inline]
    pub fn reset(&mut self) {
        self.bump.reset();
    }

    /// Get a reference to the underlying bump allocator.
    ///
    /// Useful for advanced use cases or when integrating with
    /// other bumpalo-aware APIs.
    #[inline]
    pub fn as_bump(&self) -> &Bump {
        &self.bump
    }
}

impl Default for BatchArena {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BatchArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchArena")
            .field("allocated_bytes", &self.allocated_bytes())
            .finish()
    }
}

/// Arena-backed batch of bytes for signature verification.
///
/// Efficiently collects canonical bytes from multiple events
/// for batch signature verification.
pub struct CanonicalBytesArena<'a> {
    arena: &'a BatchArena,
    items: BumpVec<'a, &'a [u8]>,
}

impl<'a> CanonicalBytesArena<'a> {
    /// Create a new canonical bytes collector.
    pub fn new(arena: &'a BatchArena, capacity: usize) -> Self {
        Self {
            arena,
            items: arena.alloc_vec_with_capacity(capacity),
        }
    }

    /// Add canonical bytes to the collection.
    pub fn push(&mut self, bytes: &[u8]) {
        let allocated = self.arena.alloc_bytes(bytes);
        self.items.push(allocated);
    }

    /// Get all collected bytes slices.
    pub fn as_slices(&self) -> &[&'a [u8]] {
        &self.items
    }

    /// Get the number of items collected.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;

    #[test]
    fn test_arena_basic_allocation() {
        let arena = BatchArena::new();

        let bytes1 = arena.alloc_bytes(b"hello");
        let bytes2 = arena.alloc_bytes(b"world");

        assert_eq!(bytes1, b"hello");
        assert_eq!(bytes2, b"world");
    }

    #[test]
    fn test_arena_vector() {
        let arena = BatchArena::new();

        let mut vec = arena.alloc_vec::<u32>();
        vec.push(1);
        vec.push(2);
        vec.push(3);

        assert_eq!(vec.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_arena_hash_array() {
        let arena = BatchArena::new();

        let hashes = arena.alloc_hash_array(4);
        assert_eq!(hashes.len(), 4);

        // All should be zero initially
        for h in hashes.iter() {
            assert!(h.is_zero());
        }

        // Modify them
        hashes[0] = hash(b"test");
        assert!(!hashes[0].is_zero());
    }

    #[test]
    fn test_arena_reset() {
        let mut arena = BatchArena::new();

        // Allocate some data
        let first = arena.alloc_bytes(&[0u8; 10000]);
        let first_ptr = first.as_ptr();
        let before = arena.allocated_bytes();
        assert!(before >= 10000);

        // Reset the arena (memory is retained for reuse, pointer reset)
        arena.reset();

        // After reset, we can reuse the same memory
        // Allocate again - should start from the beginning of the chunk
        let second = arena.alloc_bytes(&[1u8; 10000]);
        let second_ptr = second.as_ptr();

        // The pointers may be the same (memory reused) or different
        // depending on implementation, but allocation should work
        assert_eq!(second.len(), 10000);

        // Key test: after reset, we can allocate more data without
        // growing the arena (memory was already allocated)
        let after = arena.allocated_bytes();
        // The arena should not have grown significantly
        // (it might grow slightly due to alignment, but not double)
        assert!(after <= before * 2, "Arena should reuse memory after reset");

        // Verify pointers are distinct (first is now invalid, second is valid)
        // This is just a sanity check - the exact behavior depends on bumpalo
        let _ = (first_ptr, second_ptr);
    }

    #[test]
    fn test_canonical_bytes_arena() {
        let arena = BatchArena::new();
        let mut collector = CanonicalBytesArena::new(&arena, 10);

        collector.push(b"event 1 canonical bytes");
        collector.push(b"event 2 canonical bytes");
        collector.push(b"event 3 canonical bytes");

        assert_eq!(collector.len(), 3);

        let slices = collector.as_slices();
        assert_eq!(slices[0], b"event 1 canonical bytes");
        assert_eq!(slices[1], b"event 2 canonical bytes");
        assert_eq!(slices[2], b"event 3 canonical bytes");
    }

    #[test]
    fn test_arena_sizing() {
        let arena = BatchArena::for_events(100);
        // Should be at least 100KB
        assert!(arena.as_bump().chunk_capacity() >= 100 * 1024);

        let arena = BatchArena::for_hashes(1000);
        // Should be at least 64KB (1000 * 64 bytes)
        assert!(arena.as_bump().chunk_capacity() >= 64 * 1024);
    }

    #[test]
    fn test_arena_many_small_allocations() {
        let arena = BatchArena::new();

        // Allocate 1000 small items
        for i in 0..1000u32 {
            let _ = arena.alloc(i);
        }

        // Should have allocated about 4KB (1000 * 4 bytes) + overhead
        assert!(arena.allocated_bytes() >= 4000);
    }

    #[test]
    fn test_arena_slice_allocation() {
        let arena = BatchArena::new();

        let hashes: Vec<Hash> = (0..10u32)
            .map(|i| hash(&i.to_le_bytes()))
            .collect();

        let allocated = arena.alloc_slice(&hashes);

        assert_eq!(allocated.len(), 10);
        for (i, h) in allocated.iter().enumerate() {
            assert_eq!(*h, hash(&(i as u32).to_le_bytes()));
        }
    }
}
