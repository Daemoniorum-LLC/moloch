//! Cache-line aligned types for high-performance operations.
//!
//! Modern CPUs have 64-byte cache lines. Proper alignment prevents:
//! - False sharing in concurrent code
//! - Cache line splits during loads/stores
//! - Suboptimal prefetching
//!
//! # Usage
//!
//! ```rust
//! use moloch_core::aligned::{AlignedHash, AlignedHashArray};
//!
//! // Single aligned hash (for hot paths)
//! let hash = AlignedHash::from(some_hash);
//!
//! // Batch of aligned hashes (for SIMD operations)
//! let mut batch = AlignedHashArray::<8>::default();
//! for (i, h) in hashes.iter().enumerate() {
//!     batch.set(i, *h);
//! }
//! ```

use std::ops::{Deref, DerefMut};

use crate::crypto::Hash;

/// Cache line size on most modern CPUs (Intel, AMD, ARM).
pub const CACHE_LINE_SIZE: usize = 64;

/// A hash aligned to a cache line boundary.
///
/// This prevents false sharing when multiple threads access adjacent hashes
/// and ensures optimal cache behavior for frequently accessed hashes.
#[repr(C, align(64))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AlignedHash {
    hash: Hash,
    _padding: [u8; 32], // Pad to full 64-byte cache line
}

impl AlignedHash {
    /// Create a new aligned hash.
    #[inline]
    pub const fn new(hash: Hash) -> Self {
        Self {
            hash,
            _padding: [0; 32],
        }
    }

    /// Create a zero-initialized aligned hash.
    #[inline]
    pub const fn zero() -> Self {
        Self::new(Hash::ZERO)
    }

    /// Get the underlying hash.
    #[inline]
    pub const fn inner(&self) -> &Hash {
        &self.hash
    }

    /// Get a mutable reference to the underlying hash.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut Hash {
        &mut self.hash
    }

    /// Consume and return the inner hash.
    #[inline]
    pub fn into_inner(self) -> Hash {
        self.hash
    }
}

impl From<Hash> for AlignedHash {
    #[inline]
    fn from(hash: Hash) -> Self {
        Self::new(hash)
    }
}

impl From<AlignedHash> for Hash {
    #[inline]
    fn from(aligned: AlignedHash) -> Self {
        aligned.hash
    }
}

impl Deref for AlignedHash {
    type Target = Hash;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.hash
    }
}

impl DerefMut for AlignedHash {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.hash
    }
}

impl std::fmt::Debug for AlignedHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AlignedHash").field(&self.hash).finish()
    }
}

/// An array of hashes aligned to cache line boundaries.
///
/// Used for batch operations where hashes are processed together.
/// The entire array is aligned, and hashes are packed contiguously
/// for optimal SIMD access patterns.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct AlignedHashArray<const N: usize> {
    hashes: [Hash; N],
}

impl<const N: usize> AlignedHashArray<N> {
    /// Create a new array with zero hashes.
    #[inline]
    pub const fn new() -> Self {
        Self {
            hashes: [Hash::ZERO; N],
        }
    }

    /// Create from an existing array.
    #[inline]
    pub const fn from_array(hashes: [Hash; N]) -> Self {
        Self { hashes }
    }

    /// Get a hash at the specified index.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&Hash> {
        self.hashes.get(index)
    }

    /// Set a hash at the specified index.
    #[inline]
    pub fn set(&mut self, index: usize, hash: Hash) {
        if index < N {
            self.hashes[index] = hash;
        }
    }

    /// Get the underlying array.
    #[inline]
    pub const fn as_array(&self) -> &[Hash; N] {
        &self.hashes
    }

    /// Get a mutable reference to the underlying array.
    #[inline]
    pub fn as_array_mut(&mut self) -> &mut [Hash; N] {
        &mut self.hashes
    }

    /// Get a pointer to the first hash (for SIMD operations).
    #[inline]
    pub fn as_ptr(&self) -> *const Hash {
        self.hashes.as_ptr()
    }

    /// Get a mutable pointer to the first hash.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut Hash {
        self.hashes.as_mut_ptr()
    }

    /// Get the raw bytes pointer (for SIMD loads).
    #[inline]
    pub fn as_bytes_ptr(&self) -> *const u8 {
        self.hashes.as_ptr() as *const u8
    }

    /// Get a slice of all hashes.
    #[inline]
    pub fn as_slice(&self) -> &[Hash] {
        &self.hashes
    }

    /// Get a mutable slice of all hashes.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [Hash] {
        &mut self.hashes
    }

    /// Iterate over hashes.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Hash> {
        self.hashes.iter()
    }

    /// Iterate over hashes mutably.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Hash> {
        self.hashes.iter_mut()
    }
}

impl<const N: usize> Default for AlignedHashArray<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for AlignedHashArray<N> {
    type Target = [Hash; N];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.hashes
    }
}

impl<const N: usize> DerefMut for AlignedHashArray<N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.hashes
    }
}

impl<const N: usize> std::fmt::Debug for AlignedHashArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedHashArray")
            .field("len", &N)
            .field("hashes", &self.hashes)
            .finish()
    }
}

/// A cache-line padded wrapper to prevent false sharing.
///
/// Useful for counters, state variables, or any data that is
/// frequently updated by a single thread but may be adjacent
/// to data accessed by other threads.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct CacheLinePadded<T> {
    value: T,
}

impl<T> CacheLinePadded<T> {
    /// Create a new padded value.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// Get a reference to the inner value.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.value
    }

    /// Get a mutable reference to the inner value.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Consume and return the inner value.
    #[inline]
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T> Deref for CacheLinePadded<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> DerefMut for CacheLinePadded<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T: Default> Default for CacheLinePadded<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for CacheLinePadded<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CacheLinePadded").field(&self.value).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;

    #[test]
    fn test_aligned_hash_size_and_alignment() {
        assert_eq!(std::mem::size_of::<AlignedHash>(), 64);
        assert_eq!(std::mem::align_of::<AlignedHash>(), 64);
    }

    #[test]
    fn test_aligned_hash_array_alignment() {
        assert_eq!(std::mem::align_of::<AlignedHashArray<8>>(), 64);

        // Size should be 8 * 32 = 256 bytes (no extra padding needed)
        assert_eq!(std::mem::size_of::<AlignedHashArray<8>>(), 256);
    }

    #[test]
    fn test_cache_line_padded_alignment() {
        assert_eq!(std::mem::align_of::<CacheLinePadded<u64>>(), 64);

        // Should be padded to at least 64 bytes
        assert!(std::mem::size_of::<CacheLinePadded<u64>>() >= 64);
    }

    #[test]
    fn test_aligned_hash_operations() {
        let h = hash(b"test");
        let aligned = AlignedHash::new(h);

        assert_eq!(*aligned.inner(), h);
        assert_eq!(aligned.into_inner(), h);
    }

    #[test]
    fn test_aligned_hash_array_operations() {
        let mut arr = AlignedHashArray::<4>::new();

        let h0 = hash(b"zero");
        let h1 = hash(b"one");
        let h2 = hash(b"two");
        let h3 = hash(b"three");

        arr.set(0, h0);
        arr.set(1, h1);
        arr.set(2, h2);
        arr.set(3, h3);

        assert_eq!(arr.get(0), Some(&h0));
        assert_eq!(arr.get(1), Some(&h1));
        assert_eq!(arr.get(2), Some(&h2));
        assert_eq!(arr.get(3), Some(&h3));
        assert_eq!(arr.get(4), None);
    }

    #[test]
    fn test_alignment_is_correct_at_runtime() {
        let aligned = AlignedHash::new(hash(b"test"));
        let ptr = &aligned as *const AlignedHash as usize;
        assert_eq!(ptr % 64, 0, "AlignedHash should be 64-byte aligned");

        let arr = AlignedHashArray::<8>::new();
        let arr_ptr = &arr as *const AlignedHashArray<8> as usize;
        assert_eq!(arr_ptr % 64, 0, "AlignedHashArray should be 64-byte aligned");
    }

    #[test]
    fn test_heap_allocation_alignment() {
        // Box should maintain alignment
        let boxed = Box::new(AlignedHash::new(hash(b"test")));
        let ptr = boxed.as_ref() as *const AlignedHash as usize;
        assert_eq!(ptr % 64, 0, "Boxed AlignedHash should be 64-byte aligned");

        // Vec should also maintain alignment
        let mut vec = Vec::with_capacity(4);
        for i in 0..4u8 {
            vec.push(AlignedHash::new(hash(&[i])));
        }
        for (i, aligned) in vec.iter().enumerate() {
            let ptr = aligned as *const AlignedHash as usize;
            assert_eq!(ptr % 64, 0, "Vec element {} should be 64-byte aligned", i);
        }
    }
}
