//! Moloch benchmarks with optimized global allocator.
//!
//! This crate uses mimalloc as the global allocator for all benchmarks.
//! mimalloc provides:
//! - 2-3x faster small allocations
//! - Better multi-threaded scaling
//! - Reduced memory fragmentation
//!
//! # Usage
//!
//! All benchmarks in this crate automatically use mimalloc.
//! The allocator is set globally at startup.

use mimalloc::MiMalloc;

/// Global allocator using mimalloc.
///
/// mimalloc is a high-performance allocator developed by Microsoft Research.
/// It's particularly efficient for:
/// - Many small allocations (events, hashes)
/// - Multi-threaded workloads (parallel verification)
/// - Memory-intensive operations (MMR construction)
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Re-export mimalloc for direct access if needed.
pub use mimalloc;

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout};

    #[test]
    fn test_mimalloc_allocator_works() {
        // Allocate some memory through the global allocator
        let layout = Layout::from_size_align(1024, 8).unwrap();
        unsafe {
            let ptr = GLOBAL.alloc(layout);
            assert!(!ptr.is_null(), "mimalloc should allocate successfully");

            // Write and read to verify the memory works
            std::ptr::write(ptr, 42u8);
            assert_eq!(std::ptr::read(ptr), 42u8);

            GLOBAL.dealloc(ptr, layout);
        }
    }

    #[test]
    fn test_mimalloc_many_small_allocations() {
        // Mimalloc excels at many small allocations
        let mut allocations: Vec<*mut u8> = Vec::with_capacity(10_000);
        let layout = Layout::from_size_align(32, 8).unwrap();

        unsafe {
            for _ in 0..10_000 {
                let ptr = GLOBAL.alloc(layout);
                assert!(!ptr.is_null());
                allocations.push(ptr);
            }

            // Deallocate in reverse order (worst case for some allocators)
            for ptr in allocations.into_iter().rev() {
                GLOBAL.dealloc(ptr, layout);
            }
        }
    }

    #[test]
    fn test_mimalloc_concurrent_allocations() {
        use std::sync::Arc;
        use std::thread;

        let layout = Layout::from_size_align(64, 8).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(4));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();

                    // Each thread does 1000 alloc/dealloc cycles
                    for _ in 0..1000 {
                        unsafe {
                            let ptr = GLOBAL.alloc(layout);
                            assert!(!ptr.is_null());
                            std::ptr::write(ptr, 0xAB);
                            GLOBAL.dealloc(ptr, layout);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }
    }
}
