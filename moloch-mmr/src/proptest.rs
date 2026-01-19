//! Property-based tests for MMR operations.
//!
//! Tests invariants of the Merkle Mountain Range under arbitrary operations.

use proptest::prelude::*;

use crate::{MemStore, Mmr};
use moloch_core::{hash, Hash};

// ============================================================================
// Arbitrary Implementations
// ============================================================================

/// Generate arbitrary hash values (simulating leaf data).
fn arb_hash() -> impl Strategy<Value = Hash> {
    prop::array::uniform32(any::<u8>()).prop_map(Hash::from_bytes)
}

/// Generate a vector of arbitrary hashes.
fn arb_hashes(max_count: usize) -> impl Strategy<Value = Vec<Hash>> {
    prop::collection::vec(arb_hash(), 0..max_count)
}

// ============================================================================
// Property Tests: Basic MMR Operations
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Appending n leaves produces n leaf_count
    #[test]
    fn prop_mmr_leaf_count(leaves in arb_hashes(100)) {
        let mut mmr = Mmr::new(MemStore::new());
        for leaf in &leaves {
            mmr.append(*leaf).expect("append should succeed");
        }
        prop_assert_eq!(mmr.leaf_count(), leaves.len() as u64);
    }

    /// Size is always >= leaf_count (due to internal nodes)
    #[test]
    fn prop_mmr_size_ge_leaf_count(leaves in arb_hashes(100)) {
        let mut mmr = Mmr::new(MemStore::new());
        for leaf in &leaves {
            mmr.append(*leaf).expect("append should succeed");
        }
        prop_assert!(mmr.size() >= mmr.leaf_count());
    }

    /// Root is deterministic for same sequence of appends
    #[test]
    fn prop_mmr_root_deterministic(leaves in arb_hashes(50)) {
        let mut mmr1 = Mmr::new(MemStore::new());
        let mut mmr2 = Mmr::new(MemStore::new());

        for leaf in &leaves {
            mmr1.append(*leaf).expect("append should succeed");
            mmr2.append(*leaf).expect("append should succeed");
        }

        prop_assert_eq!(mmr1.root(), mmr2.root());
    }

    /// Different sequences produce different roots
    #[test]
    fn prop_mmr_different_sequences_different_roots(
        leaves1 in arb_hashes(10),
        leaves2 in arb_hashes(10)
    ) {
        prop_assume!(!leaves1.is_empty() && !leaves2.is_empty() && leaves1 != leaves2);

        let mut mmr1 = Mmr::new(MemStore::new());
        let mut mmr2 = Mmr::new(MemStore::new());

        for leaf in &leaves1 {
            mmr1.append(*leaf).expect("append should succeed");
        }
        for leaf in &leaves2 {
            mmr2.append(*leaf).expect("append should succeed");
        }

        prop_assert_ne!(mmr1.root(), mmr2.root());
    }

    /// Order matters for MMR root
    #[test]
    fn prop_mmr_order_matters(leaves in arb_hashes(10)) {
        prop_assume!(leaves.len() >= 2);

        let mut mmr1 = Mmr::new(MemStore::new());
        let mut mmr2 = Mmr::new(MemStore::new());

        for leaf in &leaves {
            mmr1.append(*leaf).expect("append should succeed");
        }

        // Reverse order
        for leaf in leaves.iter().rev() {
            mmr2.append(*leaf).expect("append should succeed");
        }

        prop_assert_ne!(mmr1.root(), mmr2.root());
    }

    /// Root changes after each append
    #[test]
    fn prop_mmr_root_changes(leaves in arb_hashes(20)) {
        prop_assume!(leaves.len() >= 2);

        let mut mmr = Mmr::new(MemStore::new());
        let mut prev_root = mmr.root();

        for leaf in &leaves {
            mmr.append(*leaf).expect("append should succeed");
            let new_root = mmr.root();
            // Root should change (technically could collide but astronomically unlikely)
            prop_assert_ne!(prev_root, new_root);
            prev_root = new_root;
        }
    }
}

// ============================================================================
// Property Tests: Inclusion Proofs
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Every appended leaf has a valid inclusion proof
    #[test]
    fn prop_mmr_all_leaves_provable(leaves in arb_hashes(50)) {
        prop_assume!(!leaves.is_empty());

        let mut mmr = Mmr::new(MemStore::new());
        let mut positions = Vec::new();

        for leaf in &leaves {
            let pos = mmr.append(*leaf).expect("append should succeed");
            positions.push(pos);
        }

        for pos in &positions {
            let proof = mmr.proof(*pos).expect("proof should succeed");
            prop_assert!(mmr.verify(&proof).expect("verify should not error"));
        }
    }

    /// Proof contains correct leaf hash
    #[test]
    fn prop_mmr_proof_contains_correct_leaf(leaves in arb_hashes(20)) {
        prop_assume!(!leaves.is_empty());

        let mut mmr = Mmr::new(MemStore::new());
        let mut positions = Vec::new();

        for leaf in &leaves {
            let pos = mmr.append(*leaf).expect("append should succeed");
            positions.push(pos);
        }

        for (i, pos) in positions.iter().enumerate() {
            let proof = mmr.proof(*pos).expect("proof should succeed");
            prop_assert_eq!(proof.leaf, leaves[i]);
        }
    }

    /// Proof.pos matches requested position
    #[test]
    fn prop_mmr_proof_pos_matches(leaves in arb_hashes(30)) {
        prop_assume!(!leaves.is_empty());

        let mut mmr = Mmr::new(MemStore::new());
        let mut positions = Vec::new();

        for leaf in &leaves {
            let pos = mmr.append(*leaf).expect("append should succeed");
            positions.push(pos);
        }

        for pos in &positions {
            let proof = mmr.proof(*pos).expect("proof should succeed");
            prop_assert_eq!(proof.pos, *pos);
        }
    }

    /// Proof size is O(log n)
    #[test]
    fn prop_mmr_proof_size_logarithmic(n in 1usize..1000usize) {
        let mut mmr = Mmr::new(MemStore::new());

        for i in 0..n {
            mmr.append(hash(format!("leaf{}", i).as_bytes())).expect("append should succeed");
        }

        // Get proof for first leaf
        let proof = mmr.proof(0).expect("proof should succeed");

        // Siblings should be at most log2(n) + number of peaks
        let max_siblings = (n as f64).log2().ceil() as usize + 10;
        prop_assert!(proof.siblings.len() <= max_siblings);
    }
}

// ============================================================================
// Property Tests: Peaks
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Number of peaks equals number of 1-bits in leaf_count
    #[test]
    fn prop_mmr_peak_count(n in 1usize..500usize) {
        let mut mmr = Mmr::new(MemStore::new());

        for i in 0..n {
            mmr.append(hash(format!("leaf{}", i).as_bytes())).expect("append should succeed");
        }

        let peaks = mmr.peak_positions();
        let expected_peaks = (n as u64).count_ones() as usize;
        prop_assert_eq!(peaks.len(), expected_peaks);
    }

    /// Peaks are in descending height order (positions increase)
    #[test]
    fn prop_mmr_peaks_ordered(n in 1usize..200usize) {
        let mut mmr = Mmr::new(MemStore::new());

        for i in 0..n {
            mmr.append(hash(format!("leaf{}", i).as_bytes())).expect("append should succeed");
        }

        let peaks = mmr.peak_positions();
        for window in peaks.windows(2) {
            prop_assert!(window[0] < window[1]);
        }
    }

    /// All peaks are within MMR size
    #[test]
    fn prop_mmr_peaks_within_size(leaves in arb_hashes(100)) {
        let mut mmr = Mmr::new(MemStore::new());

        for leaf in &leaves {
            mmr.append(*leaf).expect("append should succeed");
        }

        let size = mmr.size();
        for peak_pos in mmr.peak_positions() {
            prop_assert!(peak_pos < size);
        }
    }

    /// Root equals bagging of peaks
    #[test]
    fn prop_mmr_root_is_bagged_peaks(leaves in arb_hashes(50)) {
        prop_assume!(!leaves.is_empty());

        let mut mmr = Mmr::new(MemStore::new());

        for leaf in &leaves {
            mmr.append(*leaf).expect("append should succeed");
        }

        let peaks = mmr.peaks().expect("peaks should succeed");
        let bagged = bag_peaks(&peaks);
        prop_assert_eq!(mmr.root(), bagged);
    }
}

/// Bag peaks together to compute root (right to left).
fn bag_peaks(peaks: &[Hash]) -> Hash {
    if peaks.is_empty() {
        return Hash::ZERO;
    }
    if peaks.len() == 1 {
        return peaks[0];
    }

    let mut root = *peaks.last().unwrap();
    for peak in peaks.iter().rev().skip(1) {
        root = moloch_core::hash_pair(*peak, root);
    }
    root
}

// ============================================================================
// Property Tests: MMR Size Formula
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Size formula: size = 2*n - popcount(n) for n leaves
    #[test]
    fn prop_mmr_size_formula(n in 1usize..1000usize) {
        let mut mmr = Mmr::new(MemStore::new());

        for i in 0..n {
            mmr.append(hash(format!("leaf{}", i).as_bytes())).expect("append should succeed");
        }

        let expected_size = 2 * n - (n as u64).count_ones() as usize;
        prop_assert_eq!(mmr.size() as usize, expected_size);
    }
}

// ============================================================================
// Property Tests: Append Positions
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Append returns positions in increasing order
    #[test]
    fn prop_mmr_append_positions_increasing(leaves in arb_hashes(100)) {
        prop_assume!(leaves.len() >= 2);

        let mut mmr = Mmr::new(MemStore::new());
        let mut prev_pos: Option<u64> = None;

        for leaf in &leaves {
            let pos = mmr.append(*leaf).expect("append should succeed");
            if let Some(p) = prev_pos {
                prop_assert!(pos > p);
            }
            prev_pos = Some(pos);
        }
    }

    /// First append always returns position 0
    #[test]
    fn prop_mmr_first_append_is_zero(leaf in arb_hash()) {
        let mut mmr = Mmr::new(MemStore::new());
        let pos = mmr.append(leaf).expect("append should succeed");
        prop_assert_eq!(pos, 0);
    }
}

// ============================================================================
// Property Tests: Error Cases
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Proof for non-existent position fails
    #[test]
    fn prop_mmr_proof_out_of_bounds(n in 1usize..50usize) {
        let mut mmr = Mmr::new(MemStore::new());

        for i in 0..n {
            mmr.append(hash(format!("leaf{}", i).as_bytes())).expect("append should succeed");
        }

        let size = mmr.size();
        let result = mmr.proof(size + 100);
        prop_assert!(result.is_err());
    }

    /// Proof for internal node fails
    #[test]
    fn prop_mmr_proof_internal_node_fails(n in 2usize..20usize) {
        let mut mmr = Mmr::new(MemStore::new());

        for i in 0..n {
            mmr.append(hash(format!("leaf{}", i).as_bytes())).expect("append should succeed");
        }

        // Position 2 is an internal node (parent of 0 and 1) when n >= 2
        if n >= 2 {
            let result = mmr.proof(2);
            prop_assert!(result.is_err());
        }
    }
}

// ============================================================================
// Property Tests: Tamper Detection
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Modifying proof leaf hash causes verification failure
    #[test]
    fn prop_mmr_tampered_leaf_fails(leaves in arb_hashes(20)) {
        prop_assume!(leaves.len() >= 2);

        let mut mmr = Mmr::new(MemStore::new());
        let mut positions = Vec::new();

        for leaf in &leaves {
            let pos = mmr.append(*leaf).expect("append should succeed");
            positions.push(pos);
        }

        // Get a valid proof
        let mut proof = mmr.proof(positions[0]).expect("proof should succeed");

        // Tamper with the leaf hash
        proof.leaf = hash(b"tampered");

        // Verification should fail
        let result = mmr.verify(&proof);
        prop_assert!(result.is_err() || !result.unwrap());
    }

    /// Modifying a sibling hash causes verification failure
    #[test]
    fn prop_mmr_tampered_sibling_fails(n in 4usize..30usize) {
        let mut mmr = Mmr::new(MemStore::new());

        for i in 0..n {
            mmr.append(hash(format!("leaf{}", i).as_bytes())).expect("append should succeed");
        }

        // Get a proof with siblings
        let mut proof = mmr.proof(0).expect("proof should succeed");

        if !proof.siblings.is_empty() {
            // Tamper with first sibling
            proof.siblings[0].hash = hash(b"tampered");

            // Verification should fail
            let result = mmr.verify(&proof);
            prop_assert!(result.is_err() || !result.unwrap());
        }
    }
}
