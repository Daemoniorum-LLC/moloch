//! Merkle Mountain Range (MMR) example: Append data and generate proofs.
//!
//! MMR is an append-only data structure that provides:
//! - O(1) append
//! - O(log n) inclusion proofs
//! - O(log n) consistency proofs
//!
//! Run with: cargo run --example mmr_proofs

use moloch_core::hash;
use moloch_mmr::{MemStore, Mmr};

fn main() -> anyhow::Result<()> {
    // Create an in-memory MMR
    let mut mmr = Mmr::new(MemStore::new());

    println!("=== Merkle Mountain Range Demo ===\n");

    // Append some leaves (hashes of data)
    let data_items = ["event-1", "event-2", "event-3", "event-4", "event-5"];
    let mut positions = Vec::new();

    for item in &data_items {
        let leaf_hash = hash(item.as_bytes());
        let pos = mmr.append(leaf_hash)?;
        positions.push(pos);
        println!("Appended '{}' at position {}", item, pos);
    }

    println!("\nMMR Stats:");
    println!("  Leaf count: {}", mmr.leaf_count());
    println!("  Total nodes: {}", mmr.size());
    println!("  Root: {:?}", mmr.root());

    // Generate and verify inclusion proofs
    println!("\n=== Inclusion Proofs ===\n");

    for (i, &pos) in positions.iter().enumerate() {
        let proof = mmr.proof(pos)?;
        let is_valid = mmr.verify(&proof)?;

        println!(
            "Proof for '{}' (pos {}): {} siblings, valid: {}",
            data_items[i],
            pos,
            proof.siblings.len(),
            is_valid
        );
    }

    // Batch append for efficiency
    println!("\n=== Batch Append ===\n");

    let batch_data: Vec<_> = (6..=10)
        .map(|i| hash(format!("event-{}", i).as_bytes()))
        .collect();

    let batch_positions = mmr.append_batch(&batch_data)?;
    println!("Appended {} items in batch", batch_positions.len());
    println!("New leaf count: {}", mmr.leaf_count());
    println!("New root: {:?}", mmr.root());

    // Demonstrate proof portability
    println!("\n=== Proof Portability ===\n");

    let proof = mmr.proof(positions[0])?;
    let serialized = serde_json::to_string(&proof)?;
    println!("Serialized proof size: {} bytes", serialized.len());

    // Anyone with the root can verify the proof
    let root = mmr.root();
    println!("Root hash: {:?}", root);
    println!("Proof can be verified against this root by any party");

    Ok(())
}
