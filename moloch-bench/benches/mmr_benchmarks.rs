//! MMR (Merkle Mountain Range) benchmarks.
//!
//! Benchmarks:
//! - Leaf appending (single vs batch)
//! - Proof generation (sequential vs parallel batch)
//! - Proof verification (sequential vs parallel batch)
//! - Range proof generation

// Link mimalloc global allocator from the bench library
use moloch_bench as _;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use moloch_core::hash;
use moloch_mmr::{MemStore, Mmr};

fn make_leaf(i: u64) -> moloch_core::Hash {
    hash(&i.to_le_bytes())
}

fn bench_mmr_append(c: &mut Criterion) {
    let batch_sizes = [10, 100, 500, 1000];

    let mut group = c.benchmark_group("mmr/append");

    for &size in &batch_sizes {
        let leaves: Vec<_> = (0..size).map(make_leaf).collect();

        group.throughput(Throughput::Elements(size as u64));

        // Sequential appending
        group.bench_with_input(
            BenchmarkId::new("sequential", size),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let mut mmr = Mmr::new(MemStore::new());
                    for &leaf in leaves {
                        mmr.append(black_box(leaf)).unwrap();
                    }
                    mmr.root()
                })
            },
        );

        // Batch appending
        group.bench_with_input(BenchmarkId::new("batch", size), &leaves, |b, leaves| {
            b.iter(|| {
                let mut mmr = Mmr::new(MemStore::new());
                mmr.append_batch(black_box(leaves)).unwrap();
                mmr.root()
            })
        });
    }

    group.finish();
}

fn bench_mmr_proof_generation(c: &mut Criterion) {
    let batch_sizes = [10, 50, 100, 500, 1000];

    let mut group = c.benchmark_group("mmr/proof");

    for &size in &batch_sizes {
        // Pre-build MMR with leaves
        let mut mmr = Mmr::new(MemStore::new());
        let leaves: Vec<_> = (0..size).map(make_leaf).collect();
        let positions = mmr.append_batch(&leaves).unwrap();

        group.throughput(Throughput::Elements(size as u64));

        // Sequential proof generation
        group.bench_with_input(
            BenchmarkId::new("sequential", size),
            &(&mmr, &positions),
            |b, (mmr, positions)| {
                b.iter(|| {
                    let mut proofs = Vec::with_capacity(positions.len());
                    for &pos in *positions {
                        proofs.push(mmr.proof(black_box(pos)).unwrap());
                    }
                    proofs
                })
            },
        );

        // Parallel batch proof generation
        group.bench_with_input(
            BenchmarkId::new("parallel", size),
            &(&mmr, &positions),
            |b, (mmr, positions)| b.iter(|| mmr.proof_batch(black_box(positions)).unwrap()),
        );
    }

    group.finish();
}

fn bench_mmr_verification(c: &mut Criterion) {
    let batch_sizes = [10, 50, 100, 500, 1000];

    let mut group = c.benchmark_group("mmr/verify");

    for &size in &batch_sizes {
        // Pre-build MMR and generate proofs
        let mut mmr = Mmr::new(MemStore::new());
        let leaves: Vec<_> = (0..size).map(make_leaf).collect();
        let positions = mmr.append_batch(&leaves).unwrap();
        let proofs = mmr.proof_batch(&positions).unwrap();

        group.throughput(Throughput::Elements(size as u64));

        // Sequential verification
        group.bench_with_input(
            BenchmarkId::new("sequential", size),
            &(&mmr, &proofs),
            |b, (mmr, proofs)| {
                b.iter(|| {
                    for proof in *proofs {
                        black_box(mmr.verify(proof).unwrap());
                    }
                })
            },
        );

        // Parallel batch verification
        group.bench_with_input(
            BenchmarkId::new("parallel", size),
            &(&mmr, &proofs),
            |b, (mmr, proofs)| b.iter(|| mmr.verify_batch(black_box(proofs)).unwrap()),
        );
    }

    group.finish();
}

fn bench_mmr_proof_range(c: &mut Criterion) {
    let range_sizes = [10, 50, 100, 500];

    let mut group = c.benchmark_group("mmr/proof_range");

    // Build a large MMR
    let mut mmr = Mmr::new(MemStore::new());
    let leaves: Vec<_> = (0..2000u64).map(make_leaf).collect();
    mmr.append_batch(&leaves).unwrap();

    for &size in &range_sizes {
        group.throughput(Throughput::Elements(size as u64));

        // Range proof generation
        group.bench_with_input(
            BenchmarkId::new("range", size),
            &(&mmr, size),
            |b, (mmr, size)| {
                // Get proofs for middle range
                let start = 500;
                b.iter(|| mmr.proof_range(black_box(start), black_box(*size)).unwrap())
            },
        );
    }

    group.finish();
}

fn bench_mmr_root(c: &mut Criterion) {
    let sizes = [10, 100, 1000, 5000];

    let mut group = c.benchmark_group("mmr/root");

    for &size in &sizes {
        let mut mmr = Mmr::new(MemStore::new());
        let leaves: Vec<_> = (0..size).map(make_leaf).collect();
        mmr.append_batch(&leaves).unwrap();

        group.bench_with_input(BenchmarkId::new("compute", size), &mmr, |b, mmr| {
            b.iter(|| black_box(mmr.root()))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_mmr_append,
    bench_mmr_proof_generation,
    bench_mmr_verification,
    bench_mmr_proof_range,
    bench_mmr_root,
);

criterion_main!(benches);
