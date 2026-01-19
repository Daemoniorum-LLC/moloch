//! Storage benchmarks for Moloch.
//!
//! Benchmarks:
//! - MMR append/prove/verify operations

// Link mimalloc global allocator from the bench library
use moloch_bench as _;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use moloch_core::hash;
use moloch_mmr::{Mmr, MemStore};

fn bench_mmr_append(c: &mut Criterion) {
    let counts = [10, 100, 500, 1000];

    let mut group = c.benchmark_group("mmr/append");

    for count in counts {
        let hashes: Vec<_> = (0..count)
            .map(|i: u32| hash(&i.to_le_bytes()))
            .collect();

        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(BenchmarkId::new("leaves", count), &hashes, |b, hashes| {
            b.iter_batched(
                || Mmr::new(MemStore::new()),
                |mut mmr| {
                    for h in hashes.iter() {
                        mmr.append(black_box(*h)).unwrap();
                    }
                    mmr
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn bench_mmr_proof(c: &mut Criterion) {
    let mut mmr = Mmr::new(MemStore::new());
    let hashes: Vec<_> = (0..1000u32)
        .map(|i| hash(&i.to_le_bytes()))
        .collect();

    for h in &hashes {
        mmr.append(*h).unwrap();
    }

    c.bench_function("mmr/proof", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            idx = (idx + 1) % 1000;
            mmr.proof(black_box(idx as u64))
        })
    });
}

fn bench_mmr_verify(c: &mut Criterion) {
    let mut mmr = Mmr::new(MemStore::new());
    let hashes: Vec<_> = (0..1000u32)
        .map(|i| hash(&i.to_le_bytes()))
        .collect();

    for h in &hashes {
        mmr.append(*h).unwrap();
    }

    // Generate a proof to verify
    let proof = mmr.proof(500).unwrap();

    c.bench_function("mmr/verify", |b| {
        b.iter(|| mmr.verify(black_box(&proof)))
    });
}

fn bench_mmr_root(c: &mut Criterion) {
    let mut mmr = Mmr::new(MemStore::new());
    let hashes: Vec<_> = (0..10000u32)
        .map(|i| hash(&i.to_le_bytes()))
        .collect();

    for h in &hashes {
        mmr.append(*h).unwrap();
    }

    c.bench_function("mmr/root", |b| {
        b.iter(|| mmr.root())
    });
}

criterion_group!(
    benches,
    bench_mmr_append,
    bench_mmr_proof,
    bench_mmr_verify,
    bench_mmr_root,
);

criterion_main!(benches);
