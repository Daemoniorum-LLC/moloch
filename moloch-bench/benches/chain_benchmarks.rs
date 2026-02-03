//! Chain operation benchmarks for Moloch.
//!
//! Benchmarks:
//! - Mempool operations (add, take)

// Link mimalloc global allocator from the bench library
use moloch_bench as _;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use moloch_chain::{Mempool, MempoolConfig};
use moloch_core::crypto::SecretKey;
use moloch_core::event::{
    ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind,
};

fn create_test_event(key: &SecretKey, n: u32) -> AuditEvent {
    let actor = ActorId::new(key.public_key(), ActorKind::User);
    let resource = ResourceId::new(ResourceKind::Repository, format!("repo-{}", n % 100));

    AuditEvent::builder()
        .now()
        .event_type(EventType::Push {
            force: false,
            commits: n,
        })
        .actor(actor)
        .resource(resource)
        .outcome(Outcome::Success)
        .sign(key)
        .unwrap()
}

fn bench_mempool_add(c: &mut Criterion) {
    let key = SecretKey::generate();

    let mut group = c.benchmark_group("mempool/add");

    group.bench_function("single_event", |b| {
        let mut mempool = Mempool::new(MempoolConfig::default());
        let mut counter = 0u32;

        b.iter(|| {
            counter += 1;
            let event = create_test_event(&key, counter);
            mempool.add(black_box(event))
        })
    });

    group.finish();
}

fn bench_mempool_take(c: &mut Criterion) {
    let key = SecretKey::generate();
    let batch_sizes = [10, 100, 500, 1000];

    let mut group = c.benchmark_group("mempool/take");

    for size in batch_sizes {
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(BenchmarkId::new("events", size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let mut mempool = Mempool::new(MempoolConfig::default());
                    for i in 0..size {
                        let event = create_test_event(&key, i);
                        mempool.add(event).unwrap();
                    }
                    mempool
                },
                |mut mempool| mempool.take(black_box(size as usize)),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn bench_mempool_throughput(c: &mut Criterion) {
    let key = SecretKey::generate();

    c.bench_function("mempool/add_and_take_cycle", |b| {
        b.iter_batched(
            || {
                let mut mempool = Mempool::new(MempoolConfig::default());
                for i in 0..100u32 {
                    let event = create_test_event(&key, i);
                    mempool.add(event).unwrap();
                }
                mempool
            },
            |mut mempool| {
                // Take events
                let events = mempool.take(100);
                // Re-add with different IDs
                for (i, _) in events.iter().enumerate() {
                    let event = create_test_event(&key, (100 + i) as u32);
                    mempool.add(event).unwrap();
                }
                mempool
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_mempool_add,
    bench_mempool_take,
    bench_mempool_throughput,
);

criterion_main!(benches);
