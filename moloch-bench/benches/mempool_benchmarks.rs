//! Mempool benchmarks comparing mutex-based vs lock-free implementations.
//!
//! Benchmarks:
//! - Single-threaded add/take operations
//! - Multi-threaded concurrent add operations
//! - Multi-threaded producer/consumer patterns

// Link mimalloc global allocator from the bench library
use moloch_bench as _;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::{Arc, Mutex};
use std::thread;

use moloch_chain::{ConcurrentMempool, ConcurrentMempoolConfig, Mempool, MempoolConfig};
use moloch_core::{
    crypto::SecretKey,
    event::{ActorId, ActorKind, AuditEvent, EventType, ResourceId, ResourceKind},
};

fn test_event(key: &SecretKey, i: u32) -> AuditEvent {
    let actor = ActorId::new(key.public_key(), ActorKind::User);
    let resource = ResourceId::new(ResourceKind::Repository, format!("repo-{}", i));

    AuditEvent::builder()
        .now()
        .event_type(EventType::Push {
            force: false,
            commits: i,
        })
        .actor(actor)
        .resource(resource)
        .sign(key)
        .unwrap()
}

fn bench_single_thread_add(c: &mut Criterion) {
    let batch_sizes = [10, 100, 500, 1000];

    let mut group = c.benchmark_group("mempool/add_single");

    for &size in &batch_sizes {
        let key = SecretKey::generate();
        let events: Vec<AuditEvent> = (0..size).map(|i| test_event(&key, i)).collect();

        group.throughput(Throughput::Elements(size as u64));

        // Mutex-based mempool
        group.bench_with_input(
            BenchmarkId::new("mutex", size),
            &events,
            |b, events| {
                b.iter(|| {
                    let mut pool = Mempool::new(MempoolConfig {
                        max_size: 100_000,
                        ..Default::default()
                    });
                    for event in events {
                        pool.add(black_box(event.clone())).unwrap();
                    }
                    pool.len()
                })
            },
        );

        // Lock-free mempool
        group.bench_with_input(
            BenchmarkId::new("lockfree", size),
            &events,
            |b, events| {
                b.iter(|| {
                    let pool = ConcurrentMempool::new(ConcurrentMempoolConfig {
                        max_size: 100_000,
                        ..Default::default()
                    });
                    for event in events {
                        pool.add(black_box(event.clone())).unwrap();
                    }
                    pool.len()
                })
            },
        );
    }

    group.finish();
}

fn bench_single_thread_take(c: &mut Criterion) {
    let batch_sizes = [10, 100, 500, 1000];

    let mut group = c.benchmark_group("mempool/take_single");

    for &size in &batch_sizes {
        let key = SecretKey::generate();
        let events: Vec<AuditEvent> = (0..size).map(|i| test_event(&key, i)).collect();

        group.throughput(Throughput::Elements(size as u64));

        // Mutex-based mempool
        group.bench_with_input(
            BenchmarkId::new("mutex", size),
            &events,
            |b, events| {
                b.iter_batched(
                    || {
                        let mut pool = Mempool::new(MempoolConfig {
                            max_size: 100_000,
                            ..Default::default()
                        });
                        for event in events {
                            pool.add(event.clone()).unwrap();
                        }
                        pool
                    },
                    |mut pool| {
                        black_box(pool.take(size as usize))
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );

        // Lock-free mempool
        group.bench_with_input(
            BenchmarkId::new("lockfree", size),
            &events,
            |b, events| {
                b.iter_batched(
                    || {
                        let pool = ConcurrentMempool::new(ConcurrentMempoolConfig {
                            max_size: 100_000,
                            ..Default::default()
                        });
                        for event in events {
                            pool.add(event.clone()).unwrap();
                        }
                        pool
                    },
                    |pool| {
                        black_box(pool.take(size as usize))
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn bench_multithread_add(c: &mut Criterion) {
    let thread_counts = [2, 4, 8];
    let events_per_thread = 100;

    let mut group = c.benchmark_group("mempool/add_concurrent");
    group.sample_size(50); // Fewer samples for slower benchmarks

    for &threads in &thread_counts {
        let total_events = threads * events_per_thread;
        group.throughput(Throughput::Elements(total_events as u64));

        // Mutex-based mempool (wrapped in Mutex)
        group.bench_function(BenchmarkId::new("mutex", threads), |b| {
            b.iter(|| {
                let pool = Arc::new(Mutex::new(Mempool::new(MempoolConfig {
                    max_size: 100_000,
                    ..Default::default()
                })));

                let handles: Vec<_> = (0..threads)
                    .map(|_| {
                        let pool = Arc::clone(&pool);
                        thread::spawn(move || {
                            let key = SecretKey::generate();
                            for i in 0..events_per_thread {
                                let event = test_event(&key, i as u32);
                                pool.lock().unwrap().add(event).unwrap();
                            }
                        })
                    })
                    .collect();

                for handle in handles {
                    handle.join().unwrap();
                }

                let len = pool.lock().unwrap().len();
                len
            })
        });

        // Lock-free mempool (no external lock needed)
        group.bench_function(BenchmarkId::new("lockfree", threads), |b| {
            b.iter(|| {
                let pool = Arc::new(ConcurrentMempool::new(ConcurrentMempoolConfig {
                    max_size: 100_000,
                    ..Default::default()
                }));

                let handles: Vec<_> = (0..threads)
                    .map(|_| {
                        let pool = Arc::clone(&pool);
                        thread::spawn(move || {
                            let key = SecretKey::generate();
                            for i in 0..events_per_thread {
                                let event = test_event(&key, i as u32);
                                pool.add(event).unwrap();
                            }
                        })
                    })
                    .collect();

                for handle in handles {
                    handle.join().unwrap();
                }

                pool.len()
            })
        });
    }

    group.finish();
}

fn bench_producer_consumer(c: &mut Criterion) {
    let configs = [(2, 2), (4, 2), (4, 4)]; // (producers, consumers)
    let events_per_producer = 50;

    let mut group = c.benchmark_group("mempool/producer_consumer");
    group.sample_size(30); // Fewer samples for complex concurrent benchmarks

    for (producers, consumers) in configs {
        let label = format!("{}p{}c", producers, consumers);
        let total_events = producers * events_per_producer;
        group.throughput(Throughput::Elements(total_events as u64));

        // Lock-free mempool
        group.bench_function(BenchmarkId::new("lockfree", label.clone()), |b| {
            b.iter(|| {
                let pool = Arc::new(ConcurrentMempool::new(ConcurrentMempoolConfig {
                    max_size: 100_000,
                    ..Default::default()
                }));

                // Producers
                let producer_handles: Vec<_> = (0..producers)
                    .map(|_| {
                        let pool = Arc::clone(&pool);
                        thread::spawn(move || {
                            let key = SecretKey::generate();
                            for i in 0..events_per_producer {
                                let event = test_event(&key, i as u32);
                                pool.add(event).unwrap();
                            }
                        })
                    })
                    .collect();

                // Consumers
                let consumer_handles: Vec<_> = (0..consumers)
                    .map(|_| {
                        let pool = Arc::clone(&pool);
                        thread::spawn(move || {
                            let mut taken = 0;
                            for _ in 0..20 {
                                taken += pool.take(10).len();
                                thread::yield_now();
                            }
                            taken
                        })
                    })
                    .collect();

                for handle in producer_handles {
                    handle.join().unwrap();
                }

                let total_taken: usize = consumer_handles
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .sum();

                (pool.len(), total_taken)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_single_thread_add,
    bench_single_thread_take,
    bench_multithread_add,
    bench_producer_consumer,
);

criterion_main!(benches);
