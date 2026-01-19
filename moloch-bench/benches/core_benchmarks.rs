//! Core data structure benchmarks for Moloch.
//!
//! Benchmarks:
//! - Event creation and signing
//! - Event serialization/deserialization
//! - Hash computation
//! - Signature verification
//! - Batch verification (sequential vs batch)

// Link mimalloc global allocator from the bench library
use moloch_bench as _;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use moloch_core::crypto::SecretKey;
use moloch_core::event::{ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind};
use moloch_core::block::{BlockBuilder, SealerId};
use moloch_core::{hash, batch_verify_events, batch_verify_events_parallel, compute_events_root, compute_events_root_parallel};
use moloch_core::rkyv_types::{archive_event, access_event_unchecked};

fn create_test_event(key: &SecretKey) -> AuditEvent {
    let actor = ActorId::new(key.public_key(), ActorKind::User);
    let resource = ResourceId::new(ResourceKind::Repository, "benchmark-repo");

    AuditEvent::builder()
        .now()
        .event_type(EventType::Push { force: false, commits: 5 })
        .actor(actor)
        .resource(resource)
        .outcome(Outcome::Success)
        .metadata(serde_json::json!({
            "branch": "main",
            "commits": ["abc123", "def456", "ghi789"]
        }))
        .sign(key)
        .unwrap()
}

fn bench_event_creation(c: &mut Criterion) {
    let key = SecretKey::generate();
    let actor = ActorId::new(key.public_key(), ActorKind::User);
    let resource = ResourceId::new(ResourceKind::Repository, "benchmark-repo");

    c.bench_function("event/create_and_sign", |b| {
        b.iter(|| {
            AuditEvent::builder()
                .now()
                .event_type(EventType::Push { force: false, commits: 5 })
                .actor(actor.clone())
                .resource(resource.clone())
                .outcome(Outcome::Success)
                .sign(&key)
                .unwrap()
        })
    });
}

fn bench_event_serialization(c: &mut Criterion) {
    let key = SecretKey::generate();
    let event = create_test_event(&key);

    let mut group = c.benchmark_group("event/serialization");

    // JSON serialization
    group.bench_function("serialize_json", |b| {
        b.iter(|| serde_json::to_vec(black_box(&event)).unwrap())
    });

    let json_bytes = serde_json::to_vec(&event).unwrap();

    group.bench_function("deserialize_json", |b| {
        b.iter(|| serde_json::from_slice::<AuditEvent>(black_box(&json_bytes)).unwrap())
    });

    // Bincode serialization
    group.bench_function("serialize_bincode", |b| {
        b.iter(|| bincode::serialize(black_box(&event)).unwrap())
    });

    let bincode_bytes = bincode::serialize(&event).unwrap();

    group.bench_function("deserialize_bincode", |b| {
        b.iter(|| bincode::deserialize::<AuditEvent>(black_box(&bincode_bytes)).unwrap())
    });

    // rkyv serialization (zero-copy)
    group.bench_function("serialize_rkyv", |b| {
        b.iter(|| archive_event(black_box(&event)))
    });

    let rkyv_bytes = archive_event(&event);

    group.bench_function("access_rkyv_zerocopy", |b| {
        b.iter(|| {
            // Zero-copy access - just pointer cast, no deserialization
            let archived = unsafe { access_event_unchecked(black_box(&rkyv_bytes)) };
            black_box(archived.timestamp_ms);
        })
    });

    // Print sizes for comparison
    println!("\nSerialization sizes:");
    println!("  JSON:    {} bytes", json_bytes.len());
    println!("  Bincode: {} bytes", bincode_bytes.len());
    println!("  rkyv:    {} bytes", rkyv_bytes.len());

    group.finish();
}

fn bench_event_id_computation(c: &mut Criterion) {
    let key = SecretKey::generate();
    let event = create_test_event(&key);

    c.bench_function("event/compute_id", |b| {
        b.iter(|| black_box(&event).id())
    });
}

fn bench_event_validation(c: &mut Criterion) {
    let key = SecretKey::generate();
    let event = create_test_event(&key);

    c.bench_function("event/validate", |b| {
        b.iter(|| black_box(&event).validate())
    });
}

fn bench_hash_operations(c: &mut Criterion) {
    let data_sizes = [32, 256, 1024, 4096, 16384];

    let mut group = c.benchmark_group("hash");

    for size in data_sizes {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("blake3", size), &data, |b, data| {
            b.iter(|| hash(black_box(data)))
        });
    }

    group.finish();
}

fn bench_signature_operations(c: &mut Criterion) {
    let key = SecretKey::generate();
    let message = b"benchmark message for signature operations";

    let mut group = c.benchmark_group("signature");

    group.bench_function("sign", |b| {
        b.iter(|| key.sign(black_box(message)))
    });

    let signature = key.sign(message);
    let public_key = key.public_key();

    group.bench_function("verify", |b| {
        b.iter(|| public_key.verify(black_box(message), black_box(&signature)))
    });

    group.finish();
}

fn bench_batch_verification(c: &mut Criterion) {
    let batch_sizes = [10, 50, 100, 500, 1000];

    let mut group = c.benchmark_group("verification");

    for &size in &batch_sizes {
        // Generate events with different keys for realistic benchmark
        let events: Vec<AuditEvent> = (0..size)
            .map(|i| {
                let key = SecretKey::generate();
                let actor = ActorId::new(key.public_key(), ActorKind::User);
                let resource = ResourceId::new(ResourceKind::Repository, format!("repo-{}", i));

                AuditEvent::builder()
                    .now()
                    .event_type(EventType::Push { force: false, commits: i as u32 })
                    .actor(actor)
                    .resource(resource)
                    .outcome(Outcome::Success)
                    .sign(&key)
                    .unwrap()
            })
            .collect();

        group.throughput(Throughput::Elements(size as u64));

        // Sequential verification (baseline)
        group.bench_with_input(
            BenchmarkId::new("sequential", size),
            &events,
            |b, events| {
                b.iter(|| {
                    for event in events {
                        black_box(event).validate().unwrap();
                    }
                })
            },
        );

        // Batch verification (optimized)
        group.bench_with_input(
            BenchmarkId::new("batch", size),
            &events,
            |b, events| {
                b.iter(|| batch_verify_events(black_box(events)).unwrap())
            },
        );

        // Parallel batch verification (multi-core)
        group.bench_with_input(
            BenchmarkId::new("parallel", size),
            &events,
            |b, events| {
                b.iter(|| batch_verify_events_parallel(black_box(events)).unwrap())
            },
        );
    }

    group.finish();
}

fn bench_merkle_root(c: &mut Criterion) {
    let batch_sizes = [10, 50, 100, 500, 1000];

    let mut group = c.benchmark_group("merkle_root");

    for &size in &batch_sizes {
        // Generate events
        let events: Vec<AuditEvent> = (0..size)
            .map(|i| {
                let key = SecretKey::generate();
                let actor = ActorId::new(key.public_key(), ActorKind::User);
                let resource = ResourceId::new(ResourceKind::Repository, format!("repo-{}", i));

                AuditEvent::builder()
                    .now()
                    .event_type(EventType::Push { force: false, commits: i as u32 })
                    .actor(actor)
                    .resource(resource)
                    .outcome(Outcome::Success)
                    .sign(&key)
                    .unwrap()
            })
            .collect();

        group.throughput(Throughput::Elements(size as u64));

        // Sequential merkle root
        group.bench_with_input(
            BenchmarkId::new("sequential", size),
            &events,
            |b, events| {
                b.iter(|| compute_events_root(black_box(events)))
            },
        );

        // Parallel merkle root
        group.bench_with_input(
            BenchmarkId::new("parallel", size),
            &events,
            |b, events| {
                b.iter(|| compute_events_root_parallel(black_box(events)))
            },
        );
    }

    group.finish();
}

fn bench_block_validation(c: &mut Criterion) {
    let block_sizes = [10, 100, 500];

    let mut group = c.benchmark_group("block/validate");

    for &size in &block_sizes {
        let key = SecretKey::generate();
        let sealer = SealerId::new(key.public_key());

        // Generate events
        let events: Vec<AuditEvent> = (0..size)
            .map(|i| {
                let event_key = SecretKey::generate();
                let actor = ActorId::new(event_key.public_key(), ActorKind::User);
                let resource = ResourceId::new(ResourceKind::Repository, format!("repo-{}", i));

                AuditEvent::builder()
                    .now()
                    .event_type(EventType::Push { force: false, commits: i as u32 })
                    .actor(actor)
                    .resource(resource)
                    .outcome(Outcome::Success)
                    .sign(&event_key)
                    .unwrap()
            })
            .collect();

        // Create block
        let block = BlockBuilder::new(sealer)
            .events(events)
            .seal(&key);

        group.throughput(Throughput::Elements(size as u64));

        // Sequential validation
        group.bench_with_input(
            BenchmarkId::new("sequential", size),
            &block,
            |b, block| {
                b.iter(|| black_box(block).validate(None).unwrap())
            },
        );

        // Batch validation
        group.bench_with_input(
            BenchmarkId::new("batch", size),
            &block,
            |b, block| {
                b.iter(|| black_box(block).validate_batch(None).unwrap())
            },
        );

        // Parallel validation (batch + parallel merkle + parallel canonical bytes)
        group.bench_with_input(
            BenchmarkId::new("parallel", size),
            &block,
            |b, block| {
                b.iter(|| black_box(block).validate_parallel(None).unwrap())
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_event_creation,
    bench_event_serialization,
    bench_event_id_computation,
    bench_event_validation,
    bench_hash_operations,
    bench_signature_operations,
    bench_batch_verification,
    bench_merkle_root,
    bench_block_validation,
);

criterion_main!(benches);
