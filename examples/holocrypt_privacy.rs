//! HoloCrypt example: Zero-knowledge proofs and selective encryption.
//!
//! Demonstrates:
//! - Selective field encryption
//! - Zero-knowledge existence proofs
//! - Threshold encryption (k-of-n)
//! - Post-quantum encryption
//!
//! Run with: cargo run --example holocrypt_privacy

use moloch_core::crypto::SecretKey;
use moloch_core::event::{
    ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind,
};
use moloch_holocrypt::{
    generate_keypair, EncryptedEventBuilder, EncryptionPolicy, EventPqcKeyPair, EventProof,
    KeyShareSet, QuantumSafeEvent, ThresholdConfig, ThresholdEvent,
};

fn main() -> anyhow::Result<()> {
    // Create a test event
    let secret_key = SecretKey::generate();
    let actor = ActorId::new(secret_key.public_key(), ActorKind::User);
    let resource = ResourceId::new(ResourceKind::Document, "contract-2024-001");

    let event = AuditEvent::builder()
        .now()
        .event_type(EventType::AccessGranted { permission: "download".into() })
        .actor(actor)
        .resource(resource)
        .outcome(Outcome::Success)
        .metadata(serde_json::json!({
            "ip": "10.0.0.50",
            "action": "download",
            "file_size": 1024000
        }))
        .sign(&secret_key)?;

    println!("=== HoloCrypt Privacy Features ===\n");

    // 1. Selective Field Encryption
    println!("--- Selective Encryption ---\n");

    let (sealing_key, opening_key) = generate_keypair("audit-key");

    let encrypted = EncryptedEventBuilder::new()
        .event(event.clone())
        .policy(EncryptionPolicy::default()) // Encrypts actor + metadata
        .build(&sealing_key)?;

    println!("Encrypted event created:");
    println!("  Event type visible: {:?}", encrypted.header.event_type);
    println!("  Resource visible: {:?}", encrypted.header.resource);
    println!("  Actor encrypted: <hidden>");
    println!("  Metadata encrypted: <hidden>");

    // Decrypt with key
    let decrypted = encrypted.decrypt(&opening_key)?;
    println!(
        "\nDecrypted event - actor restored: {:?}",
        &decrypted.actor
    );

    // 2. Zero-Knowledge Proofs
    println!("\n--- Zero-Knowledge Proofs ---\n");

    // Prove event exists without revealing content
    let existence_proof = EventProof::builder()
        .event(encrypted.clone())
        .prove_existence()
        .build()?;

    println!("Existence proof generated");
    println!("  Proves: Event exists in the system");
    println!("  Reveals: Nothing about content");

    let valid = existence_proof.verify(&encrypted)?;
    println!(
        "  Verification: {}",
        if valid { "PASSED" } else { "FAILED" }
    );

    // Prove event type without revealing actor
    let _type_proof = EventProof::builder()
        .event(encrypted.clone())
        .prove_event_type("Access")
        .build()?;

    println!("\nType proof generated");
    println!("  Proves: Event is of type 'Access'");
    println!("  Reveals: Event type only (not actor/metadata)");

    // 3. Threshold Encryption (k-of-n)
    println!("\n--- Threshold Encryption (2-of-3) ---\n");

    let config = ThresholdConfig::two_of_three();
    let (threshold_event, shares) = ThresholdEvent::seal(&event, config)?;

    println!("Event encrypted with 2-of-3 threshold");
    println!("  Generated {} key shares", shares.len());
    println!("  Requires 2 shares to decrypt");

    // Collect 2 shares (simulating distributed key holders)
    let mut share_set = KeyShareSet::new();
    share_set.add(shares[0].clone());
    share_set.add(shares[1].clone());

    let _threshold_decrypted = threshold_event.unseal(&share_set)?;
    println!("  Decryption with 2 shares: SUCCESS");

    // 4. Post-Quantum Encryption
    println!("\n--- Post-Quantum Encryption (ML-KEM-768) ---\n");

    let pqc_key = EventPqcKeyPair::generate("archive-key");

    let quantum_safe = QuantumSafeEvent::seal(&event, &pqc_key)?;
    println!("Event encrypted with ML-KEM-768 (NIST Level 3)");
    println!("  Algorithm: Kyber/ML-KEM-768");
    println!("  Security: Quantum-resistant");

    let pqc_decrypted = quantum_safe.unseal(&pqc_key)?;
    println!("  Decryption: SUCCESS");
    println!("  Event ID matches: {}", pqc_decrypted.id() == event.id());

    println!("\n=== Demo Complete ===");

    Ok(())
}
