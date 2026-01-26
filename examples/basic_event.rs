//! Basic example: Create and sign an audit event.
//!
//! Run with: cargo run --example basic_event

use moloch_core::crypto::SecretKey;
use moloch_core::event::{
    ActorId, ActorKind, AuditEvent, EventType, Outcome, ResourceId, ResourceKind,
};

fn main() -> anyhow::Result<()> {
    // Generate a signing key
    let secret_key = SecretKey::generate();
    let public_key = secret_key.public_key();

    println!("Generated keypair:");
    println!("  Public key: {:?}", public_key);

    // Create an actor (the entity performing the action)
    let actor = ActorId::new(public_key.clone(), ActorKind::User);

    // Create a resource (what the action affects)
    let resource = ResourceId::new(ResourceKind::Repository, "my-org/my-repo");

    // Build and sign an audit event
    let event = AuditEvent::builder()
        .now()
        .event_type(EventType::Push {
            force: false,
            commits: 5,
        })
        .actor(actor)
        .resource(resource)
        .outcome(Outcome::Success)
        .metadata(serde_json::json!({
            "branch": "main",
            "commit_sha": "abc123def456",
            "ip_address": "192.168.1.100"
        }))
        .sign(&secret_key)?;

    println!("\nCreated audit event:");
    println!("  Event ID: {:?}", event.id());
    println!("  Timestamp: {}", event.timestamp_ms());
    println!("  Event Type: {:?}", event.event_type());
    println!("  Outcome: {:?}", event.outcome());

    // Verify the signature
    let is_valid = event.verify()?;
    println!("\nSignature valid: {}", is_valid);

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&event)?;
    println!("\nEvent JSON:\n{}", json);

    Ok(())
}
