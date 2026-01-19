//! Bridge protocol for cross-chain communication.

use std::sync::Arc;

use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

use crate::chain::ChainStatus;
use crate::errors::{FederationError, Result};
use crate::proof::{CrossChainReference, FinalityProof, ProofBundle};

use moloch_core::{BlockHash, EventId, Hash};

/// Bridge configuration.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Maximum pending messages.
    pub max_pending: usize,
    /// Timeout for requests in seconds.
    pub request_timeout_secs: u64,
    /// Retry attempts for failed requests.
    pub retry_attempts: u32,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            max_pending: 1000,
            request_timeout_secs: 30,
            retry_attempts: 3,
        }
    }
}

/// State of the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeState {
    /// Bridge is connecting.
    Connecting,
    /// Bridge is active.
    Active,
    /// Bridge is disconnected.
    Disconnected,
    /// Bridge encountered an error.
    Error,
}

/// Messages that can be sent over the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeMessage {
    /// Request event proof.
    RequestProof {
        /// Event ID.
        event_id: EventId,
        /// Requesting chain.
        from_chain: String,
    },
    /// Proof response.
    ProofResponse {
        /// Event ID.
        event_id: EventId,
        /// Proof bundle.
        proof: ProofBundle,
    },
    /// Chain status update.
    StatusUpdate {
        /// Chain ID.
        chain_id: String,
        /// New status.
        status: ChainStatus,
        /// Finalized height.
        height: u64,
    },
    /// Ping for liveness.
    Ping {
        /// Timestamp.
        timestamp: i64,
    },
    /// Pong response.
    Pong {
        /// Original timestamp.
        timestamp: i64,
    },
}

/// Bridge to a federated chain.
pub struct Bridge {
    /// Target chain ID.
    chain_id: String,
    /// Bridge configuration.
    config: BridgeConfig,
    /// Current state.
    state: Arc<RwLock<BridgeState>>,
    /// Pending requests.
    pending: Arc<RwLock<Vec<PendingRequest>>>,
}

/// A pending request.
struct PendingRequest {
    /// Request ID.
    id: u64,
    /// Event ID being requested.
    event_id: EventId,
    /// Creation time.
    created_at: i64,
}

impl Bridge {
    /// Create a new bridge.
    pub fn new(chain_id: String) -> Self {
        Self {
            chain_id,
            config: BridgeConfig::default(),
            state: Arc::new(RwLock::new(BridgeState::Connecting)),
            pending: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create with configuration.
    pub fn with_config(chain_id: String, config: BridgeConfig) -> Self {
        Self {
            chain_id,
            config,
            state: Arc::new(RwLock::new(BridgeState::Connecting)),
            pending: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get bridge state.
    pub async fn state(&self) -> BridgeState {
        *self.state.read().await
    }

    /// Check if bridge is active.
    pub async fn is_active(&self) -> bool {
        *self.state.read().await == BridgeState::Active
    }

    /// Create a cross-chain reference.
    pub async fn create_reference(&self, event_id: EventId) -> Result<CrossChainReference> {
        // In a real implementation, this would query the remote chain
        // For now, create a placeholder reference
        let reference = CrossChainReference::new(
            self.chain_id.clone(),
            event_id,
            0, // Would be fetched from remote
            BlockHash(Hash::ZERO), // Would be fetched from remote
        );

        Ok(reference)
    }

    /// Verify a cross-chain reference.
    pub async fn verify_reference(&self, reference: &CrossChainReference) -> Result<bool> {
        // Verify the reference belongs to this chain
        if reference.source_chain != self.chain_id {
            return Err(FederationError::InvalidReference(
                "chain mismatch".to_string(),
            ));
        }

        // Check if proof is present
        let proof = reference.proof.as_ref()
            .ok_or_else(|| FederationError::ProofVerificationFailed(
                "no proof attached".to_string(),
            ))?;

        // Verify event proof matches reference
        if proof.event_proof.event_id != reference.event_id {
            return Err(FederationError::ProofVerificationFailed(
                "event ID mismatch".to_string(),
            ));
        }

        // In a real implementation:
        // 1. Verify event inclusion in block
        // 2. Verify block finality
        // 3. Verify chain state consistency

        Ok(true)
    }

    /// Request proof from remote chain.
    pub async fn request_proof(&self, event_id: EventId, from_chain: &str) -> Result<()> {
        let mut pending = self.pending.write().await;

        if pending.len() >= self.config.max_pending {
            return Err(FederationError::BridgeConnectionFailed(
                "too many pending requests".to_string(),
            ));
        }

        let request = PendingRequest {
            id: pending.len() as u64 + 1,
            event_id,
            created_at: chrono::Utc::now().timestamp(),
        };

        pending.push(request);

        // In a real implementation, send message to remote chain
        let _message = BridgeMessage::RequestProof {
            event_id,
            from_chain: from_chain.to_string(),
        };

        Ok(())
    }

    /// Get pending request count.
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }

    /// Clean up expired requests.
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now().timestamp();
        let timeout = self.config.request_timeout_secs as i64;

        let mut pending = self.pending.write().await;
        pending.retain(|r| now - r.created_at < timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bridge_creation() {
        let bridge = Bridge::new("test-chain".to_string());
        assert_eq!(bridge.state().await, BridgeState::Connecting);
        assert!(!bridge.is_active().await);
    }

    #[tokio::test]
    async fn test_create_reference() {
        let bridge = Bridge::new("test-chain".to_string());
        let event_id = EventId(Hash::ZERO);

        let reference = bridge.create_reference(event_id).await.unwrap();
        assert_eq!(reference.source_chain, "test-chain");
        assert_eq!(reference.event_id, event_id);
    }

    #[tokio::test]
    async fn test_pending_requests() {
        let bridge = Bridge::new("test-chain".to_string());
        let event_id = EventId(Hash::ZERO);

        bridge.request_proof(event_id, "other-chain").await.unwrap();
        assert_eq!(bridge.pending_count().await, 1);
    }
}
