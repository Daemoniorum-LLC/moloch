//! Anchor manager for coordinating anchoring operations.
//!
//! The manager orchestrates providers, scheduling, and proof tracking.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::commitment::Commitment;
use crate::errors::{AnchorError, Result};
use crate::proof::{AnchorProof, AnchorStatus, ProofBundle, Verification};
#[cfg(test)]
use crate::provider::AnchorProvider;
use crate::provider::{AnchorTx, TxId};
use crate::registry::{ProviderRegistry, SelectionStrategy};
use crate::scheduler::{AnchorPriority, AnchorRequest, AnchorScheduler};

/// Anchor manager configuration.
#[derive(Debug, Clone)]
pub struct AnchorManagerConfig {
    /// Required confirmations before considering anchor confirmed.
    pub required_confirmations: u64,
    /// Finality threshold (confirmations to consider final).
    pub finality_threshold: u64,
    /// Maximum concurrent anchor operations.
    pub max_concurrent_anchors: usize,
    /// Retry failed anchors.
    pub retry_on_failure: bool,
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Default provider selection strategy.
    pub default_strategy: SelectionStrategy,
}

impl Default for AnchorManagerConfig {
    fn default() -> Self {
        Self {
            required_confirmations: 6,
            finality_threshold: 100,
            max_concurrent_anchors: 10,
            retry_on_failure: true,
            max_retries: 3,
            default_strategy: SelectionStrategy::All,
        }
    }
}

/// Status of an anchoring operation.
#[derive(Debug, Clone)]
pub struct AnchorOperation {
    /// The commitment being anchored.
    pub commitment: Commitment,
    /// Submitted transactions by provider.
    pub transactions: HashMap<String, AnchorTx>,
    /// Proofs received.
    pub proofs: Vec<AnchorProof>,
    /// Current status.
    pub status: OperationStatus,
    /// Retry count.
    pub retry_count: u32,
    /// Created timestamp.
    pub created_at: i64,
    /// Last update timestamp.
    pub updated_at: i64,
}

/// Operation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    /// Queued for processing.
    Queued,
    /// Submitting to providers.
    Submitting,
    /// Waiting for confirmations.
    Pending,
    /// At least one provider confirmed.
    Confirmed,
    /// All required providers finalized.
    Finalized,
    /// Operation failed.
    Failed,
}

impl AnchorOperation {
    /// Create a new operation.
    fn new(commitment: Commitment) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            commitment,
            transactions: HashMap::new(),
            proofs: Vec::new(),
            status: OperationStatus::Queued,
            retry_count: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Add a transaction.
    fn add_tx(&mut self, provider_id: String, tx: AnchorTx) {
        self.transactions.insert(provider_id, tx);
        self.updated_at = chrono::Utc::now().timestamp();
    }

    /// Add a proof.
    fn add_proof(&mut self, proof: AnchorProof) {
        self.proofs.push(proof);
        self.updated_at = chrono::Utc::now().timestamp();
    }

    /// Update status.
    fn set_status(&mut self, status: OperationStatus) {
        self.status = status;
        self.updated_at = chrono::Utc::now().timestamp();
    }
}

/// The anchor manager coordinates all anchoring operations.
pub struct AnchorManager {
    /// Configuration.
    config: AnchorManagerConfig,
    /// Provider registry.
    registry: Arc<ProviderRegistry>,
    /// Request scheduler.
    scheduler: Arc<AnchorScheduler>,
    /// Active operations by commitment hash.
    operations: RwLock<HashMap<String, AnchorOperation>>,
    /// Completed proofs by commitment hash.
    completed: RwLock<HashMap<String, ProofBundle>>,
}

impl AnchorManager {
    /// Create a new anchor manager.
    pub fn new(registry: Arc<ProviderRegistry>, scheduler: Arc<AnchorScheduler>) -> Self {
        Self::with_config(registry, scheduler, AnchorManagerConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(
        registry: Arc<ProviderRegistry>,
        scheduler: Arc<AnchorScheduler>,
        config: AnchorManagerConfig,
    ) -> Self {
        Self {
            config,
            registry,
            scheduler,
            operations: RwLock::new(HashMap::new()),
            completed: RwLock::new(HashMap::new()),
        }
    }

    /// Submit a commitment for anchoring.
    pub async fn anchor(&self, commitment: Commitment) -> Result<String> {
        self.anchor_with_priority(commitment, AnchorPriority::Normal)
            .await
    }

    /// Submit a commitment with priority.
    pub async fn anchor_with_priority(
        &self,
        commitment: Commitment,
        priority: AnchorPriority,
    ) -> Result<String> {
        let op_id = hex::encode(commitment.hash().as_bytes());

        // Check if already processing
        if self.operations.read().contains_key(&op_id) {
            return Ok(op_id);
        }

        // Create operation
        let operation = AnchorOperation::new(commitment.clone());
        self.operations.write().insert(op_id.clone(), operation);

        // Submit to scheduler
        let request = AnchorRequest::new(commitment).with_priority(priority);
        self.scheduler.submit(request)?;

        Ok(op_id)
    }

    /// Process pending anchor requests.
    pub async fn process(&self) -> Result<usize> {
        let requests = self
            .scheduler
            .next_batch(self.config.max_concurrent_anchors);
        let mut processed = 0;

        for request in requests {
            let result = self.submit_to_providers(&request).await;
            if result.is_ok() {
                processed += 1;
            }
        }

        Ok(processed)
    }

    /// Submit a request to all selected providers.
    async fn submit_to_providers(&self, request: &AnchorRequest) -> Result<()> {
        let op_id = hex::encode(request.commitment.hash().as_bytes());

        // Update status
        if let Some(op) = self.operations.write().get_mut(&op_id) {
            op.set_status(OperationStatus::Submitting);
        }

        // Select providers
        let providers = if request.target_chains.is_empty() {
            self.registry.select(self.config.default_strategy)
        } else {
            request
                .target_chains
                .iter()
                .flat_map(|chain| self.registry.for_chain(chain))
                .collect()
        };

        if providers.is_empty() {
            return Err(AnchorError::NoProvidersAvailable);
        }

        // Submit to each provider
        let mut success = false;
        for provider in providers {
            match provider.submit(&request.commitment).await {
                Ok(tx) => {
                    let provider_id = provider.id().to_string();
                    if let Some(op) = self.operations.write().get_mut(&op_id) {
                        op.add_tx(provider_id.clone(), tx);
                    }
                    self.registry.record_success(&provider_id);
                    success = true;
                }
                Err(_e) => {
                    let provider_id = provider.id().to_string();
                    self.registry.record_failure(&provider_id);
                    // Continue trying other providers
                }
            }
        }

        // Update status
        if let Some(op) = self.operations.write().get_mut(&op_id) {
            if success {
                op.set_status(OperationStatus::Pending);
            } else {
                op.set_status(OperationStatus::Failed);
            }
        }

        if success {
            Ok(())
        } else {
            Err(AnchorError::AllProvidersFailed)
        }
    }

    /// Check and update confirmation status for all pending operations.
    pub async fn update_confirmations(&self) -> Result<()> {
        let op_ids: Vec<String> = self
            .operations
            .read()
            .iter()
            .filter(|(_, op)| {
                matches!(
                    op.status,
                    OperationStatus::Pending | OperationStatus::Confirmed
                )
            })
            .map(|(id, _)| id.clone())
            .collect();

        for op_id in op_ids {
            self.check_operation_confirmations(&op_id).await?;
        }

        Ok(())
    }

    /// Check confirmations for a specific operation.
    async fn check_operation_confirmations(&self, op_id: &str) -> Result<()> {
        let txs: Vec<(String, TxId)> = {
            let ops = self.operations.read();
            if let Some(op) = ops.get(op_id) {
                op.transactions
                    .iter()
                    .map(|(pid, tx)| (pid.clone(), tx.tx_id.clone()))
                    .collect()
            } else {
                return Ok(());
            }
        };

        let mut any_confirmed = false;
        let mut all_finalized = true;

        for (provider_id, tx_id) in txs {
            if let Some(provider) = self.registry.get(&provider_id) {
                match provider.confirmations(&tx_id).await {
                    Ok(confirmations) => {
                        if confirmations >= self.config.required_confirmations {
                            any_confirmed = true;

                            // Get full proof
                            if let Ok(proof) = provider.get_proof(&tx_id).await {
                                let status = if confirmations >= self.config.finality_threshold {
                                    AnchorStatus::Finalized
                                } else {
                                    AnchorStatus::Confirmed(confirmations)
                                };

                                let proof = AnchorProof { status, ..proof };

                                if let Some(op) = self.operations.write().get_mut(op_id) {
                                    op.add_proof(proof);
                                }
                            }

                            if confirmations < self.config.finality_threshold {
                                all_finalized = false;
                            }
                        } else {
                            all_finalized = false;
                        }
                    }
                    Err(_) => {
                        all_finalized = false;
                    }
                }
            }
        }

        // Update operation status
        if let Some(op) = self.operations.write().get_mut(op_id) {
            if all_finalized && !op.transactions.is_empty() {
                op.set_status(OperationStatus::Finalized);
            } else if any_confirmed {
                op.set_status(OperationStatus::Confirmed);
            }
        }

        Ok(())
    }

    /// Get operation status.
    pub fn get_operation(&self, op_id: &str) -> Option<AnchorOperation> {
        self.operations.read().get(op_id).cloned()
    }

    /// Get proof bundle for a completed operation.
    pub fn get_proof_bundle(&self, op_id: &str) -> Option<ProofBundle> {
        // First check completed
        if let Some(bundle) = self.completed.read().get(op_id) {
            return Some(bundle.clone());
        }

        // Check if operation is finalized
        let ops = self.operations.read();
        if let Some(op) = ops.get(op_id) {
            if op.status == OperationStatus::Finalized {
                let mut bundle = ProofBundle::new(op.commitment.clone());
                for proof in &op.proofs {
                    bundle.add_proof(proof.clone());
                }
                return Some(bundle);
            }
        }

        None
    }

    /// Complete an operation (move to completed set).
    pub fn complete_operation(&self, op_id: &str) -> Option<ProofBundle> {
        let mut ops = self.operations.write();
        if let Some(op) = ops.remove(op_id) {
            let mut bundle = ProofBundle::new(op.commitment);
            for proof in op.proofs {
                bundle.add_proof(proof);
            }
            self.completed
                .write()
                .insert(op_id.to_string(), bundle.clone());
            return Some(bundle);
        }
        None
    }

    /// Verify an anchor proof.
    pub async fn verify(&self, proof: &AnchorProof) -> Result<Verification> {
        if let Some(provider) = self.registry.get(&proof.provider) {
            match provider.verify(proof).await {
                Ok(true) => {
                    let confirmations = provider.confirmations(&proof.tx_id).await.unwrap_or(0);
                    Ok(Verification::success(
                        &proof.provider,
                        &proof.chain_id,
                        confirmations,
                    ))
                }
                Ok(false) => Ok(Verification::failure(
                    &proof.provider,
                    &proof.chain_id,
                    "Proof verification failed",
                )),
                Err(e) => Ok(Verification::failure(
                    &proof.provider,
                    &proof.chain_id,
                    e.to_string(),
                )),
            }
        } else {
            Err(AnchorError::ProviderNotFound(proof.provider.clone()))
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> AnchorStats {
        let ops = self.operations.read();
        let mut stats = AnchorStats::default();

        for op in ops.values() {
            stats.total_operations += 1;
            match op.status {
                OperationStatus::Queued => stats.queued += 1,
                OperationStatus::Submitting => stats.submitting += 1,
                OperationStatus::Pending => stats.pending += 1,
                OperationStatus::Confirmed => stats.confirmed += 1,
                OperationStatus::Finalized => stats.finalized += 1,
                OperationStatus::Failed => stats.failed += 1,
            }
        }

        stats.completed = self.completed.read().len();
        stats.providers = self.registry.enabled_count();

        stats
    }
}

/// Anchor statistics.
#[derive(Debug, Clone, Default)]
pub struct AnchorStats {
    /// Total active operations.
    pub total_operations: usize,
    /// Queued count.
    pub queued: usize,
    /// Currently submitting.
    pub submitting: usize,
    /// Pending confirmation.
    pub pending: usize,
    /// Confirmed but not finalized.
    pub confirmed: usize,
    /// Fully finalized.
    pub finalized: usize,
    /// Failed operations.
    pub failed: usize,
    /// Completed and archived.
    pub completed: usize,
    /// Available providers.
    pub providers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{AnchorCost, ProviderCapabilities, ProviderInfo, ProviderStatus};
    use async_trait::async_trait;
    use moloch_core::Hash;

    struct MockProvider {
        id: String,
    }

    #[async_trait]
    impl AnchorProvider for MockProvider {
        fn info(&self) -> ProviderInfo {
            ProviderInfo {
                id: self.id.clone(),
                name: self.id.clone(),
                chain_id: "testnet".to_string(),
                status: ProviderStatus::Available,
                capabilities: ProviderCapabilities::default(),
                block_height: 1000,
                endpoint: None,
            }
        }

        fn id(&self) -> &str {
            &self.id
        }

        async fn status(&self) -> ProviderStatus {
            ProviderStatus::Available
        }

        async fn submit(&self, commitment: &Commitment) -> Result<AnchorTx> {
            Ok(AnchorTx::pending(TxId::new("mock_tx"), &self.id, "testnet"))
        }

        async fn verify(&self, _proof: &AnchorProof) -> Result<bool> {
            Ok(true)
        }

        async fn confirmations(&self, _tx_id: &TxId) -> Result<u64> {
            Ok(100)
        }

        async fn get_proof(&self, tx_id: &TxId) -> Result<AnchorProof> {
            Ok(AnchorProof::new(
                Commitment::new("test", Hash::ZERO, 1),
                &self.id,
                "testnet",
                tx_id.clone(),
                1000,
                "block",
            ))
        }

        async fn estimate_cost(&self, _commitment: &Commitment) -> Result<AnchorCost> {
            Ok(AnchorCost::new(0.001, "TEST"))
        }

        async fn block_height(&self) -> Result<u64> {
            Ok(1000)
        }
    }

    #[tokio::test]
    async fn test_anchor_manager() {
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register(Arc::new(MockProvider {
                id: "mock".to_string(),
            }))
            .unwrap();

        let scheduler = Arc::new(AnchorScheduler::new());
        let manager = AnchorManager::new(registry, scheduler);

        let commitment = Commitment::new("test", Hash::ZERO, 100);
        let op_id = manager.anchor(commitment).await.unwrap();

        assert!(!op_id.is_empty());

        let stats = manager.stats();
        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.queued, 1);
    }
}
