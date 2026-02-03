//! Ethereum AnchorProvider implementation.

use alloy::consensus::Transaction as TxTrait;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::{Client, Http};
use async_trait::async_trait;
use parking_lot::RwLock;

use moloch_anchor::{
    AnchorCost, AnchorProof, AnchorProvider, AnchorStatus, AnchorTx, Commitment, FinalityType,
    ProviderCapabilities, ProviderInfo, ProviderStatus, TxId,
};
use moloch_core::Hash;

use crate::config::{AnchorMethod, EthereumConfig};
use crate::error::{EthereumError, Result};
use crate::{ANCHOR_DATA_SIZE, MOLOCH_SELECTOR};

/// Ethereum anchor provider.
///
/// Implements anchoring via calldata or smart contract events.
pub struct EthereumProvider {
    /// Provider ID.
    id: String,
    /// Configuration.
    config: EthereumConfig,
    /// Alloy provider.
    provider: RootProvider<Http<Client>>,
    /// Wallet for signing.
    wallet: Option<EthereumWallet>,
    /// Signer address.
    signer_address: Option<Address>,
    /// Current status.
    status: RwLock<ProviderStatus>,
    /// Cached block number.
    cached_block: RwLock<Option<(u64, i64)>>,
}

impl EthereumProvider {
    /// Create a new Ethereum provider.
    pub async fn new(config: EthereumConfig) -> Result<Self> {
        config.validate()?;

        let id = config.provider_id.clone();

        // Create HTTP provider
        let provider = ProviderBuilder::new().on_http(
            config
                .rpc_url
                .parse()
                .map_err(|e: url::ParseError| EthereumError::RpcConnection(e.to_string()))?,
        );

        // Set up wallet if private key provided
        let (wallet, signer_address) = if let Some(ref key) = config.private_key {
            let key_hex = key.strip_prefix("0x").unwrap_or(key);
            let signer: PrivateKeySigner = key_hex.parse()?;
            let address = signer.address();
            let wallet = EthereumWallet::from(signer);
            (Some(wallet), Some(address))
        } else {
            (None, None)
        };

        Ok(Self {
            id,
            config,
            provider,
            wallet,
            signer_address,
            status: RwLock::new(ProviderStatus::Available),
            cached_block: RwLock::new(None),
        })
    }

    /// Create and verify connection.
    pub async fn connect(config: EthereumConfig) -> Result<Self> {
        let provider = Self::new(config).await?;
        provider.verify_chain().await?;
        Ok(provider)
    }

    /// Verify chain ID matches configuration.
    async fn verify_chain(&self) -> Result<()> {
        let chain_id = self.provider.get_chain_id().await?;
        let expected = self.config.chain.chain_id();

        if chain_id != expected {
            return Err(EthereumError::NetworkMismatch {
                expected,
                got: chain_id,
            });
        }

        Ok(())
    }

    /// Get current block number with caching.
    async fn get_block_number_cached(&self) -> Result<u64> {
        let now = chrono::Utc::now().timestamp();

        // Check cache (valid for 3 seconds)
        if let Some((block, ts)) = *self.cached_block.read() {
            if now - ts < 3 {
                return Ok(block);
            }
        }

        // Fetch fresh value
        let block = self.provider.get_block_number().await?;
        *self.cached_block.write() = Some((block, now));
        Ok(block)
    }

    /// Parse TxId to Ethereum TxHash.
    fn parse_tx_hash(tx_id: &TxId) -> Result<TxHash> {
        let hex = tx_id.0.strip_prefix("0x").unwrap_or(&tx_id.0);
        let bytes = hex::decode(hex)?;
        if bytes.len() != 32 {
            return Err(EthereumError::InvalidTxHash("invalid length".into()));
        }
        Ok(TxHash::from_slice(&bytes))
    }

    /// Format TxHash as TxId.
    fn format_tx_hash(hash: &TxHash) -> TxId {
        TxId::new(format!("0x{}", hex::encode(hash.as_slice())))
    }

    /// Build anchor calldata.
    fn build_calldata(commitment: &Commitment) -> Vec<u8> {
        let mut data = Vec::with_capacity(ANCHOR_DATA_SIZE);

        // Selector
        data.extend_from_slice(&MOLOCH_SELECTOR);

        // Commitment hash
        let commitment_hash = commitment.hash();
        data.extend_from_slice(commitment_hash.as_bytes());

        // Chain ID hash (first 8 bytes)
        let chain_hash = moloch_core::hash(commitment.chain_id.as_bytes());
        data.extend_from_slice(&chain_hash.as_bytes()[..8]);

        data
    }

    /// Parse anchor calldata.
    fn parse_calldata(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if data.len() < ANCHOR_DATA_SIZE {
            return Err(EthereumError::InvalidCalldata(format!(
                "data too small: {} < {}",
                data.len(),
                ANCHOR_DATA_SIZE
            )));
        }

        // Check selector
        if data[0..4] != MOLOCH_SELECTOR {
            return Err(EthereumError::InvalidCalldata("invalid selector".into()));
        }

        Ok((
            data[4..36].to_vec(),  // commitment hash
            data[36..44].to_vec(), // chain id hash
        ))
    }

    /// Send anchor transaction via calldata.
    async fn send_calldata_anchor(&self, commitment: &Commitment) -> Result<TxHash> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| EthereumError::Wallet("no wallet configured".into()))?;

        let from = self
            .signer_address
            .ok_or_else(|| EthereumError::Wallet("no signer address".into()))?;

        // Build calldata
        let calldata = Self::build_calldata(commitment);

        // Create transaction to self (anchor transaction)
        let tx = TransactionRequest::default()
            .with_from(from)
            .with_to(from) // Send to self
            .with_value(U256::ZERO)
            .with_input(Bytes::from(calldata));

        // Get gas estimate
        let gas_estimate = self.provider.estimate_gas(&tx).await?;

        // Get gas price
        let gas_price: u128 = if self.config.gas_price_gwei > 0 {
            self.config.gas_price_gwei as u128 * 1_000_000_000u128
        } else {
            self.provider.get_gas_price().await?
        };

        // Build final transaction
        let tx = tx
            .with_gas_limit(gas_estimate)
            .with_gas_price(gas_price)
            .with_chain_id(self.config.chain.chain_id())
            .with_nonce(self.provider.get_transaction_count(from).await?);

        // Sign and send
        let tx_envelope = tx
            .build(wallet)
            .await
            .map_err(|e| EthereumError::TxBuild(e.to_string()))?;

        let pending = self
            .provider
            .send_tx_envelope(tx_envelope)
            .await
            .map_err(|e| EthereumError::Broadcast(e.to_string()))?;

        Ok(*pending.tx_hash())
    }

    /// Get transaction confirmations.
    async fn get_confirmations(&self, tx_hash: &TxHash) -> Result<u64> {
        // Get receipt
        let receipt = self
            .provider
            .get_transaction_receipt(*tx_hash)
            .await?
            .ok_or_else(|| EthereumError::ReceiptNotFound(tx_hash.to_string()))?;

        // Check if reverted
        if !receipt.status() {
            return Err(EthereumError::Reverted(tx_hash.to_string()));
        }

        // Calculate confirmations
        let tx_block = receipt.block_number.unwrap_or(0);
        let current_block = self.get_block_number_cached().await?;

        if current_block >= tx_block {
            Ok(current_block - tx_block + 1)
        } else {
            Ok(0)
        }
    }

    /// Update provider status.
    async fn update_status(&self) {
        let status = match self.provider.get_chain_id().await {
            Ok(_) => ProviderStatus::Available,
            Err(_) => ProviderStatus::Unavailable,
        };
        *self.status.write() = status;
    }
}

#[async_trait]
impl AnchorProvider for EthereumProvider {
    fn info(&self) -> ProviderInfo {
        let block_height = self.cached_block.read().map(|(h, _)| h).unwrap_or(0);

        ProviderInfo {
            id: self.id.clone(),
            name: format!("Ethereum {}", self.config.chain.name()),
            chain_id: self.config.chain.moloch_chain_id(),
            status: *self.status.read(),
            capabilities: ProviderCapabilities {
                max_data_size: 128 * 1024, // ~128KB calldata limit
                batch_anchor: true,
                spv_proofs: false, // Ethereum doesn't have SPV in the same sense
                smart_contracts: true,
                confirmation_time_secs: self.config.chain.block_time_secs()
                    * self.config.required_confirmations,
                finality_type: FinalityType::Deterministic, // With PoS
            },
            block_height,
            endpoint: Some(self.config.rpc_url.clone()),
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    async fn status(&self) -> ProviderStatus {
        self.update_status().await;
        *self.status.read()
    }

    async fn submit(&self, commitment: &Commitment) -> moloch_anchor::Result<AnchorTx> {
        self.update_status().await;

        if !matches!(*self.status.read(), ProviderStatus::Available) {
            return Err(moloch_anchor::AnchorError::ProviderUnavailable(
                self.id.clone(),
            ));
        }

        let tx_hash = match self.config.anchor_method {
            AnchorMethod::Calldata => self.send_calldata_anchor(commitment).await,
            AnchorMethod::ContractEvent => {
                // TODO: Implement contract-based anchoring
                Err(EthereumError::Config(
                    "Contract anchoring not yet implemented".into(),
                ))
            }
            AnchorMethod::Blob => Err(EthereumError::Config(
                "Blob anchoring not yet implemented".into(),
            )),
        }
        .map_err(|e| moloch_anchor::AnchorError::SubmissionFailed(e.to_string()))?;

        Ok(AnchorTx::pending(
            Self::format_tx_hash(&tx_hash),
            &self.id,
            self.config.chain.moloch_chain_id(),
        ))
    }

    async fn verify(&self, proof: &AnchorProof) -> moloch_anchor::Result<bool> {
        let tx_hash = Self::parse_tx_hash(&proof.tx_id)
            .map_err(|e| moloch_anchor::AnchorError::VerificationFailed(e.to_string()))?;

        // Get transaction
        let tx = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(|e| moloch_anchor::AnchorError::VerificationFailed(e.to_string()))?
            .ok_or_else(|| {
                moloch_anchor::AnchorError::VerificationFailed("transaction not found".into())
            })?;

        // Parse calldata
        let input = tx.input();
        let (commitment_hash, _chain_hash) = Self::parse_calldata(input)
            .map_err(|e| moloch_anchor::AnchorError::VerificationFailed(e.to_string()))?;

        // Verify commitment hash matches
        let expected_hash = proof.commitment.hash();
        if commitment_hash != expected_hash.as_bytes() {
            return Ok(false);
        }

        // Verify transaction succeeded
        if let Ok(Some(r)) = self.provider.get_transaction_receipt(tx_hash).await {
            return Ok(r.status());
        }

        Ok(true)
    }

    async fn confirmations(&self, tx_id: &TxId) -> moloch_anchor::Result<u64> {
        let tx_hash = Self::parse_tx_hash(tx_id)
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))?;

        self.get_confirmations(&tx_hash)
            .await
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))
    }

    async fn get_proof(&self, tx_id: &TxId) -> moloch_anchor::Result<AnchorProof> {
        let tx_hash = Self::parse_tx_hash(tx_id)
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))?;

        // Get receipt
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))?
            .ok_or_else(|| moloch_anchor::AnchorError::TxNotFound(tx_id.0.clone()))?;

        // Get transaction
        let tx = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))?
            .ok_or_else(|| moloch_anchor::AnchorError::TxNotFound(tx_id.0.clone()))?;

        // Parse commitment from calldata
        let input = tx.input();
        let (commitment_hash, _) = Self::parse_calldata(input)
            .map_err(|e| moloch_anchor::AnchorError::InvalidProof(e.to_string()))?;

        // Create placeholder commitment
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&commitment_hash);
        let commitment = Commitment::new(
            self.config.chain.moloch_chain_id(),
            Hash::from_bytes(hash_bytes),
            0,
        );

        // Get confirmations
        let block_number = receipt.block_number.unwrap_or(0);
        let current_block = self.get_block_number_cached().await.unwrap_or(0);
        let confirmations = if current_block >= block_number {
            current_block - block_number + 1
        } else {
            0
        };

        // Determine status
        let status = if !receipt.status() {
            AnchorStatus::Failed
        } else if confirmations >= self.config.required_confirmations {
            if confirmations >= 100 {
                AnchorStatus::Finalized
            } else {
                AnchorStatus::Confirmed(confirmations)
            }
        } else if confirmations > 0 {
            AnchorStatus::Confirmed(confirmations)
        } else {
            AnchorStatus::Pending
        };

        let block_hash = receipt
            .block_hash
            .map(|h| format!("0x{}", hex::encode(h.as_slice())))
            .unwrap_or_default();

        Ok(AnchorProof::new(
            commitment,
            &self.id,
            self.config.chain.moloch_chain_id(),
            tx_id.clone(),
            block_number,
            block_hash,
        )
        .with_status(status))
    }

    async fn estimate_cost(&self, _commitment: &Commitment) -> moloch_anchor::Result<AnchorCost> {
        // Estimate gas
        let gas_estimate: u64 = if self.config.gas_limit > 0 {
            self.config.gas_limit
        } else {
            30_000 // Typical calldata transaction
        };

        // Get gas price
        let gas_price: u128 = if self.config.gas_price_gwei > 0 {
            self.config.gas_price_gwei as u128 * 1_000_000_000u128
        } else {
            self.provider
                .get_gas_price()
                .await
                .map_err(|e| moloch_anchor::AnchorError::Internal(e.to_string()))?
        };

        // Calculate cost in ETH
        let cost_wei = gas_estimate as u128 * gas_price;
        let cost_eth = cost_wei as f64 / 1e18;

        Ok(AnchorCost::new(cost_eth, "ETH")
            .with_time(self.config.chain.block_time_secs() * self.config.required_confirmations))
    }

    async fn block_height(&self) -> moloch_anchor::Result<u64> {
        self.get_block_number_cached()
            .await
            .map_err(|e| moloch_anchor::AnchorError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calldata_roundtrip() {
        let commitment = Commitment::new("test-chain", Hash::ZERO, 100);
        let calldata = EthereumProvider::build_calldata(&commitment);

        assert_eq!(calldata.len(), ANCHOR_DATA_SIZE);
        assert_eq!(&calldata[0..4], &MOLOCH_SELECTOR);

        let (hash, _chain) = EthereumProvider::parse_calldata(&calldata).unwrap();
        assert_eq!(hash, commitment.hash().as_bytes());
    }

    #[test]
    fn test_tx_hash_format() {
        let hash_str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let tx_id = TxId::new(hash_str);

        let parsed = EthereumProvider::parse_tx_hash(&tx_id).unwrap();
        let formatted = EthereumProvider::format_tx_hash(&parsed);

        assert_eq!(formatted.0.to_lowercase(), hash_str.to_lowercase());
    }
}
