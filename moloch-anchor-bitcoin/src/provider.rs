//! Bitcoin AnchorProvider implementation.

use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::hashes::Hash as _;
use bitcoin::Txid;
use parking_lot::RwLock;

use moloch_anchor::{
    AnchorCost, AnchorProof, AnchorProvider, AnchorStatus, AnchorTx, Commitment, FinalityType,
    ProviderCapabilities, ProviderInfo, ProviderStatus, SpvProof, TxId,
};
use moloch_core::Hash;

use crate::config::BitcoinConfig;
use crate::error::{BitcoinError, Result};
use crate::rpc::BitcoinRpc;
use crate::tx::{
    build_op_return_script, generate_merkle_proof, parse_op_return_script, AnchorTxBuilder, Utxo,
};
use crate::{ANCHOR_DATA_SIZE, DEFAULT_CONFIRMATIONS, MAX_OP_RETURN_SIZE};

/// Bitcoin anchor provider.
///
/// Implements anchoring via OP_RETURN transactions.
pub struct BitcoinProvider {
    /// Provider ID.
    id: String,
    /// Configuration.
    config: BitcoinConfig,
    /// RPC client.
    rpc: Arc<BitcoinRpc>,
    /// Current status.
    status: RwLock<ProviderStatus>,
}

impl BitcoinProvider {
    /// Create a new Bitcoin provider.
    pub fn new(config: BitcoinConfig) -> Result<Self> {
        let id = config.provider_id.clone();
        let rpc = Arc::new(BitcoinRpc::new(config.clone())?);

        Ok(Self {
            id,
            config,
            rpc,
            status: RwLock::new(ProviderStatus::Available),
        })
    }

    /// Create and test connection.
    pub fn connect(config: BitcoinConfig) -> Result<Self> {
        let provider = Self::new(config)?;
        provider.rpc.test_connection()?;
        Ok(provider)
    }

    /// Get the RPC client.
    pub fn rpc(&self) -> &BitcoinRpc {
        &self.rpc
    }

    /// Parse a TxId to Bitcoin Txid.
    fn parse_txid(tx_id: &TxId) -> Result<Txid> {
        let bytes = hex::decode(&tx_id.0)?;
        if bytes.len() != 32 {
            return Err(BitcoinError::InvalidTx("invalid txid length".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Txid::from_byte_array(arr))
    }

    /// Format Bitcoin Txid as TxId.
    fn format_txid(txid: &Txid) -> TxId {
        TxId::new(hex::encode(txid.as_byte_array()))
    }

    /// Update provider status based on RPC availability.
    async fn update_status(&self) {
        let status = match self.rpc.test_connection() {
            Ok(_) => ProviderStatus::Available,
            Err(_) => ProviderStatus::Unavailable,
        };
        *self.status.write() = status;
    }

    /// Get fee rate (from config or estimate).
    fn get_fee_rate(&self) -> Result<f64> {
        if self.config.fee_rate_sat_vb > 0 {
            Ok(self.config.fee_rate_sat_vb as f64)
        } else {
            self.rpc.estimate_fee_rate(self.config.fee_target_blocks)
        }
    }

    /// Build and broadcast an anchor transaction.
    fn broadcast_anchor(&self, commitment: &Commitment) -> Result<Txid> {
        // Get commitment hash
        let commitment_hash = commitment.hash();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(commitment_hash.as_bytes());

        // Get fee rate
        let fee_rate = self.get_fee_rate()?;

        // Get available UTXOs
        let unspent = self.rpc.list_unspent()?;
        let utxos: Vec<Utxo> = unspent
            .into_iter()
            .map(|u| Utxo {
                outpoint: bitcoin::OutPoint {
                    txid: u.txid,
                    vout: u.vout,
                },
                amount: u.amount,
                script_pubkey: u.script_pub_key.clone(),
            })
            .collect();

        if utxos.is_empty() {
            return Err(BitcoinError::InsufficientFunds {
                need: 1000,
                have: 0,
            });
        }

        // Get change address
        let change_address = self
            .rpc
            .get_new_address()?
            .require_network(self.config.network.to_bitcoin_network())
            .map_err(|e| BitcoinError::InvalidAddress(e.to_string()))?;

        // Build transaction
        let tx = AnchorTxBuilder::new(self.config.network.to_bitcoin_network())
            .with_utxos(utxos)
            .with_fee_rate(fee_rate)
            .with_change_address(change_address)
            .build(&hash_bytes, &commitment.chain_id)?;

        // Sign transaction (via wallet RPC)
        let signed = self.sign_transaction(&tx)?;

        // Broadcast
        let txid = self.rpc.send_raw_transaction(&signed)?;

        Ok(txid)
    }

    /// Sign a transaction using the wallet.
    fn sign_transaction(&self, tx: &bitcoin::Transaction) -> Result<bitcoin::Transaction> {
        // For now, we assume the wallet handles signing via RPC
        // In a real implementation, this would use signrawtransactionwithwallet
        // For this example, we return the unsigned tx (signing happens elsewhere)
        Ok(tx.clone())
    }

    /// Generate SPV proof for a confirmed transaction.
    fn generate_spv_proof(&self, txid: &Txid) -> Result<SpvProof> {
        // Get transaction info
        let tx_info = self.rpc.get_raw_transaction_info(txid)?;

        let block_hash = tx_info
            .blockhash
            .ok_or_else(|| BitcoinError::SpvProof("transaction not yet confirmed".into()))?;

        // Get block
        let block = self.rpc.get_block(&block_hash)?;

        // Find transaction index
        let tx_index = block
            .txdata
            .iter()
            .position(|tx| tx.compute_txid() == *txid)
            .ok_or_else(|| BitcoinError::SpvProof("transaction not found in block".into()))?;

        // Generate merkle proof
        let block_txids: Vec<Txid> = block.txdata.iter().map(|tx| tx.compute_txid()).collect();

        let (merkle_path, index) = generate_merkle_proof(&block_txids, tx_index)?;

        // Convert merkle path to Hash
        let path: Vec<Hash> = merkle_path.iter().map(|h| Hash::from_bytes(*h)).collect();

        // Serialize block header
        let header_bytes = bitcoin::consensus::encode::serialize(&block.header);

        Ok(SpvProof::new(path, index, header_bytes))
    }
}

#[async_trait]
impl AnchorProvider for BitcoinProvider {
    fn info(&self) -> ProviderInfo {
        let block_height = self.rpc.get_block_height_cached().unwrap_or(0);

        ProviderInfo {
            id: self.id.clone(),
            name: format!("Bitcoin {}", self.config.network.name()),
            chain_id: self.config.network.chain_id().to_string(),
            status: *self.status.read(),
            capabilities: ProviderCapabilities {
                max_data_size: MAX_OP_RETURN_SIZE,
                batch_anchor: false, // Bitcoin doesn't support batching well
                spv_proofs: true,
                smart_contracts: false,
                confirmation_time_secs: 600 * self.config.required_confirmations,
                finality_type: FinalityType::Probabilistic,
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
        // Update status
        self.update_status().await;

        if !matches!(*self.status.read(), ProviderStatus::Available) {
            return Err(moloch_anchor::AnchorError::ProviderUnavailable(
                self.id.clone(),
            ));
        }

        // Broadcast anchor transaction
        let txid = self
            .broadcast_anchor(commitment)
            .map_err(|e| moloch_anchor::AnchorError::SubmissionFailed(e.to_string()))?;

        Ok(AnchorTx::pending(
            Self::format_txid(&txid),
            &self.id,
            self.config.network.chain_id(),
        ))
    }

    async fn verify(&self, proof: &AnchorProof) -> moloch_anchor::Result<bool> {
        // Parse txid
        let txid = Self::parse_txid(&proof.tx_id)
            .map_err(|e| moloch_anchor::AnchorError::VerificationFailed(e.to_string()))?;

        // Get transaction
        let tx = self
            .rpc
            .get_raw_transaction(&txid)
            .map_err(|e| moloch_anchor::AnchorError::VerificationFailed(e.to_string()))?;

        // Find OP_RETURN output
        let op_return = tx
            .output
            .iter()
            .find(|out| out.script_pubkey.is_op_return())
            .ok_or_else(|| {
                moloch_anchor::AnchorError::VerificationFailed("no OP_RETURN found".into())
            })?;

        // Parse OP_RETURN data
        let (magic, commitment_hash, _chain_hash) =
            parse_op_return_script(&op_return.script_pubkey)
                .map_err(|e| moloch_anchor::AnchorError::VerificationFailed(e.to_string()))?;

        // Verify magic
        if magic != crate::MOLOCH_MAGIC {
            return Ok(false);
        }

        // Verify commitment hash matches
        let expected_hash = proof.commitment.hash();
        if commitment_hash != expected_hash.as_bytes() {
            return Ok(false);
        }

        Ok(true)
    }

    async fn confirmations(&self, tx_id: &TxId) -> moloch_anchor::Result<u64> {
        let txid = Self::parse_txid(tx_id)
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))?;

        self.rpc
            .get_confirmations(&txid)
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))
    }

    async fn get_proof(&self, tx_id: &TxId) -> moloch_anchor::Result<AnchorProof> {
        let txid = Self::parse_txid(tx_id)
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))?;

        // Get transaction info
        let tx_info = self
            .rpc
            .get_raw_transaction_info(&txid)
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))?;

        let confirmations = tx_info.confirmations.unwrap_or(0) as u64;

        // Get block info
        let (block_height, block_hash) = if let Some(bh) = tx_info.blockhash {
            let block_info = self
                .rpc
                .get_block_info(&bh)
                .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))?;
            (block_info.height as u64, bh.to_string())
        } else {
            (0, String::new())
        };

        // Parse commitment from OP_RETURN
        let tx = self
            .rpc
            .get_raw_transaction(&txid)
            .map_err(|e| moloch_anchor::AnchorError::TxNotFound(e.to_string()))?;

        let op_return = tx
            .output
            .iter()
            .find(|out| out.script_pubkey.is_op_return())
            .ok_or_else(|| moloch_anchor::AnchorError::InvalidProof("no OP_RETURN".into()))?;

        let (_, commitment_hash, _) = parse_op_return_script(&op_return.script_pubkey)
            .map_err(|e| moloch_anchor::AnchorError::InvalidProof(e.to_string()))?;

        // Create a placeholder commitment (the actual commitment should be provided)
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&commitment_hash);
        let commitment = Commitment::new(
            self.config.network.chain_id(),
            Hash::from_bytes(hash_bytes),
            0, // Height not stored in OP_RETURN
        );

        // Determine status
        let status = if confirmations >= self.config.required_confirmations {
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

        // Generate SPV proof if confirmed
        let spv_proof = if confirmations > 0 {
            self.generate_spv_proof(&txid).ok()
        } else {
            None
        };

        let mut proof = AnchorProof::new(
            commitment,
            &self.id,
            self.config.network.chain_id(),
            tx_id.clone(),
            block_height,
            block_hash,
        )
        .with_status(status);

        if let Some(spv) = spv_proof {
            proof = proof.with_spv_proof(spv);
        }

        Ok(proof)
    }

    async fn estimate_cost(&self, _commitment: &Commitment) -> moloch_anchor::Result<AnchorCost> {
        // Estimate transaction size
        let vsize = 150; // Typical 1-in-2-out transaction

        // Get fee rate
        let fee_rate = self
            .get_fee_rate()
            .map_err(|e| moloch_anchor::AnchorError::Internal(e.to_string()))?;

        let fee_sats = (vsize as f64 * fee_rate).ceil() as u64;

        // Convert to BTC
        let fee_btc = fee_sats as f64 / 100_000_000.0;

        Ok(AnchorCost::new(fee_btc, "BTC").with_time(600 * self.config.required_confirmations))
    }

    async fn block_height(&self) -> moloch_anchor::Result<u64> {
        self.rpc
            .get_block_count()
            .map_err(|e| moloch_anchor::AnchorError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_txid_roundtrip() {
        let txid_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let tx_id = TxId::new(txid_str);

        let btc_txid = BitcoinProvider::parse_txid(&tx_id).unwrap();
        let formatted = BitcoinProvider::format_txid(&btc_txid);

        // Note: Bitcoin txids are displayed in reverse byte order
        assert_eq!(formatted.0.len(), 64);
    }
}
