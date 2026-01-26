//! Bitcoin RPC client wrapper.


use bitcoin::consensus::encode;
use bitcoin::{Block, BlockHash, Transaction, Txid};
use bitcoincore_rpc::json::{
    EstimateMode, GetBlockResult, GetRawTransactionResult, GetTransactionResult,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use parking_lot::RwLock;

use crate::config::BitcoinConfig;
use crate::error::{BitcoinError, Result};

/// Wrapper around Bitcoin Core RPC client.
pub struct BitcoinRpc {
    /// RPC client.
    client: Client,
    /// Configuration.
    config: BitcoinConfig,
    /// Cached block height.
    cached_height: RwLock<Option<(u64, i64)>>, // (height, timestamp)
}

impl BitcoinRpc {
    /// Create a new RPC client.
    pub fn new(config: BitcoinConfig) -> Result<Self> {
        config.validate()?;

        let auth = match (&config.rpc_user, &config.rpc_password) {
            (Some(user), Some(pass)) => Auth::UserPass(user.clone(), pass.clone()),
            _ => Auth::None,
        };

        let url = if let Some(ref wallet) = config.wallet {
            format!("{}/wallet/{}", config.rpc_url, wallet)
        } else {
            config.rpc_url.clone()
        };

        let client =
            Client::new(&url, auth).map_err(|e| BitcoinError::RpcConnection(e.to_string()))?;

        Ok(Self {
            client,
            config,
            cached_height: RwLock::new(None),
        })
    }

    /// Get the configuration.
    pub fn config(&self) -> &BitcoinConfig {
        &self.config
    }

    /// Get current block count.
    pub fn get_block_count(&self) -> Result<u64> {
        Ok(self.client.get_block_count()?)
    }

    /// Get current block height with caching.
    pub fn get_block_height_cached(&self) -> Result<u64> {
        let now = chrono::Utc::now().timestamp();

        // Check cache (valid for 10 seconds)
        if let Some((height, ts)) = *self.cached_height.read() {
            if now - ts < 10 {
                return Ok(height);
            }
        }

        // Fetch fresh value
        let height = self.get_block_count()?;
        *self.cached_height.write() = Some((height, now));
        Ok(height)
    }

    /// Get best block hash.
    pub fn get_best_block_hash(&self) -> Result<BlockHash> {
        Ok(self.client.get_best_block_hash()?)
    }

    /// Get block by hash.
    pub fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        Ok(self.client.get_block(hash)?)
    }

    /// Get block info by hash.
    pub fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult> {
        Ok(self.client.get_block_info(hash)?)
    }

    /// Get block hash by height.
    pub fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        Ok(self.client.get_block_hash(height)?)
    }

    /// Get raw transaction.
    pub fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction> {
        self.client
            .get_raw_transaction(txid, None)
            .map_err(|e| BitcoinError::TxNotFound(e.to_string()))
    }

    /// Get raw transaction with block info.
    pub fn get_raw_transaction_info(&self, txid: &Txid) -> Result<GetRawTransactionResult> {
        self.client
            .get_raw_transaction_info(txid, None)
            .map_err(|e| BitcoinError::TxNotFound(e.to_string()))
    }

    /// Get wallet transaction.
    pub fn get_transaction(&self, txid: &Txid) -> Result<GetTransactionResult> {
        self.client
            .get_transaction(txid, None)
            .map_err(|e| BitcoinError::TxNotFound(e.to_string()))
    }

    /// Broadcast a raw transaction.
    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid> {
        let hex = encode::serialize_hex(tx);
        self.client
            .send_raw_transaction(hex)
            .map_err(|e| BitcoinError::Broadcast(e.to_string()))
    }

    /// Estimate fee rate in sat/vB.
    pub fn estimate_fee_rate(&self, target_blocks: u16) -> Result<f64> {
        let estimate = self
            .client
            .estimate_smart_fee(target_blocks, Some(EstimateMode::Economical))
            .map_err(|e| BitcoinError::FeeEstimation(e.to_string()))?;

        if let Some(rate) = estimate.fee_rate {
            // Convert from BTC/kvB to sat/vB
            let btc_per_kvb = rate.to_btc();
            let sat_per_vb = btc_per_kvb * 100_000.0; // BTC/kvB * 100_000 = sat/vB
            Ok(sat_per_vb)
        } else {
            // Fallback to a reasonable default
            Ok(10.0)
        }
    }

    /// Get unspent outputs.
    pub fn list_unspent(&self) -> Result<Vec<bitcoincore_rpc::json::ListUnspentResultEntry>> {
        Ok(self.client.list_unspent(Some(1), None, None, None, None)?)
    }

    /// Generate new address.
    pub fn get_new_address(&self) -> Result<bitcoin::Address<bitcoin::address::NetworkUnchecked>> {
        Ok(self.client.get_new_address(None, None)?)
    }

    /// Get confirmations for a transaction.
    pub fn get_confirmations(&self, txid: &Txid) -> Result<u64> {
        match self.get_raw_transaction_info(txid) {
            Ok(info) => Ok(info.confirmations.unwrap_or(0) as u64),
            Err(BitcoinError::TxNotFound(_)) => {
                // Try wallet transaction
                match self.get_transaction(txid) {
                    Ok(info) => Ok(info.info.confirmations as u64),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Get transaction block hash.
    pub fn get_tx_block_hash(&self, txid: &Txid) -> Result<Option<BlockHash>> {
        match self.get_raw_transaction_info(txid) {
            Ok(info) => Ok(info.blockhash),
            Err(BitcoinError::TxNotFound(_)) => match self.get_transaction(txid) {
                Ok(info) => Ok(info.info.blockhash),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    }

    /// Test connection to the node.
    pub fn test_connection(&self) -> Result<()> {
        let info = self.client.get_blockchain_info()?;

        // Verify network matches
        let expected = self.config.network.to_bitcoin_network();
        let actual = info.chain;

        if actual != expected {
            return Err(BitcoinError::NetworkMismatch {
                expected: format!("{:?}", expected),
                got: format!("{:?}", actual),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = BitcoinConfig::regtest("http://localhost:18443");
        assert!(config.validate().is_ok());

        let bad_config = BitcoinConfig::new("", crate::Network::Mainnet);
        assert!(bad_config.validate().is_err());
    }
}
