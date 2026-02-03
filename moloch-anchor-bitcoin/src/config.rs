//! Bitcoin provider configuration.

use serde::{Deserialize, Serialize};

/// Bitcoin network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Network {
    /// Bitcoin mainnet.
    #[default]
    Mainnet,
    /// Bitcoin testnet.
    Testnet,
    /// Bitcoin signet.
    Signet,
    /// Bitcoin regtest (local development).
    Regtest,
}

impl Network {
    /// Get the network name.
    pub fn name(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }

    /// Get the chain ID for this network.
    pub fn chain_id(&self) -> &'static str {
        match self {
            Network::Mainnet => "bitcoin-mainnet",
            Network::Testnet => "bitcoin-testnet",
            Network::Signet => "bitcoin-signet",
            Network::Regtest => "bitcoin-regtest",
        }
    }

    /// Convert to bitcoin crate network type.
    pub fn to_bitcoin_network(&self) -> bitcoin::Network {
        match self {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Signet => bitcoin::Network::Signet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }
}

/// Configuration for the Bitcoin provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinConfig {
    /// RPC endpoint URL.
    pub rpc_url: String,

    /// RPC username (optional).
    pub rpc_user: Option<String>,

    /// RPC password (optional).
    pub rpc_password: Option<String>,

    /// Bitcoin network.
    pub network: Network,

    /// Wallet name (optional, for multi-wallet nodes).
    pub wallet: Option<String>,

    /// Required confirmations for finality.
    pub required_confirmations: u64,

    /// Fee rate in sat/vB (0 = auto-estimate).
    pub fee_rate_sat_vb: u64,

    /// Target confirmation blocks for fee estimation.
    pub fee_target_blocks: u16,

    /// Connection timeout in seconds.
    pub timeout_secs: u64,

    /// Maximum retries for RPC calls.
    pub max_retries: u32,

    /// Provider ID.
    pub provider_id: String,
}

impl BitcoinConfig {
    /// Create a new configuration.
    pub fn new(rpc_url: impl Into<String>, network: Network) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            rpc_user: None,
            rpc_password: None,
            network,
            wallet: None,
            required_confirmations: super::DEFAULT_CONFIRMATIONS,
            fee_rate_sat_vb: 0,
            fee_target_blocks: 6,
            timeout_secs: 30,
            max_retries: 3,
            provider_id: format!("bitcoin-{}", network.name()),
        }
    }

    /// Create configuration for mainnet.
    pub fn mainnet(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, Network::Mainnet)
    }

    /// Create configuration for testnet.
    pub fn testnet(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, Network::Testnet)
    }

    /// Create configuration for regtest.
    pub fn regtest(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, Network::Regtest)
    }

    /// Set RPC authentication.
    pub fn with_auth(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.rpc_user = Some(user.into());
        self.rpc_password = Some(password.into());
        self
    }

    /// Set wallet name.
    pub fn with_wallet(mut self, wallet: impl Into<String>) -> Self {
        self.wallet = Some(wallet.into());
        self
    }

    /// Set required confirmations.
    pub fn with_confirmations(mut self, confirmations: u64) -> Self {
        self.required_confirmations = confirmations;
        self
    }

    /// Set fixed fee rate in sat/vB.
    pub fn with_fee_rate(mut self, sat_per_vb: u64) -> Self {
        self.fee_rate_sat_vb = sat_per_vb;
        self
    }

    /// Set fee estimation target blocks.
    pub fn with_fee_target(mut self, blocks: u16) -> Self {
        self.fee_target_blocks = blocks;
        self
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Set provider ID.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.provider_id = id.into();
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), super::BitcoinError> {
        if self.rpc_url.is_empty() {
            return Err(super::BitcoinError::Config("RPC URL is required".into()));
        }

        if self.required_confirmations == 0 {
            return Err(super::BitcoinError::Config(
                "Required confirmations must be at least 1".into(),
            ));
        }

        Ok(())
    }
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self::new("http://127.0.0.1:8332", Network::Mainnet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = BitcoinConfig::testnet("http://localhost:18332")
            .with_auth("user", "pass")
            .with_wallet("moloch")
            .with_confirmations(3)
            .with_fee_rate(10);

        assert_eq!(config.network, Network::Testnet);
        assert_eq!(config.rpc_user, Some("user".to_string()));
        assert_eq!(config.required_confirmations, 3);
        assert_eq!(config.fee_rate_sat_vb, 10);
    }

    #[test]
    fn test_network_chain_id() {
        assert_eq!(Network::Mainnet.chain_id(), "bitcoin-mainnet");
        assert_eq!(Network::Testnet.chain_id(), "bitcoin-testnet");
    }
}
