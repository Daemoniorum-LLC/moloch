//! Ethereum provider configuration.

use serde::{Deserialize, Serialize};

/// Ethereum chain/network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Chain {
    /// Ethereum mainnet (chain ID 1).
    Mainnet,
    /// Sepolia testnet (chain ID 11155111).
    Sepolia,
    /// Holesky testnet (chain ID 17000).
    Holesky,
    /// Arbitrum One (chain ID 42161).
    Arbitrum,
    /// Optimism (chain ID 10).
    Optimism,
    /// Base (chain ID 8453).
    Base,
    /// Polygon (chain ID 137).
    Polygon,
    /// Custom chain with specified ID.
    Custom(u64),
}

impl Chain {
    /// Get the chain ID.
    pub fn chain_id(&self) -> u64 {
        match self {
            Chain::Mainnet => 1,
            Chain::Sepolia => 11155111,
            Chain::Holesky => 17000,
            Chain::Arbitrum => 42161,
            Chain::Optimism => 10,
            Chain::Base => 8453,
            Chain::Polygon => 137,
            Chain::Custom(id) => *id,
        }
    }

    /// Get the chain name.
    pub fn name(&self) -> &'static str {
        match self {
            Chain::Mainnet => "mainnet",
            Chain::Sepolia => "sepolia",
            Chain::Holesky => "holesky",
            Chain::Arbitrum => "arbitrum",
            Chain::Optimism => "optimism",
            Chain::Base => "base",
            Chain::Polygon => "polygon",
            Chain::Custom(_) => "custom",
        }
    }

    /// Get the Moloch chain identifier.
    pub fn moloch_chain_id(&self) -> String {
        match self {
            Chain::Custom(id) => format!("ethereum-{}", id),
            _ => format!("ethereum-{}", self.name()),
        }
    }

    /// Average block time in seconds.
    pub fn block_time_secs(&self) -> u64 {
        match self {
            Chain::Mainnet | Chain::Sepolia | Chain::Holesky => 12,
            Chain::Arbitrum => 1,
            Chain::Optimism | Chain::Base => 2,
            Chain::Polygon => 2,
            Chain::Custom(_) => 12,
        }
    }

    /// From chain ID.
    pub fn from_chain_id(id: u64) -> Self {
        match id {
            1 => Chain::Mainnet,
            11155111 => Chain::Sepolia,
            17000 => Chain::Holesky,
            42161 => Chain::Arbitrum,
            10 => Chain::Optimism,
            8453 => Chain::Base,
            137 => Chain::Polygon,
            _ => Chain::Custom(id),
        }
    }
}

impl Default for Chain {
    fn default() -> Self {
        Chain::Mainnet
    }
}

/// Method for anchoring data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AnchorMethod {
    /// Embed data in transaction calldata (cheapest).
    #[default]
    Calldata,
    /// Emit events from anchor contract.
    ContractEvent,
    /// Store in EIP-4844 blob (future).
    Blob,
}

/// Configuration for the Ethereum provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumConfig {
    /// RPC endpoint URL.
    pub rpc_url: String,

    /// Chain/network.
    pub chain: Chain,

    /// Private key for signing (hex, with or without 0x prefix).
    pub private_key: Option<String>,

    /// Anchor contract address (for ContractEvent method).
    pub anchor_contract: Option<String>,

    /// Anchoring method.
    pub anchor_method: AnchorMethod,

    /// Required confirmations for finality.
    pub required_confirmations: u64,

    /// Gas price in gwei (0 = auto-estimate).
    pub gas_price_gwei: u64,

    /// Max priority fee in gwei (for EIP-1559).
    pub max_priority_fee_gwei: u64,

    /// Gas limit (0 = auto-estimate).
    pub gas_limit: u64,

    /// Connection timeout in seconds.
    pub timeout_secs: u64,

    /// Maximum retries for RPC calls.
    pub max_retries: u32,

    /// Provider ID.
    pub provider_id: String,
}

impl EthereumConfig {
    /// Create a new configuration.
    pub fn new(rpc_url: impl Into<String>, chain: Chain) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            chain,
            private_key: None,
            anchor_contract: None,
            anchor_method: AnchorMethod::Calldata,
            required_confirmations: super::DEFAULT_CONFIRMATIONS,
            gas_price_gwei: 0,
            max_priority_fee_gwei: 2,
            gas_limit: 0,
            timeout_secs: 30,
            max_retries: 3,
            provider_id: format!("ethereum-{}", chain.name()),
        }
    }

    /// Create configuration for mainnet.
    pub fn mainnet(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, Chain::Mainnet)
    }

    /// Create configuration for Sepolia testnet.
    pub fn sepolia(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, Chain::Sepolia)
    }

    /// Create configuration for Arbitrum.
    pub fn arbitrum(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, Chain::Arbitrum).with_confirmations(1) // Arbitrum has instant finality via L1
    }

    /// Create configuration for Base.
    pub fn base(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, Chain::Base).with_confirmations(1)
    }

    /// Set private key for signing.
    pub fn with_private_key(mut self, key: impl Into<String>) -> Self {
        self.private_key = Some(key.into());
        self
    }

    /// Set anchor contract address.
    pub fn with_contract(mut self, address: impl Into<String>) -> Self {
        self.anchor_contract = Some(address.into());
        self.anchor_method = AnchorMethod::ContractEvent;
        self
    }

    /// Set anchor method.
    pub fn with_method(mut self, method: AnchorMethod) -> Self {
        self.anchor_method = method;
        self
    }

    /// Set required confirmations.
    pub fn with_confirmations(mut self, confirmations: u64) -> Self {
        self.required_confirmations = confirmations;
        self
    }

    /// Set fixed gas price in gwei.
    pub fn with_gas_price(mut self, gwei: u64) -> Self {
        self.gas_price_gwei = gwei;
        self
    }

    /// Set max priority fee in gwei.
    pub fn with_priority_fee(mut self, gwei: u64) -> Self {
        self.max_priority_fee_gwei = gwei;
        self
    }

    /// Set gas limit.
    pub fn with_gas_limit(mut self, limit: u64) -> Self {
        self.gas_limit = limit;
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
    pub fn validate(&self) -> Result<(), super::EthereumError> {
        if self.rpc_url.is_empty() {
            return Err(super::EthereumError::Config("RPC URL is required".into()));
        }

        if self.required_confirmations == 0 {
            return Err(super::EthereumError::Config(
                "Required confirmations must be at least 1".into(),
            ));
        }

        if self.anchor_method == AnchorMethod::ContractEvent && self.anchor_contract.is_none() {
            return Err(super::EthereumError::Config(
                "Anchor contract required for ContractEvent method".into(),
            ));
        }

        Ok(())
    }
}

impl Default for EthereumConfig {
    fn default() -> Self {
        Self::new("http://127.0.0.1:8545", Chain::Mainnet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_ids() {
        assert_eq!(Chain::Mainnet.chain_id(), 1);
        assert_eq!(Chain::Sepolia.chain_id(), 11155111);
        assert_eq!(Chain::Arbitrum.chain_id(), 42161);
    }

    #[test]
    fn test_config_builder() {
        let config = EthereumConfig::sepolia("https://sepolia.example.com")
            .with_private_key("0xabc123")
            .with_confirmations(6)
            .with_priority_fee(3);

        assert_eq!(config.chain, Chain::Sepolia);
        assert!(config.private_key.is_some());
        assert_eq!(config.required_confirmations, 6);
    }

    #[test]
    fn test_from_chain_id() {
        assert_eq!(Chain::from_chain_id(1), Chain::Mainnet);
        assert_eq!(Chain::from_chain_id(42161), Chain::Arbitrum);
        assert_eq!(Chain::from_chain_id(999), Chain::Custom(999));
    }
}
