//! Ethereum Anchoring for Moloch.
//!
//! This crate provides an Ethereum implementation of the `AnchorProvider` trait,
//! allowing Moloch chain state to be anchored to Ethereum and EVM-compatible chains.
//!
//! # Anchoring Methods
//!
//! This provider supports multiple anchoring methods:
//!
//! 1. **Calldata Anchoring** (Default)
//!    - Embeds commitment in transaction input data
//!    - Most cost-effective for pure anchoring
//!    - Data: `[MOLOCH_SELECTOR (4)] [commitment_hash (32)] [chain_id_hash (8)]`
//!
//! 2. **Contract Event Anchoring**
//!    - Emits events from a dedicated anchor contract
//!    - Better for on-chain verification
//!    - Supports batch anchoring
//!
//! # Example
//!
//! ```ignore
//! use moloch_anchor_ethereum::{EthereumProvider, EthereumConfig, Chain};
//!
//! let config = EthereumConfig::new("https://eth.llamarpc.com", Chain::Mainnet)
//!     .with_private_key("0x...");
//!
//! let provider = EthereumProvider::new(config).await?;
//!
//! // Anchor a commitment
//! let tx = provider.submit(&commitment).await?;
//!
//! // Wait for confirmations
//! let proof = provider.wait_for_confirmations(&tx.tx_id, 12).await?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod config;
mod error;
mod provider;

pub use config::{AnchorMethod, Chain, EthereumConfig};
pub use error::{EthereumError, Result};
pub use provider::EthereumProvider;

/// Function selector for Moloch anchor calls (first 4 bytes of keccak256("anchor(bytes32,bytes8)")).
pub const MOLOCH_SELECTOR: [u8; 4] = [0x4d, 0x4f, 0x4c, 0x43]; // "MOLC" for simplicity

/// Default number of confirmations for finality.
pub const DEFAULT_CONFIRMATIONS: u64 = 12;

/// Anchor data size: selector(4) + commitment(32) + chain_id(8) = 44 bytes.
pub const ANCHOR_DATA_SIZE: usize = 44;
