//! Bitcoin OP_RETURN Anchoring for Moloch.
//!
//! This crate provides a Bitcoin implementation of the `AnchorProvider` trait,
//! allowing Moloch chain state to be anchored to Bitcoin using OP_RETURN transactions.
//!
//! # How It Works
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    BITCOIN ANCHORING FLOW                            │
//! │                                                                      │
//! │  1. Commitment Created                                               │
//! │     └─ MMR root + height + metadata → 32-byte hash                  │
//! │                                                                      │
//! │  2. OP_RETURN Transaction                                            │
//! │     └─ [MOLOCH_MAGIC] [commitment_hash] [chain_id_hash]             │
//! │        └─ 4 bytes      32 bytes          8 bytes = 44 bytes total   │
//! │                                                                      │
//! │  3. Broadcast & Confirm                                              │
//! │     └─ Wait for 6 confirmations (≈60 minutes)                       │
//! │                                                                      │
//! │  4. Generate SPV Proof                                               │
//! │     └─ Block header + merkle path → verifiable anywhere             │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use moloch_anchor_bitcoin::{BitcoinProvider, BitcoinConfig, Network};
//!
//! let config = BitcoinConfig::new("http://localhost:8332", Network::Testnet)
//!     .with_auth("user", "password");
//!
//! let provider = BitcoinProvider::new(config)?;
//!
//! // Anchor a commitment
//! let tx = provider.submit(&commitment).await?;
//!
//! // Wait for confirmations
//! let proof = provider.wait_for_confirmations(&tx.tx_id, 6).await?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod config;
mod error;
mod provider;
mod rpc;
mod tx;

pub use config::{BitcoinConfig, Network};
pub use error::{BitcoinError, Result};
pub use provider::BitcoinProvider;

/// Magic bytes identifying Moloch anchors in OP_RETURN.
pub const MOLOCH_MAGIC: &[u8] = b"MLCH";

/// Maximum OP_RETURN data size (80 bytes standard).
pub const MAX_OP_RETURN_SIZE: usize = 80;

/// Moloch anchor data size: magic(4) + commitment(32) + chain_id(8) = 44 bytes.
pub const ANCHOR_DATA_SIZE: usize = 44;

/// Default number of confirmations for finality.
pub const DEFAULT_CONFIRMATIONS: u64 = 6;
