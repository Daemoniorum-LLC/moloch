//! Networking layer for Moloch audit chain.
//!
//! This crate provides peer-to-peer communication for the Moloch chain:
//! - Transport layer with TLS 1.3
//! - Protocol messages for gossip and sync
//! - Peer discovery and management
//! - Chain synchronization protocols
//!
//! # Architecture
//!
//! The networking layer is organized into four main components:
//!
//! 1. **Transport** (`transport.rs`) - TCP connections with TLS, connection pooling
//! 2. **Protocol** (`protocol.rs`) - Message types and serialization
//! 3. **Discovery** (`discovery.rs`) - Peer discovery and scoring
//! 4. **Sync** (`sync.rs`) - Chain synchronization protocols
//!
//! # Example
//!
//! ```ignore
//! use moloch_net::{NetworkConfig, NetworkNode};
//!
//! // Create node configuration
//! let config = NetworkConfig::builder()
//!     .listen_addr("0.0.0.0:9000")
//!     .chain_id("moloch-testnet")
//!     .build();
//!
//! // Start the network node
//! let node = NetworkNode::new(config, storage).await?;
//! node.connect_to_peers(&["peer1:9000", "peer2:9000"]).await?;
//! ```

pub mod discovery;
pub mod protocol;
pub mod sync;
pub mod transport;

pub use discovery::{PeerDiscovery, PeerInfo, PeerScore, PeerState};
pub use protocol::{Message, MessageCodec, PeerId, ProtocolVersion};
pub use sync::{SyncManager, SyncMode, SyncStatus};
pub use transport::{
    Connection, ConnectionPool, NetworkConfig, TlsConfig, Transport, TransportError,
};
