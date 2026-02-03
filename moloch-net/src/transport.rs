//! Transport layer for Moloch network.
//!
//! Provides TCP connections with TLS 1.3 encryption, connection pooling,
//! and automatic reconnection handling.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::error;

use crate::protocol::{
    generate_message_id, DisconnectReason, HelloAckMessage, HelloMessage, Message, MessageCodec,
    PeerId, ProtocolVersion,
};
#[cfg(test)]
use crate::protocol::{PingMessage, StatusMessage};
use moloch_core::crypto::{PublicKey, SecretKey};

/// Network configuration.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// Chain ID for network separation.
    pub chain_id: String,
    /// Node's secret key for identity.
    pub node_key: SecretKey,
    /// TLS configuration.
    pub tls: TlsConfig,
    /// Maximum number of connections.
    pub max_connections: usize,
    /// Connection timeout.
    pub connection_timeout: Duration,
    /// Handshake timeout.
    pub handshake_timeout: Duration,
    /// Keep-alive interval (ping frequency).
    pub keepalive_interval: Duration,
    /// Maximum time without response before disconnecting.
    pub idle_timeout: Duration,
    /// Reconnection backoff (initial delay).
    pub reconnect_delay: Duration,
    /// Maximum reconnection attempts.
    pub max_reconnect_attempts: usize,
    /// Message codec configuration.
    pub max_message_size: usize,
}

impl NetworkConfig {
    /// Create a new network config builder.
    pub fn builder() -> NetworkConfigBuilder {
        NetworkConfigBuilder::default()
    }

    /// Get the node's public key.
    pub fn node_pubkey(&self) -> PublicKey {
        self.node_key.public_key()
    }

    /// Get the peer ID for this node.
    pub fn peer_id(&self) -> PeerId {
        PeerId::new(self.node_pubkey())
    }
}

/// Builder for NetworkConfig.
#[derive(Debug, Default)]
pub struct NetworkConfigBuilder {
    listen_addr: Option<SocketAddr>,
    chain_id: Option<String>,
    node_key: Option<SecretKey>,
    tls: Option<TlsConfig>,
    max_connections: Option<usize>,
    connection_timeout: Option<Duration>,
    handshake_timeout: Option<Duration>,
    keepalive_interval: Option<Duration>,
    idle_timeout: Option<Duration>,
    reconnect_delay: Option<Duration>,
    max_reconnect_attempts: Option<usize>,
    max_message_size: Option<usize>,
}

impl NetworkConfigBuilder {
    /// Set the listen address.
    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }

    /// Set the listen address from a string.
    pub fn listen_addr_str(mut self, addr: &str) -> Result<Self, std::net::AddrParseError> {
        self.listen_addr = Some(addr.parse()?);
        Ok(self)
    }

    /// Set the chain ID.
    pub fn chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }

    /// Set the node key.
    pub fn node_key(mut self, key: SecretKey) -> Self {
        self.node_key = Some(key);
        self
    }

    /// Set TLS configuration.
    pub fn tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Set maximum connections.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    /// Set connection timeout.
    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = Some(timeout);
        self
    }

    /// Set handshake timeout.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = Some(timeout);
        self
    }

    /// Set keepalive interval.
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive_interval = Some(interval);
        self
    }

    /// Set idle timeout.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Build the config.
    pub fn build(self) -> Result<NetworkConfig, TransportError> {
        let node_key = self.node_key.unwrap_or_else(SecretKey::generate);

        Ok(NetworkConfig {
            listen_addr: self
                .listen_addr
                .ok_or_else(|| TransportError::Config("listen_addr is required".into()))?,
            chain_id: self
                .chain_id
                .ok_or_else(|| TransportError::Config("chain_id is required".into()))?,
            node_key,
            tls: self.tls.unwrap_or_default(),
            max_connections: self.max_connections.unwrap_or(100),
            connection_timeout: self.connection_timeout.unwrap_or(Duration::from_secs(10)),
            handshake_timeout: self.handshake_timeout.unwrap_or(Duration::from_secs(5)),
            keepalive_interval: self.keepalive_interval.unwrap_or(Duration::from_secs(30)),
            idle_timeout: self.idle_timeout.unwrap_or(Duration::from_secs(120)),
            reconnect_delay: self.reconnect_delay.unwrap_or(Duration::from_secs(1)),
            max_reconnect_attempts: self.max_reconnect_attempts.unwrap_or(5),
            max_message_size: self
                .max_message_size
                .unwrap_or(MessageCodec::DEFAULT_MAX_SIZE),
        })
    }
}

/// TLS configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Enable TLS.
    pub enabled: bool,
    /// Certificate in DER format.
    pub cert: Option<Vec<u8>>,
    /// Private key in PKCS#8 DER format.
    pub key: Option<Vec<u8>>,
    /// Skip certificate verification (for testing only!).
    pub skip_verify: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert: None,
            key: None,
            skip_verify: false,
        }
    }
}

impl TlsConfig {
    /// Create a self-signed certificate for testing.
    pub fn generate_self_signed(common_name: &str) -> Result<Self, TransportError> {
        use rcgen::{generate_simple_self_signed, CertifiedKey};

        let subject_alt_names = vec![common_name.to_string()];
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)
            .map_err(|e| {
                TransportError::Tls(format!("failed to generate self-signed cert: {}", e))
            })?;

        Ok(Self {
            enabled: true,
            cert: Some(cert.der().to_vec()),
            key: Some(key_pair.serialize_der()),
            skip_verify: false,
        })
    }
}

/// Transport errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("protocol mismatch: {0}")]
    ProtocolMismatch(String),

    #[error("chain ID mismatch: expected {expected}, got {got}")]
    ChainMismatch { expected: String, got: String },

    #[error("connection closed: {0:?}")]
    ConnectionClosed(DisconnectReason),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("too many connections")]
    TooManyConnections,

    #[error("duplicate connection")]
    DuplicateConnection,

    #[error("message codec error: {0}")]
    Codec(#[from] crate::protocol::CodecError),

    #[error("serialization error: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),

    #[error("peer not found: {0}")]
    PeerNotFound(String),
}

/// A network connection with a peer.
#[derive(Debug)]
pub struct Connection {
    /// Unique connection ID.
    pub id: ConnectionId,
    /// Remote peer ID.
    pub peer_id: PeerId,
    /// Remote address.
    pub remote_addr: SocketAddr,
    /// Connection state.
    pub state: ConnectionState,
    /// When the connection was established.
    pub connected_at: DateTime<Utc>,
    /// Last activity timestamp.
    pub last_activity: DateTime<Utc>,
    /// Number of messages sent.
    pub messages_sent: u64,
    /// Number of messages received.
    pub messages_received: u64,
    /// Round-trip latency (from ping/pong).
    pub latency: Option<Duration>,
    /// Is this an outbound connection?
    pub outbound: bool,
}

/// Unique connection identifier.
pub type ConnectionId = u64;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is being established.
    Connecting,
    /// TLS handshake in progress.
    TlsHandshake,
    /// Protocol handshake in progress.
    Handshaking,
    /// Connection is active.
    Active,
    /// Connection is closing.
    Closing,
    /// Connection is closed.
    Closed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Connecting => write!(f, "connecting"),
            ConnectionState::TlsHandshake => write!(f, "tls_handshake"),
            ConnectionState::Handshaking => write!(f, "handshaking"),
            ConnectionState::Active => write!(f, "active"),
            ConnectionState::Closing => write!(f, "closing"),
            ConnectionState::Closed => write!(f, "closed"),
        }
    }
}

/// Connection pool managing multiple peer connections.
#[derive(Debug)]
pub struct ConnectionPool {
    /// Network configuration.
    config: Arc<NetworkConfig>,
    /// Active connections by peer ID.
    connections: RwLock<HashMap<PeerId, Connection>>,
    /// Connection count by address (for deduplication).
    by_address: RwLock<HashMap<SocketAddr, PeerId>>,
    /// Next connection ID.
    next_id: std::sync::atomic::AtomicU64,
}

impl ConnectionPool {
    /// Create a new connection pool.
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config: Arc::new(config),
            connections: RwLock::new(HashMap::new()),
            by_address: RwLock::new(HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Get the network configuration.
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    /// Generate a new connection ID.
    fn next_connection_id(&self) -> ConnectionId {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Get the number of active connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Check if we're connected to a peer.
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        let conns = self.connections.read().await;
        conns
            .get(peer_id)
            .map(|c| c.state == ConnectionState::Active)
            .unwrap_or(false)
    }

    /// Get connection info for a peer.
    pub async fn get_connection(&self, peer_id: &PeerId) -> Option<Connection> {
        let conns = self.connections.read().await;
        // Clone the connection info (not the actual stream)
        conns.get(peer_id).map(|c| Connection {
            id: c.id,
            peer_id: c.peer_id.clone(),
            remote_addr: c.remote_addr,
            state: c.state,
            connected_at: c.connected_at,
            last_activity: c.last_activity,
            messages_sent: c.messages_sent,
            messages_received: c.messages_received,
            latency: c.latency,
            outbound: c.outbound,
        })
    }

    /// Get all peer IDs.
    pub async fn peer_ids(&self) -> Vec<PeerId> {
        self.connections.read().await.keys().cloned().collect()
    }

    /// Add a connection to the pool.
    pub async fn add_connection(
        &self,
        peer_id: PeerId,
        remote_addr: SocketAddr,
        outbound: bool,
    ) -> Result<ConnectionId, TransportError> {
        let mut conns = self.connections.write().await;
        let mut by_addr = self.by_address.write().await;

        // Check limits
        if conns.len() >= self.config.max_connections {
            return Err(TransportError::TooManyConnections);
        }

        // Check for duplicate
        if conns.contains_key(&peer_id) {
            return Err(TransportError::DuplicateConnection);
        }

        let conn_id = self.next_connection_id();
        let now = Utc::now();

        let conn = Connection {
            id: conn_id,
            peer_id: peer_id.clone(),
            remote_addr,
            state: ConnectionState::Active,
            connected_at: now,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
            latency: None,
            outbound,
        };

        conns.insert(peer_id.clone(), conn);
        by_addr.insert(remote_addr, peer_id);

        Ok(conn_id)
    }

    /// Remove a connection from the pool.
    pub async fn remove_connection(&self, peer_id: &PeerId) -> Option<Connection> {
        let mut conns = self.connections.write().await;
        let mut by_addr = self.by_address.write().await;

        if let Some(conn) = conns.remove(peer_id) {
            by_addr.remove(&conn.remote_addr);
            Some(conn)
        } else {
            None
        }
    }

    /// Update connection state.
    pub async fn update_state(&self, peer_id: &PeerId, state: ConnectionState) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.get_mut(peer_id) {
            conn.state = state;
        }
    }

    /// Record message sent.
    pub async fn record_sent(&self, peer_id: &PeerId) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.get_mut(peer_id) {
            conn.messages_sent += 1;
            conn.last_activity = Utc::now();
        }
    }

    /// Record message received.
    pub async fn record_received(&self, peer_id: &PeerId) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.get_mut(peer_id) {
            conn.messages_received += 1;
            conn.last_activity = Utc::now();
        }
    }

    /// Update latency measurement.
    pub async fn update_latency(&self, peer_id: &PeerId, latency: Duration) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.get_mut(peer_id) {
            conn.latency = Some(latency);
        }
    }

    /// Get connections that have been idle too long.
    pub async fn get_idle_connections(&self, max_idle: Duration) -> Vec<PeerId> {
        let conns = self.connections.read().await;
        let now = Utc::now();

        conns
            .iter()
            .filter(|(_, conn)| {
                let idle_time = now.signed_duration_since(conn.last_activity);
                idle_time.num_milliseconds() > max_idle.as_millis() as i64
            })
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }
}

/// Transport layer for network communication.
#[derive(Debug)]
pub struct Transport {
    /// Network configuration.
    config: Arc<NetworkConfig>,
    /// Connection pool.
    pool: Arc<ConnectionPool>,
    /// Message codec.
    codec: MessageCodec,
}

impl Transport {
    /// Create a new transport.
    pub fn new(config: NetworkConfig) -> Self {
        let codec = MessageCodec::with_max_size(config.max_message_size);
        let config = Arc::new(config);
        let pool = Arc::new(ConnectionPool::new((*config).clone()));

        Self {
            config,
            pool,
            codec,
        }
    }

    /// Get the connection pool.
    pub fn pool(&self) -> &Arc<ConnectionPool> {
        &self.pool
    }

    /// Get the network configuration.
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    /// Create a Hello message for handshaking.
    pub fn create_hello(
        &self,
        height: Option<u64>,
        head_hash: Option<moloch_core::block::BlockHash>,
    ) -> HelloMessage {
        let timestamp = Utc::now();
        let message_bytes = format!(
            "{}:{}:{}",
            self.config.chain_id,
            height.unwrap_or(0),
            timestamp.timestamp_millis()
        );
        let signature = self.config.node_key.sign(message_bytes.as_bytes());

        HelloMessage {
            id: generate_message_id(),
            version: ProtocolVersion::CURRENT,
            chain_id: self.config.chain_id.clone(),
            node_key: self.config.node_pubkey(),
            height,
            head_hash,
            timestamp,
            signature,
        }
    }

    /// Create a HelloAck response.
    pub fn create_hello_ack(
        &self,
        request_id: u64,
        height: Option<u64>,
        head_hash: Option<moloch_core::block::BlockHash>,
    ) -> HelloAckMessage {
        let timestamp = Utc::now();
        let message_bytes = format!(
            "ack:{}:{}:{}",
            self.config.chain_id,
            height.unwrap_or(0),
            timestamp.timestamp_millis()
        );
        let signature = self.config.node_key.sign(message_bytes.as_bytes());

        HelloAckMessage {
            request_id,
            version: ProtocolVersion::CURRENT,
            chain_id: self.config.chain_id.clone(),
            node_key: self.config.node_pubkey(),
            height,
            head_hash,
            timestamp,
            signature,
        }
    }

    /// Validate a Hello message.
    pub fn validate_hello(&self, hello: &HelloMessage) -> Result<(), TransportError> {
        // Check protocol version
        if !hello.version.is_compatible_with(&ProtocolVersion::CURRENT) {
            return Err(TransportError::ProtocolMismatch(format!(
                "incompatible protocol version: {}",
                hello.version
            )));
        }

        // Check chain ID
        if hello.chain_id != self.config.chain_id {
            return Err(TransportError::ChainMismatch {
                expected: self.config.chain_id.clone(),
                got: hello.chain_id.clone(),
            });
        }

        // Verify signature (proves key ownership)
        let message_bytes = format!(
            "{}:{}:{}",
            hello.chain_id,
            hello.height.unwrap_or(0),
            hello.timestamp.timestamp_millis()
        );

        hello
            .node_key
            .verify(message_bytes.as_bytes(), &hello.signature)
            .map_err(|_| TransportError::HandshakeFailed("invalid signature".into()))?;

        Ok(())
    }

    /// Validate a HelloAck message.
    pub fn validate_hello_ack(&self, ack: &HelloAckMessage) -> Result<(), TransportError> {
        // Check protocol version
        if !ack.version.is_compatible_with(&ProtocolVersion::CURRENT) {
            return Err(TransportError::ProtocolMismatch(format!(
                "incompatible protocol version: {}",
                ack.version
            )));
        }

        // Check chain ID
        if ack.chain_id != self.config.chain_id {
            return Err(TransportError::ChainMismatch {
                expected: self.config.chain_id.clone(),
                got: ack.chain_id.clone(),
            });
        }

        // Verify signature
        let message_bytes = format!(
            "ack:{}:{}:{}",
            ack.chain_id,
            ack.height.unwrap_or(0),
            ack.timestamp.timestamp_millis()
        );

        ack.node_key
            .verify(message_bytes.as_bytes(), &ack.signature)
            .map_err(|_| TransportError::HandshakeFailed("invalid signature".into()))?;

        Ok(())
    }

    /// Encode a message for sending.
    pub fn encode_message(&self, message: &Message) -> Result<Vec<u8>, TransportError> {
        Ok(self.codec.encode(message)?)
    }

    /// Decode a received message.
    pub fn decode_message(&self, data: &[u8]) -> Result<Message, TransportError> {
        Ok(self.codec.decode(data)?)
    }

    /// Read a message from an async reader.
    pub async fn read_message<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<Message, TransportError> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let length = u32::from_be_bytes(len_buf) as usize;

        if length > self.config.max_message_size {
            return Err(TransportError::Codec(
                crate::protocol::CodecError::MessageTooLarge {
                    size: length,
                    max: self.config.max_message_size,
                },
            ));
        }

        // Read payload
        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload).await?;

        let message = bincode::deserialize(&payload)?;
        Ok(message)
    }

    /// Write a message to an async writer.
    pub async fn write_message<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        message: &Message,
    ) -> Result<(), TransportError> {
        let frame = self.encode_message(message)?;
        writer.write_all(&frame).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// Statistics for the transport layer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportStats {
    /// Total connections established.
    pub connections_established: u64,
    /// Total connections closed.
    pub connections_closed: u64,
    /// Total messages sent.
    pub messages_sent: u64,
    /// Total messages received.
    pub messages_received: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Current active connections.
    pub active_connections: usize,
    /// Failed connection attempts.
    pub connection_failures: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> NetworkConfig {
        NetworkConfig::builder()
            .listen_addr_str("127.0.0.1:0")
            .unwrap()
            .chain_id("moloch-test")
            .node_key(SecretKey::generate())
            .tls(TlsConfig {
                enabled: false,
                ..Default::default()
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_network_config_builder() {
        let config = test_config();
        assert_eq!(config.chain_id, "moloch-test");
        assert_eq!(config.max_connections, 100);
    }

    #[test]
    fn test_network_config_builder_missing_fields() {
        let result = NetworkConfig::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_config_self_signed() {
        let config = TlsConfig::generate_self_signed("localhost").unwrap();
        assert!(config.enabled);
        assert!(config.cert.is_some());
        assert!(config.key.is_some());
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(format!("{}", ConnectionState::Active), "active");
        assert_eq!(format!("{}", ConnectionState::Connecting), "connecting");
    }

    #[tokio::test]
    async fn test_connection_pool_add_remove() {
        let config = test_config();
        let pool = ConnectionPool::new(config);

        let key = SecretKey::generate();
        let peer_id = PeerId::new(key.public_key());
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        // Add connection
        let conn_id = pool
            .add_connection(peer_id.clone(), addr, true)
            .await
            .unwrap();
        assert!(conn_id > 0);
        assert_eq!(pool.connection_count().await, 1);
        assert!(pool.is_connected(&peer_id).await);

        // Remove connection
        let removed = pool.remove_connection(&peer_id).await;
        assert!(removed.is_some());
        assert_eq!(pool.connection_count().await, 0);
        assert!(!pool.is_connected(&peer_id).await);
    }

    #[tokio::test]
    async fn test_connection_pool_duplicate() {
        let config = test_config();
        let pool = ConnectionPool::new(config);

        let key = SecretKey::generate();
        let peer_id = PeerId::new(key.public_key());
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        pool.add_connection(peer_id.clone(), addr, true)
            .await
            .unwrap();

        // Try to add duplicate
        let result = pool.add_connection(peer_id, addr, true).await;
        assert!(matches!(result, Err(TransportError::DuplicateConnection)));
    }

    #[tokio::test]
    async fn test_connection_pool_max_connections() {
        let mut config = test_config();
        config.max_connections = 2;
        let pool = ConnectionPool::new(config);

        // Add two connections
        for i in 0..2 {
            let key = SecretKey::generate();
            let peer_id = PeerId::new(key.public_key());
            let addr: SocketAddr = format!("127.0.0.1:800{}", i).parse().unwrap();
            pool.add_connection(peer_id, addr, true).await.unwrap();
        }

        // Third should fail
        let key = SecretKey::generate();
        let peer_id = PeerId::new(key.public_key());
        let addr: SocketAddr = "127.0.0.1:8002".parse().unwrap();
        let result = pool.add_connection(peer_id, addr, true).await;
        assert!(matches!(result, Err(TransportError::TooManyConnections)));
    }

    #[tokio::test]
    async fn test_connection_pool_stats() {
        let config = test_config();
        let pool = ConnectionPool::new(config);

        let key = SecretKey::generate();
        let peer_id = PeerId::new(key.public_key());
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        pool.add_connection(peer_id.clone(), addr, true)
            .await
            .unwrap();

        // Record activity
        pool.record_sent(&peer_id).await;
        pool.record_sent(&peer_id).await;
        pool.record_received(&peer_id).await;
        pool.update_latency(&peer_id, Duration::from_millis(50))
            .await;

        let conn = pool.get_connection(&peer_id).await.unwrap();
        assert_eq!(conn.messages_sent, 2);
        assert_eq!(conn.messages_received, 1);
        assert_eq!(conn.latency, Some(Duration::from_millis(50)));
    }

    #[test]
    fn test_transport_hello_creation() {
        let config = test_config();
        let transport = Transport::new(config.clone());

        let hello = transport.create_hello(Some(100), None);

        assert_eq!(hello.chain_id, "moloch-test");
        assert_eq!(hello.height, Some(100));
        assert!(hello.version.is_compatible_with(&ProtocolVersion::CURRENT));
    }

    #[test]
    fn test_transport_hello_validation() {
        let config = test_config();
        let transport = Transport::new(config);

        let hello = transport.create_hello(Some(100), None);
        let result = transport.validate_hello(&hello);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transport_hello_wrong_chain() {
        let config = test_config();
        let transport = Transport::new(config);

        let mut hello = transport.create_hello(Some(100), None);
        hello.chain_id = "wrong-chain".into();

        let result = transport.validate_hello(&hello);
        assert!(matches!(result, Err(TransportError::ChainMismatch { .. })));
    }

    #[test]
    fn test_transport_hello_ack() {
        let config = test_config();
        let transport = Transport::new(config);

        let hello = transport.create_hello(Some(100), None);
        let ack = transport.create_hello_ack(hello.id, Some(50), None);

        assert_eq!(ack.request_id, hello.id);
        assert!(transport.validate_hello_ack(&ack).is_ok());
    }

    #[tokio::test]
    async fn test_transport_message_roundtrip() {
        let config = test_config();
        let transport = Transport::new(config);

        let message = Message::Status(StatusMessage {
            height: Some(100),
            head_hash: None,
            peer_count: 5,
            syncing: false,
            timestamp: Utc::now(),
        });

        let encoded = transport.encode_message(&message).unwrap();
        let decoded = transport.decode_message(&encoded).unwrap();

        match decoded {
            Message::Status(s) => {
                assert_eq!(s.height, Some(100));
                assert_eq!(s.peer_count, 5);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[tokio::test]
    async fn test_transport_async_message_io() {
        use tokio::io::duplex;

        let config = test_config();
        let transport = Transport::new(config);

        let (mut client, mut server) = duplex(1024);

        let message = Message::Ping(PingMessage {
            id: 42,
            timestamp: Utc::now(),
        });

        // Write message
        transport
            .write_message(&mut client, &message)
            .await
            .unwrap();

        // Read message
        let received = transport.read_message(&mut server).await.unwrap();

        match received {
            Message::Ping(p) => assert_eq!(p.id, 42),
            _ => panic!("wrong message type"),
        }
    }

    #[tokio::test]
    async fn test_get_idle_connections() {
        let mut config = test_config();
        config.idle_timeout = Duration::from_millis(100);
        let pool = ConnectionPool::new(config);

        let key = SecretKey::generate();
        let peer_id = PeerId::new(key.public_key());
        let addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();

        pool.add_connection(peer_id.clone(), addr, true)
            .await
            .unwrap();

        // Initially not idle
        let idle = pool.get_idle_connections(Duration::from_millis(100)).await;
        assert!(idle.is_empty());

        // Wait and check again
        tokio::time::sleep(Duration::from_millis(150)).await;
        let idle = pool.get_idle_connections(Duration::from_millis(100)).await;
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0], peer_id);
    }
}
