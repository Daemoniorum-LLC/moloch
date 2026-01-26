//! Protocol messages for Moloch network communication.
//!
//! Defines message types for:
//! - Handshake (Hello, status exchange)
//! - Gossip (new events, new blocks)
//! - Sync (block requests, block responses)
//! - Consensus (proposals, votes)

use std::io::{self, Read, Write};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use moloch_core::block::{Block, BlockHash, BlockHeader};
use moloch_core::crypto::{Hash, PublicKey, Sig};
use moloch_core::event::{AuditEvent, EventId};

/// Protocol version for compatibility checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ProtocolVersion {
    /// Current protocol version.
    pub const CURRENT: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    /// Check if this version is compatible with another.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        // Major version must match
        self.major == other.major
    }

    /// Create a new protocol version.
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Unique identifier for a message (for deduplication and request/response matching).
pub type MessageId = u64;

/// Unique identifier for a peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId {
    /// Public key of the peer.
    pub key: PublicKey,
}

impl PeerId {
    /// Create a new peer ID from a public key.
    pub fn new(key: PublicKey) -> Self {
        Self { key }
    }

    /// Get the hash-based identifier.
    pub fn id(&self) -> Hash {
        self.key.id()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.key.as_bytes()[..8]))
    }
}

/// Network message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // === Handshake ===
    /// Initial handshake message sent when connecting.
    Hello(HelloMessage),

    /// Response to Hello with our status.
    HelloAck(HelloAckMessage),

    /// Periodic status update.
    Status(StatusMessage),

    /// Disconnect notification.
    Goodbye(GoodbyeMessage),

    // === Gossip ===
    /// Announce a new event (push).
    NewEvent(NewEventMessage),

    /// Announce a new block (push).
    NewBlock(NewBlockMessage),

    /// Announce available events/blocks (pull-based).
    Announce(AnnounceMessage),

    // === Sync ===
    /// Request blocks by height range.
    GetBlocks(GetBlocksMessage),

    /// Response with requested blocks.
    Blocks(BlocksMessage),

    /// Request block headers by height range.
    GetHeaders(GetHeadersMessage),

    /// Response with block headers.
    Headers(HeadersMessage),

    /// Request specific events by ID.
    GetEvents(GetEventsMessage),

    /// Response with requested events.
    Events(EventsMessage),

    /// Request current chain state snapshot.
    GetSnapshot(GetSnapshotMessage),

    /// Response with chain snapshot.
    Snapshot(SnapshotMessage),

    // === Consensus ===
    /// Block proposal from leader.
    Proposal(ProposalMessage),

    /// Vote on a proposal.
    Vote(VoteMessage),

    /// Request votes for a block.
    GetVotes(GetVotesMessage),

    /// Response with collected votes.
    Votes(VotesMessage),

    // === Ping/Pong ===
    /// Keep-alive ping.
    Ping(PingMessage),

    /// Keep-alive pong response.
    Pong(PongMessage),
}

impl Message {
    /// Get the message type as a string.
    pub fn type_name(&self) -> &'static str {
        match self {
            Message::Hello(_) => "Hello",
            Message::HelloAck(_) => "HelloAck",
            Message::Status(_) => "Status",
            Message::Goodbye(_) => "Goodbye",
            Message::NewEvent(_) => "NewEvent",
            Message::NewBlock(_) => "NewBlock",
            Message::Announce(_) => "Announce",
            Message::GetBlocks(_) => "GetBlocks",
            Message::Blocks(_) => "Blocks",
            Message::GetHeaders(_) => "GetHeaders",
            Message::Headers(_) => "Headers",
            Message::GetEvents(_) => "GetEvents",
            Message::Events(_) => "Events",
            Message::GetSnapshot(_) => "GetSnapshot",
            Message::Snapshot(_) => "Snapshot",
            Message::Proposal(_) => "Proposal",
            Message::Vote(_) => "Vote",
            Message::GetVotes(_) => "GetVotes",
            Message::Votes(_) => "Votes",
            Message::Ping(_) => "Ping",
            Message::Pong(_) => "Pong",
        }
    }

    /// Check if this is a request message (expects a response).
    pub fn is_request(&self) -> bool {
        matches!(
            self,
            Message::Hello(_)
                | Message::GetBlocks(_)
                | Message::GetHeaders(_)
                | Message::GetEvents(_)
                | Message::GetSnapshot(_)
                | Message::GetVotes(_)
                | Message::Ping(_)
        )
    }

    /// Get the message ID if present.
    pub fn message_id(&self) -> Option<MessageId> {
        match self {
            Message::Hello(m) => Some(m.id),
            Message::HelloAck(m) => Some(m.request_id),
            Message::GetBlocks(m) => Some(m.id),
            Message::Blocks(m) => Some(m.request_id),
            Message::GetHeaders(m) => Some(m.id),
            Message::Headers(m) => Some(m.request_id),
            Message::GetEvents(m) => Some(m.id),
            Message::Events(m) => Some(m.request_id),
            Message::GetSnapshot(m) => Some(m.id),
            Message::Snapshot(m) => Some(m.request_id),
            Message::GetVotes(m) => Some(m.id),
            Message::Votes(m) => Some(m.request_id),
            Message::Ping(m) => Some(m.id),
            Message::Pong(m) => Some(m.request_id),
            _ => None,
        }
    }
}

// === Handshake Messages ===

/// Initial handshake message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    /// Message ID for request/response matching.
    pub id: MessageId,
    /// Protocol version.
    pub version: ProtocolVersion,
    /// Chain ID (for network separation).
    pub chain_id: String,
    /// Node's public key.
    pub node_key: PublicKey,
    /// Current chain height (None if not synced).
    pub height: Option<u64>,
    /// Current head block hash.
    pub head_hash: Option<BlockHash>,
    /// Timestamp of the message.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
    /// Signature over the message (proves key ownership).
    pub signature: Sig,
}

/// Response to Hello message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAckMessage {
    /// ID of the Hello message being acknowledged.
    pub request_id: MessageId,
    /// Protocol version.
    pub version: ProtocolVersion,
    /// Chain ID.
    pub chain_id: String,
    /// Node's public key.
    pub node_key: PublicKey,
    /// Current chain height.
    pub height: Option<u64>,
    /// Current head block hash.
    pub head_hash: Option<BlockHash>,
    /// Timestamp.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
    /// Signature.
    pub signature: Sig,
}

/// Periodic status update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusMessage {
    /// Current chain height.
    pub height: Option<u64>,
    /// Current head block hash.
    pub head_hash: Option<BlockHash>,
    /// Number of known peers.
    pub peer_count: usize,
    /// Is the node syncing?
    pub syncing: bool,
    /// Timestamp.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
}

/// Disconnect notification with reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoodbyeMessage {
    /// Reason for disconnecting.
    pub reason: DisconnectReason,
    /// Optional message.
    pub message: Option<String>,
}

/// Reasons for disconnecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectReason {
    /// Normal shutdown.
    Shutdown,
    /// Protocol version mismatch.
    ProtocolMismatch,
    /// Chain ID mismatch.
    ChainMismatch,
    /// Too many connections.
    TooManyConnections,
    /// Peer misbehaving.
    Misbehavior,
    /// Connection timeout.
    Timeout,
    /// Duplicate connection.
    DuplicateConnection,
    /// Requested by user.
    Requested,
    /// Other reason.
    Other,
}

// === Gossip Messages ===

/// Announce a new event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewEventMessage {
    /// The event.
    pub event: AuditEvent,
}

/// Announce a new block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewBlockMessage {
    /// The block.
    pub block: Block,
}

/// Announce available data (pull-based gossip).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnounceMessage {
    /// Type of announcement.
    pub announcement: Announcement,
}

/// Types of announcements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Announcement {
    /// New block available at height.
    Block { height: u64, hash: BlockHash },
    /// New events available.
    Events { ids: Vec<EventId> },
    /// New chain tip.
    ChainTip { height: u64, hash: BlockHash },
}

// === Sync Messages ===

/// Request blocks by height range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBlocksMessage {
    /// Request ID.
    pub id: MessageId,
    /// Start height (inclusive).
    pub start_height: u64,
    /// Number of blocks to request.
    pub count: u32,
}

/// Response with blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocksMessage {
    /// ID of the request being answered.
    pub request_id: MessageId,
    /// Requested blocks.
    pub blocks: Vec<Block>,
    /// Are there more blocks available?
    pub has_more: bool,
}

/// Request block headers by height range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeadersMessage {
    /// Request ID.
    pub id: MessageId,
    /// Start height (inclusive).
    pub start_height: u64,
    /// Number of headers to request.
    pub count: u32,
}

/// Response with headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadersMessage {
    /// ID of the request being answered.
    pub request_id: MessageId,
    /// Requested headers.
    pub headers: Vec<BlockHeader>,
    /// Are there more headers available?
    pub has_more: bool,
}

/// Request specific events by ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEventsMessage {
    /// Request ID.
    pub id: MessageId,
    /// Event IDs to request.
    pub event_ids: Vec<EventId>,
}

/// Response with events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsMessage {
    /// ID of the request being answered.
    pub request_id: MessageId,
    /// Requested events.
    pub events: Vec<AuditEvent>,
    /// IDs of events that were not found.
    pub not_found: Vec<EventId>,
}

/// Request chain state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSnapshotMessage {
    /// Request ID.
    pub id: MessageId,
    /// Requested height (None = latest).
    pub height: Option<u64>,
}

/// Chain state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMessage {
    /// ID of the request being answered.
    pub request_id: MessageId,
    /// Snapshot height.
    pub height: u64,
    /// Head block hash at this height.
    pub head_hash: BlockHash,
    /// MMR root at this height.
    pub mmr_root: Hash,
    /// Number of blocks in the chain.
    pub block_count: u64,
    /// Total number of events in the chain.
    pub event_count: u64,
    /// Validator set at this height.
    pub validators: Vec<PublicKey>,
}

// === Consensus Messages ===

/// Block proposal from leader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalMessage {
    /// The proposed block.
    pub block: Block,
    /// Proposer's signature over the block.
    pub signature: Sig,
}

/// Vote on a proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteMessage {
    /// Hash of the block being voted on.
    pub block_hash: BlockHash,
    /// Height of the block.
    pub height: u64,
    /// Voter's public key.
    pub voter: PublicKey,
    /// Vote signature.
    pub signature: Sig,
}

/// Request votes for a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetVotesMessage {
    /// Request ID.
    pub id: MessageId,
    /// Block hash to get votes for.
    pub block_hash: BlockHash,
}

/// Response with votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotesMessage {
    /// ID of the request being answered.
    pub request_id: MessageId,
    /// Block hash.
    pub block_hash: BlockHash,
    /// Collected votes.
    pub votes: Vec<VoteMessage>,
}

// === Ping/Pong Messages ===

/// Keep-alive ping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingMessage {
    /// Message ID.
    pub id: MessageId,
    /// Timestamp for latency measurement.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
}

/// Keep-alive pong response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongMessage {
    /// ID of the ping being responded to.
    pub request_id: MessageId,
    /// Timestamp from the ping.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub ping_timestamp: DateTime<Utc>,
    /// Our timestamp.
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub pong_timestamp: DateTime<Utc>,
}

/// Message codec for serialization/deserialization.
#[derive(Debug, Clone)]
pub struct MessageCodec {
    /// Maximum message size in bytes.
    max_size: usize,
}

impl MessageCodec {
    /// Default maximum message size (16 MB).
    pub const DEFAULT_MAX_SIZE: usize = 16 * 1024 * 1024;

    /// Create a new codec with default settings.
    pub fn new() -> Self {
        Self {
            max_size: Self::DEFAULT_MAX_SIZE,
        }
    }

    /// Create a codec with a custom max size.
    pub fn with_max_size(max_size: usize) -> Self {
        Self { max_size }
    }

    /// Encode a message to bytes.
    pub fn encode(&self, message: &Message) -> Result<Vec<u8>, CodecError> {
        let payload = bincode::serialize(message)?;

        if payload.len() > self.max_size {
            return Err(CodecError::MessageTooLarge {
                size: payload.len(),
                max: self.max_size,
            });
        }

        // Frame format: [length: 4 bytes][payload]
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);

        Ok(frame)
    }

    /// Decode a message from bytes.
    pub fn decode(&self, data: &[u8]) -> Result<Message, CodecError> {
        if data.len() < 4 {
            return Err(CodecError::IncompletFrame);
        }

        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

        if length > self.max_size {
            return Err(CodecError::MessageTooLarge {
                size: length,
                max: self.max_size,
            });
        }

        if data.len() < 4 + length {
            return Err(CodecError::IncompletFrame);
        }

        let message = bincode::deserialize(&data[4..4 + length])?;
        Ok(message)
    }

    /// Read a framed message from a reader.
    pub fn read_message<R: Read>(&self, reader: &mut R) -> Result<Message, CodecError> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let length = u32::from_be_bytes(len_buf) as usize;

        if length > self.max_size {
            return Err(CodecError::MessageTooLarge {
                size: length,
                max: self.max_size,
            });
        }

        // Read payload
        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload)?;

        let message = bincode::deserialize(&payload)?;
        Ok(message)
    }

    /// Write a framed message to a writer.
    pub fn write_message<W: Write>(
        &self,
        writer: &mut W,
        message: &Message,
    ) -> Result<(), CodecError> {
        let frame = self.encode(message)?;
        writer.write_all(&frame)?;
        Ok(())
    }
}

impl Default for MessageCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors during message encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("message too large: {size} bytes exceeds limit of {max} bytes")]
    MessageTooLarge { size: usize, max: usize },

    #[error("incomplete frame")]
    IncompletFrame,

    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Generate a unique message ID.
pub fn generate_message_id() -> MessageId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;

    #[test]
    fn test_protocol_version_compatibility() {
        let v1 = ProtocolVersion::new(1, 0, 0);
        let v1_1 = ProtocolVersion::new(1, 1, 0);
        let v2 = ProtocolVersion::new(2, 0, 0);

        assert!(v1.is_compatible_with(&v1_1));
        assert!(v1_1.is_compatible_with(&v1));
        assert!(!v1.is_compatible_with(&v2));
    }

    #[test]
    fn test_protocol_version_display() {
        let v = ProtocolVersion::new(1, 2, 3);
        assert_eq!(format!("{}", v), "1.2.3");
    }

    #[test]
    fn test_peer_id() {
        let key = SecretKey::generate();
        let peer_id = PeerId::new(key.public_key());

        // ID should be deterministic
        let id1 = peer_id.id();
        let id2 = peer_id.id();
        assert_eq!(id1, id2);

        // Display should be short hex
        let display = format!("{}", peer_id);
        assert_eq!(display.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_message_type_names() {
        let key = SecretKey::generate();
        let hello = Message::Hello(HelloMessage {
            id: 1,
            version: ProtocolVersion::CURRENT,
            chain_id: "test".into(),
            node_key: key.public_key(),
            height: Some(100),
            head_hash: None,
            timestamp: Utc::now(),
            signature: key.sign(b"hello"),
        });

        assert_eq!(hello.type_name(), "Hello");
        assert!(hello.is_request());
        assert_eq!(hello.message_id(), Some(1));
    }

    #[test]
    fn test_message_codec_roundtrip() {
        let codec = MessageCodec::new();
        let key = SecretKey::generate();

        let original = Message::Status(StatusMessage {
            height: Some(50),
            head_hash: None,
            peer_count: 5,
            syncing: false,
            timestamp: Utc::now(),
        });

        let encoded = codec.encode(&original).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        match (&original, &decoded) {
            (Message::Status(orig), Message::Status(dec)) => {
                assert_eq!(orig.height, dec.height);
                assert_eq!(orig.peer_count, dec.peer_count);
                assert_eq!(orig.syncing, dec.syncing);
            }
            _ => panic!("message type mismatch"),
        }
    }

    #[test]
    fn test_message_codec_size_limit() {
        let codec = MessageCodec::with_max_size(100);

        // Create a message that will be too large
        let large_message = Message::Goodbye(GoodbyeMessage {
            reason: DisconnectReason::Other,
            message: Some("x".repeat(200)),
        });

        let result = codec.encode(&large_message);
        assert!(matches!(result, Err(CodecError::MessageTooLarge { .. })));
    }

    #[test]
    fn test_message_codec_incomplete_frame() {
        let codec = MessageCodec::new();
        let result = codec.decode(&[0, 0, 0]); // Only 3 bytes, need at least 4
        assert!(matches!(result, Err(CodecError::IncompletFrame)));
    }

    #[test]
    fn test_ping_pong_messages() {
        let ping = PingMessage {
            id: 42,
            timestamp: Utc::now(),
        };

        let pong = PongMessage {
            request_id: 42,
            ping_timestamp: ping.timestamp,
            pong_timestamp: Utc::now(),
        };

        assert_eq!(pong.request_id, ping.id);
    }

    #[test]
    fn test_disconnect_reasons() {
        let reasons = vec![
            DisconnectReason::Shutdown,
            DisconnectReason::ProtocolMismatch,
            DisconnectReason::ChainMismatch,
            DisconnectReason::TooManyConnections,
            DisconnectReason::Misbehavior,
            DisconnectReason::Timeout,
            DisconnectReason::DuplicateConnection,
            DisconnectReason::Requested,
            DisconnectReason::Other,
        ];

        let codec = MessageCodec::new();

        for reason in reasons {
            let msg = Message::Goodbye(GoodbyeMessage {
                reason,
                message: None,
            });

            let encoded = codec.encode(&msg).unwrap();
            let decoded = codec.decode(&encoded).unwrap();

            match decoded {
                Message::Goodbye(g) => assert_eq!(g.reason, reason),
                _ => panic!("wrong message type"),
            }
        }
    }

    #[test]
    fn test_get_blocks_message() {
        let msg = GetBlocksMessage {
            id: generate_message_id(),
            start_height: 100,
            count: 50,
        };

        let codec = MessageCodec::new();
        let encoded = codec.encode(&Message::GetBlocks(msg.clone())).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        match decoded {
            Message::GetBlocks(m) => {
                assert_eq!(m.start_height, 100);
                assert_eq!(m.count, 50);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_announcement_variants() {
        use moloch_core::crypto::hash;

        let announcements = vec![
            Announcement::Block {
                height: 100,
                hash: moloch_core::block::BlockHash(hash(b"block")),
            },
            Announcement::Events {
                ids: vec![moloch_core::event::EventId(hash(b"event1"))],
            },
            Announcement::ChainTip {
                height: 200,
                hash: moloch_core::block::BlockHash(hash(b"tip")),
            },
        ];

        let codec = MessageCodec::new();

        for ann in announcements {
            let msg = Message::Announce(AnnounceMessage { announcement: ann });
            let encoded = codec.encode(&msg).unwrap();
            let decoded = codec.decode(&encoded).unwrap();
            assert!(matches!(decoded, Message::Announce(_)));
        }
    }

    #[test]
    fn test_generate_message_id_unique() {
        let id1 = generate_message_id();
        let id2 = generate_message_id();
        let id3 = generate_message_id();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }
}
