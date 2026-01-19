//! WebSocket subscriptions for real-time updates.
//!
//! Supports:
//! - Subscribe to new events
//! - Subscribe to new blocks
//! - Filter by actor/resource
//! - Automatic reconnection

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex as AsyncMutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use moloch_core::block::Block;
use moloch_core::crypto::Hash;
use moloch_core::event::AuditEvent;

use crate::rest::{BlockInfo, EventInfo};
use crate::server::ApiState;

/// Subscription filter for WebSocket clients.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    /// Subscribe to events.
    #[serde(default)]
    pub events: bool,
    /// Subscribe to blocks.
    #[serde(default)]
    pub blocks: bool,
    /// Filter events by actor ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Filter events by resource ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Filter events by type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
}

impl SubscriptionFilter {
    /// Create a filter for all events.
    pub fn all_events() -> Self {
        Self {
            events: true,
            blocks: false,
            ..Default::default()
        }
    }

    /// Create a filter for all blocks.
    pub fn all_blocks() -> Self {
        Self {
            events: false,
            blocks: true,
            ..Default::default()
        }
    }

    /// Create a filter for everything.
    pub fn all() -> Self {
        Self {
            events: true,
            blocks: true,
            ..Default::default()
        }
    }

    /// Check if an event matches the filter.
    pub fn matches_event(&self, event: &AuditEvent) -> bool {
        if !self.events {
            return false;
        }

        if let Some(ref actor) = self.actor {
            if !format!("{:?}", event.actor).contains(actor) {
                return false;
            }
        }

        if let Some(ref resource) = self.resource {
            if !format!("{:?}", event.resource).contains(resource) {
                return false;
            }
        }

        if let Some(ref event_type) = self.event_type {
            if !format!("{:?}", event.event_type).contains(event_type) {
                return false;
            }
        }

        true
    }

    /// Check if blocks should be sent.
    pub fn wants_blocks(&self) -> bool {
        self.blocks
    }
}

/// WebSocket message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WsMessage {
    /// Subscribe to events/blocks.
    Subscribe(SubscriptionFilter),
    /// Unsubscribe.
    Unsubscribe,
    /// Ping (keep-alive).
    Ping,
    /// Pong response.
    Pong,
    /// New event notification.
    Event(EventInfo),
    /// New block notification.
    Block(BlockInfo),
    /// Error message.
    Error { message: String },
    /// Subscription confirmed.
    Subscribed { id: String },
    /// Welcome message on connect.
    Welcome { version: String },
}

/// A WebSocket subscription.
#[derive(Debug)]
pub struct WsSubscription {
    /// Unique subscription ID.
    pub id: String,
    /// Current filter.
    pub filter: SubscriptionFilter,
    /// When the subscription was created.
    pub created_at: DateTime<Utc>,
    /// Number of messages sent.
    pub messages_sent: u64,
}

impl WsSubscription {
    /// Create a new subscription.
    pub fn new(filter: SubscriptionFilter) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            filter,
            created_at: Utc::now(),
            messages_sent: 0,
        }
    }

    /// Update the filter.
    pub fn update_filter(&mut self, filter: SubscriptionFilter) {
        self.filter = filter;
    }

    /// Increment message counter.
    pub fn increment_messages(&mut self) {
        self.messages_sent += 1;
    }
}

/// WebSocket handler.
pub struct WsHandler {
    /// Broadcast channel for events.
    event_tx: broadcast::Sender<Arc<AuditEvent>>,
    /// Broadcast channel for blocks.
    block_tx: broadcast::Sender<Arc<Block>>,
    /// Active subscriptions count.
    subscription_count: Arc<RwLock<usize>>,
}

impl WsHandler {
    /// Create a new WebSocket handler.
    pub fn new(channel_capacity: usize) -> Self {
        let (event_tx, _) = broadcast::channel(channel_capacity);
        let (block_tx, _) = broadcast::channel(channel_capacity);

        Self {
            event_tx,
            block_tx,
            subscription_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Broadcast an event to all subscribers.
    pub fn broadcast_event(&self, event: AuditEvent) {
        let _ = self.event_tx.send(Arc::new(event));
    }

    /// Broadcast a block to all subscribers.
    pub fn broadcast_block(&self, block: Block) {
        let _ = self.block_tx.send(Arc::new(block));
    }

    /// Get the number of active subscriptions.
    pub fn subscription_count(&self) -> usize {
        *self.subscription_count.read()
    }

    /// Subscribe to events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<Arc<AuditEvent>> {
        self.event_tx.subscribe()
    }

    /// Subscribe to blocks.
    pub fn subscribe_blocks(&self) -> broadcast::Receiver<Arc<Block>> {
        self.block_tx.subscribe()
    }

    /// Handle a WebSocket connection.
    pub async fn handle_connection(&self, socket: WebSocket) {
        let (sender, receiver) = socket.split();

        // Increment subscription count
        {
            let mut count = self.subscription_count.write();
            *count += 1;
        }

        let subscription = Arc::new(RwLock::new(WsSubscription::new(SubscriptionFilter::default())));
        let event_rx = self.event_tx.subscribe();
        let block_rx = self.block_tx.subscribe();

        // Send welcome message
        let sender = Arc::new(AsyncMutex::new(sender));
        Self::send_message(&sender, WsMessage::Welcome {
            version: "0.1.0".to_string(),
        }).await;

        // Spawn tasks for sending and receiving
        let sender_clone = sender.clone();
        let subscription_clone = subscription.clone();

        let send_task = tokio::spawn(Self::send_loop(
            sender_clone,
            subscription_clone,
            event_rx,
            block_rx,
        ));

        let recv_task = tokio::spawn(Self::receive_loop(
            sender.clone(),
            subscription.clone(),
            receiver,
        ));

        // Wait for either task to complete
        tokio::select! {
            _ = send_task => {}
            _ = recv_task => {}
        }

        // Decrement subscription count
        {
            let mut count = self.subscription_count.write();
            *count = count.saturating_sub(1);
        }

        info!("WebSocket connection closed");
    }

    /// Send loop: broadcast events and blocks to the client.
    async fn send_loop(
        sender: Arc<AsyncMutex<SplitSink<WebSocket, Message>>>,
        subscription: Arc<RwLock<WsSubscription>>,
        mut event_rx: broadcast::Receiver<Arc<AuditEvent>>,
        mut block_rx: broadcast::Receiver<Arc<Block>>,
    ) {
        loop {
            tokio::select! {
                result = event_rx.recv() => {
                    match result {
                        Ok(event) => {
                            let filter = subscription.read().filter.clone();
                            if filter.matches_event(&event) {
                                let info = EventInfo::from(event.as_ref());
                                Self::send_message(&sender, WsMessage::Event(info)).await;
                                subscription.write().increment_messages();
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("WebSocket client lagged, skipped {} events", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                result = block_rx.recv() => {
                    match result {
                        Ok(block) => {
                            let filter = subscription.read().filter.clone();
                            if filter.wants_blocks() {
                                let info = BlockInfo::from(block.as_ref());
                                Self::send_message(&sender, WsMessage::Block(info)).await;
                                subscription.write().increment_messages();
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("WebSocket client lagged, skipped {} blocks", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Receive loop: handle incoming messages from the client.
    async fn receive_loop(
        sender: Arc<AsyncMutex<SplitSink<WebSocket, Message>>>,
        subscription: Arc<RwLock<WsSubscription>>,
        mut receiver: SplitStream<WebSocket>,
    ) {
        while let Some(result) = receiver.next().await {
            match result {
                Ok(Message::Text(text)) => {
                    match serde_json::from_str::<WsMessage>(&text) {
                        Ok(msg) => {
                            Self::handle_message(&sender, &subscription, msg).await;
                        }
                        Err(e) => {
                            Self::send_message(&sender, WsMessage::Error {
                                message: format!("invalid message: {}", e),
                            }).await;
                        }
                    }
                }
                Ok(Message::Ping(data)) => {
                    let mut sender = sender.lock().await;
                    let _ = sender.send(Message::Pong(data)).await;
                }
                Ok(Message::Close(_)) => {
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    }

    /// Handle an incoming WebSocket message.
    async fn handle_message(
        sender: &Arc<AsyncMutex<SplitSink<WebSocket, Message>>>,
        subscription: &Arc<RwLock<WsSubscription>>,
        msg: WsMessage,
    ) {
        match msg {
            WsMessage::Subscribe(filter) => {
                let id = {
                    let mut sub = subscription.write();
                    sub.update_filter(filter);
                    sub.id.clone()
                };
                debug!("Client subscribed with filter");
                Self::send_message(sender, WsMessage::Subscribed { id }).await;
            }
            WsMessage::Unsubscribe => {
                subscription.write().update_filter(SubscriptionFilter::default());
                debug!("Client unsubscribed");
            }
            WsMessage::Ping => {
                Self::send_message(sender, WsMessage::Pong).await;
            }
            _ => {
                // Ignore other messages from client
            }
        }
    }

    /// Send a message to the client.
    async fn send_message(
        sender: &Arc<AsyncMutex<SplitSink<WebSocket, Message>>>,
        msg: WsMessage,
    ) {
        if let Ok(json) = serde_json::to_string(&msg) {
            let mut sender = sender.lock().await;
            if let Err(e) = sender.send(Message::Text(json)).await {
                error!("Failed to send WebSocket message: {}", e);
            }
        }
    }
}

/// WebSocket upgrade handler.
pub async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        state.ws_handler.handle_connection(socket).await;
    })
}

/// Create WebSocket router.
pub fn create_router() -> Router<Arc<ApiState>> {
    Router::new().route("/ws", get(ws_upgrade))
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;
    use moloch_core::event::{ActorId, ActorKind, EventType, ResourceId, ResourceKind};

    fn make_event(key: &SecretKey) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test-repo");

        AuditEvent::builder()
            .now()
            .event_type(EventType::Push { force: false, commits: 1 })
            .actor(actor)
            .resource(resource)
            .sign(key)
            .unwrap()
    }

    #[test]
    fn test_subscription_filter_default() {
        let filter = SubscriptionFilter::default();
        assert!(!filter.events);
        assert!(!filter.blocks);
    }

    #[test]
    fn test_subscription_filter_all_events() {
        let filter = SubscriptionFilter::all_events();
        assert!(filter.events);
        assert!(!filter.blocks);
    }

    #[test]
    fn test_subscription_filter_all_blocks() {
        let filter = SubscriptionFilter::all_blocks();
        assert!(!filter.events);
        assert!(filter.blocks);
    }

    #[test]
    fn test_subscription_filter_matches_event() {
        let key = SecretKey::generate();
        let event = make_event(&key);

        // Filter that matches all events
        let filter = SubscriptionFilter::all_events();
        assert!(filter.matches_event(&event));

        // Filter that doesn't subscribe to events
        let filter = SubscriptionFilter::all_blocks();
        assert!(!filter.matches_event(&event));

        // Filter with actor filter
        let mut filter = SubscriptionFilter::all_events();
        filter.actor = Some("nonexistent".to_string());
        assert!(!filter.matches_event(&event));
    }

    #[test]
    fn test_ws_subscription_new() {
        let sub = WsSubscription::new(SubscriptionFilter::all());
        assert!(!sub.id.is_empty());
        assert_eq!(sub.messages_sent, 0);
    }

    #[test]
    fn test_ws_subscription_increment() {
        let mut sub = WsSubscription::new(SubscriptionFilter::all());
        sub.increment_messages();
        sub.increment_messages();
        assert_eq!(sub.messages_sent, 2);
    }

    #[test]
    fn test_ws_handler_creation() {
        let handler = WsHandler::new(100);
        assert_eq!(handler.subscription_count(), 0);
    }

    #[test]
    fn test_ws_message_serialization() {
        let msg = WsMessage::Subscribe(SubscriptionFilter::all_events());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("Subscribe"));

        let msg = WsMessage::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("Ping"));

        let msg = WsMessage::Error {
            message: "test error".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("test error"));
    }

    #[test]
    fn test_ws_message_deserialization() {
        let json = r#"{"type":"Subscribe","data":{"events":true,"blocks":false}}"#;
        let msg: WsMessage = serde_json::from_str(json).unwrap();
        match msg {
            WsMessage::Subscribe(filter) => {
                assert!(filter.events);
                assert!(!filter.blocks);
            }
            _ => panic!("expected Subscribe"),
        }
    }
}
