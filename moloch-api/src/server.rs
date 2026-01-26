//! API server configuration and state.
//!
//! Manages:
//! - Server configuration
//! - Shared state across handlers
//! - Middleware stack
//! - Server lifecycle

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::Method;
use axum::Router;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use moloch_core::block::Block;
use moloch_core::crypto::Hash;
use moloch_core::event::AuditEvent;

use crate::auth::{AuthConfig, AuthMiddleware};
use crate::rest::{ConsistencyProofResponse, EventsQuery, InclusionProofResponse, StatusResponse};
use crate::ws::WsHandler;

/// API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Listen address.
    pub listen_addr: SocketAddr,
    /// Chain ID.
    pub chain_id: String,
    /// Enable CORS.
    pub cors_enabled: bool,
    /// Allowed origins (if CORS enabled).
    pub allowed_origins: Vec<String>,
    /// Request timeout.
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,
    /// Maximum request body size.
    pub max_body_size: usize,
    /// WebSocket channel capacity.
    pub ws_channel_capacity: usize,
}

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
        duration.as_secs().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            chain_id: "moloch-local".to_string(),
            cors_enabled: true,
            allowed_origins: vec!["*".to_string()],
            request_timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024, // 10 MB
            ws_channel_capacity: 1000,
        }
    }
}

/// Shared API state.
pub struct ApiState {
    /// Server configuration.
    pub config: ApiConfig,
    /// Authentication middleware.
    pub auth: AuthMiddleware,
    /// WebSocket handler.
    pub ws_handler: WsHandler,
    /// Server start time.
    start_time: Instant,
    /// Current block height.
    height: RwLock<u64>,
    /// Latest block hash.
    latest_block: RwLock<Option<String>>,
    /// Number of pending events.
    pending_events: RwLock<usize>,
    /// Number of connected peers.
    peer_count: RwLock<usize>,
    /// Mock storage for events (in a real implementation, this would be the actual storage).
    events: RwLock<Vec<AuditEvent>>,
    /// Mock storage for blocks.
    blocks: RwLock<Vec<Block>>,
}

impl ApiState {
    /// Create new API state.
    pub fn new(config: ApiConfig, auth_config: AuthConfig) -> Self {
        Self {
            ws_handler: WsHandler::new(config.ws_channel_capacity),
            config,
            auth: AuthMiddleware::new(auth_config),
            start_time: Instant::now(),
            height: RwLock::new(0),
            latest_block: RwLock::new(None),
            pending_events: RwLock::new(0),
            peer_count: RwLock::new(0),
            events: RwLock::new(Vec::new()),
            blocks: RwLock::new(Vec::new()),
        }
    }

    /// Submit an event to the mempool.
    pub async fn submit_event(&self, event: AuditEvent) -> Result<(), String> {
        // Validate event
        event
            .validate()
            .map_err(|e| format!("invalid event: {}", e))?;

        // Add to events (in real impl, add to mempool)
        self.events.write().push(event.clone());
        *self.pending_events.write() += 1;

        // Broadcast to WebSocket subscribers
        self.ws_handler.broadcast_event(event);

        Ok(())
    }

    /// Get an event by ID.
    pub async fn get_event(&self, id: &Hash) -> Option<AuditEvent> {
        self.events
            .read()
            .iter()
            .find(|e| e.id().as_hash() == id)
            .cloned()
    }

    /// Query events.
    pub async fn query_events(&self, query: &EventsQuery) -> Result<Vec<AuditEvent>, String> {
        let events = self.events.read();
        let mut results: Vec<_> = events.iter().cloned().collect();

        // Apply time range filter
        if let Some(from) = query.from {
            results.retain(|e| e.event_time >= from);
        }
        if let Some(to) = query.to {
            results.retain(|e| e.event_time < to);
        }

        // Apply pagination
        let offset = query.offset;
        let limit = query.limit;

        if offset >= results.len() {
            return Ok(vec![]);
        }

        let end = (offset + limit).min(results.len());
        Ok(results[offset..end].to_vec())
    }

    /// Get a block by height.
    pub async fn get_block(&self, height: u64) -> Option<Block> {
        self.blocks
            .read()
            .iter()
            .find(|b| b.header.height == height)
            .cloned()
    }

    /// Get the latest block.
    pub async fn get_latest_block(&self) -> Option<Block> {
        self.blocks.read().last().cloned()
    }

    /// Add a block.
    pub async fn add_block(&self, block: Block) {
        *self.height.write() = block.header.height;
        *self.latest_block.write() = Some(block.hash().as_hash().to_hex());

        // Broadcast to WebSocket subscribers
        self.ws_handler.broadcast_block(block.clone());

        self.blocks.write().push(block);
    }

    /// Get inclusion proof for an event.
    pub async fn get_inclusion_proof(&self, _event_id: &Hash) -> Option<InclusionProofResponse> {
        // In a real implementation, this would generate an actual Merkle proof
        // For now, return a mock proof
        Some(InclusionProofResponse {
            event_id: _event_id.to_hex(),
            block_height: 0,
            block_hash: "mock".to_string(),
            proof: vec![],
            index: 0,
        })
    }

    /// Get consistency proof between heights.
    pub async fn get_consistency_proof(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Option<ConsistencyProofResponse> {
        // In a real implementation, this would generate an MMR consistency proof
        // For now, return a mock proof
        Some(ConsistencyProofResponse {
            from_height,
            to_height,
            from_root: "mock".to_string(),
            to_root: "mock".to_string(),
            proof: vec![],
        })
    }

    /// Get node status.
    pub async fn get_status(&self) -> StatusResponse {
        StatusResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            chain_id: self.config.chain_id.clone(),
            height: *self.height.read(),
            latest_block: self.latest_block.read().clone(),
            syncing: false,
            peer_count: *self.peer_count.read(),
            pending_events: *self.pending_events.read(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }

    /// Set peer count (for testing/updates).
    pub fn set_peer_count(&self, count: usize) {
        *self.peer_count.write() = count;
    }

    /// Get uptime.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// The API server.
pub struct ApiServer {
    config: ApiConfig,
    state: Arc<ApiState>,
}

impl ApiServer {
    /// Create a new API server.
    pub fn new(config: ApiConfig, auth_config: AuthConfig) -> Self {
        let state = Arc::new(ApiState::new(config.clone(), auth_config));
        Self { config, state }
    }

    /// Get a reference to the shared state.
    pub fn state(&self) -> Arc<ApiState> {
        self.state.clone()
    }

    /// Create the router with all middleware.
    pub fn router(&self) -> Router {
        let cors = if self.config.cors_enabled {
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        } else {
            CorsLayer::new()
        };

        let middleware = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(cors);

        crate::rest::create_router()
            .merge(crate::ws::create_router())
            .layer(middleware)
            .with_state(self.state.clone())
    }

    /// Run the server.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let router = self.router();
        let listener = TcpListener::bind(&self.config.listen_addr).await?;

        info!("API server listening on {}", self.config.listen_addr);

        axum::serve(listener, router).await.map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moloch_core::crypto::SecretKey;
    use moloch_core::event::{ActorId, ActorKind, EventType, ResourceId, ResourceKind};

    fn make_config() -> ApiConfig {
        ApiConfig::default()
    }

    fn make_auth_config() -> AuthConfig {
        AuthConfig::default()
    }

    fn make_event(key: &SecretKey) -> AuditEvent {
        let actor = ActorId::new(key.public_key(), ActorKind::User);
        let resource = ResourceId::new(ResourceKind::Repository, "test-repo");

        AuditEvent::builder()
            .now()
            .event_type(EventType::Push {
                force: false,
                commits: 1,
            })
            .actor(actor)
            .resource(resource)
            .sign(key)
            .unwrap()
    }

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.listen_addr.port(), 8080);
        assert!(config.cors_enabled);
    }

    #[test]
    fn test_api_state_creation() {
        let config = make_config();
        let auth_config = make_auth_config();
        let state = ApiState::new(config, auth_config);

        assert_eq!(*state.height.read(), 0);
        assert!(state.latest_block.read().is_none());
    }

    #[tokio::test]
    async fn test_submit_event() {
        let config = make_config();
        let auth_config = make_auth_config();
        let state = ApiState::new(config, auth_config);

        let key = SecretKey::generate();
        let event = make_event(&key);

        let result = state.submit_event(event).await;
        assert!(result.is_ok());
        assert_eq!(*state.pending_events.read(), 1);
    }

    #[tokio::test]
    async fn test_get_event() {
        let config = make_config();
        let auth_config = make_auth_config();
        let state = ApiState::new(config, auth_config);

        let key = SecretKey::generate();
        let event = make_event(&key);
        let id = event.id();

        state.submit_event(event).await.unwrap();

        let found = state.get_event(id.as_hash()).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), id);
    }

    #[tokio::test]
    async fn test_get_status() {
        let config = make_config();
        let auth_config = make_auth_config();
        let state = ApiState::new(config, auth_config);

        let status = state.get_status().await;
        assert_eq!(status.height, 0);
        assert!(!status.syncing);
    }

    #[tokio::test]
    async fn test_query_events() {
        let config = make_config();
        let auth_config = make_auth_config();
        let state = ApiState::new(config, auth_config);

        let key = SecretKey::generate();
        for _ in 0..5 {
            let event = make_event(&key);
            state.submit_event(event).await.unwrap();
        }

        let query = EventsQuery {
            limit: 3,
            offset: 0,
            ..Default::default()
        };

        let results = state.query_events(&query).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_api_server_creation() {
        let config = make_config();
        let auth_config = make_auth_config();
        let server = ApiServer::new(config, auth_config);

        assert!(server.state.uptime() < Duration::from_secs(1));
    }

    #[test]
    fn test_api_server_router() {
        let config = make_config();
        let auth_config = make_auth_config();
        let server = ApiServer::new(config, auth_config);

        let _router = server.router();
        // Router creation should not panic
    }

    #[test]
    fn test_set_peer_count() {
        let config = make_config();
        let auth_config = make_auth_config();
        let state = ApiState::new(config, auth_config);

        state.set_peer_count(5);
        assert_eq!(*state.peer_count.read(), 5);
    }
}
