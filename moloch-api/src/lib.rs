//! API layer for Moloch audit chain.
//!
//! This crate provides external access to the chain via:
//! - REST API for CRUD operations
//! - WebSocket for real-time subscriptions
//! - Authentication and rate limiting
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                      API Server                         │
//! │  (Axum router with middleware stack)                    │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!           ┌────────────────┼────────────────┐
//!           ▼                ▼                ▼
//! ┌─────────────────┐ ┌────────────┐ ┌───────────────────┐
//! │    REST API     │ │ WebSocket  │ │  Authentication   │
//! │  (events,blocks)│ │(subscribe) │ │  (JWT, API keys)  │
//! └─────────────────┘ └────────────┘ └───────────────────┘
//!           │                │                │
//!           └────────────────┼────────────────┘
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                    ApiState                             │
//! │  (Shared state: storage, index, consensus)              │
//! └─────────────────────────────────────────────────────────┘
//! ```

pub mod auth;
pub mod rest;
pub mod server;
pub mod ws;

pub use auth::{ApiKey, AuthConfig, AuthError, AuthMiddleware, Claims};
pub use rest::{EventsApi, BlocksApi, ProofsApi, StatusApi};
pub use server::{ApiConfig, ApiServer, ApiState};
pub use ws::{WsHandler, WsSubscription, SubscriptionFilter};
