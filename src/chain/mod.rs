//! Chain-driven KAS validation module.
//!
//! This module provides blockchain-based session validation for the Key Access Server.
//! Instead of evaluating policies locally, the KAS queries the arkavo-node blockchain
//! for SessionGrant data and validates requests against on-chain state.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
//! │ ChainClient │────▶│ SessionCache │────▶│ SessionValidator│
//! │   (subxt)   │     │   (6s TTL)   │     │    (trait)      │
//! └─────────────┘     └──────────────┘     └─────────────────┘
//!        │                                          │
//!        │                                          │
//!        ▼                                          ▼
//! ┌─────────────┐                          ┌─────────────────┐
//! │arkavo-node  │                          │ ChainValidator  │
//! │  blockchain │                          │    (impl)       │
//! └─────────────┘                          └─────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use arkavo_rs::chain::{ChainClient, SessionCache, ChainValidator, SessionValidator};
//!
//! // Initialize components
//! let client = Arc::new(ChainClient::new("ws://chain.arkavo.net".to_string()));
//! let cache = Arc::new(SessionCache::new(server_secret, redis_client));
//! let validator = ChainValidator::new(client, cache);
//!
//! // Validate a request
//! let request = ChainValidationRequest {
//!     session_id: "abc123...".to_string(),
//!     resource_id: "def456...".to_string(),
//!     signature: signature_bytes,
//!     algorithm: "ES256".to_string(),
//!     nonce: 12345,
//! };
//!
//! match validator.validate(&request).await {
//!     Ok(session) => { /* proceed with rewrap */ }
//!     Err(e) => { /* return error response */ }
//! }
//! ```

pub mod cache;
pub mod client;
pub mod error;
pub mod types;
pub mod validator;

// Re-export main types for convenience
pub use cache::SessionCache;
pub use client::ChainClient;
pub use error::{CacheError, ChainError, ValidationError};
pub use types::{ChainValidationRequest, SessionGrant, ValidatedSession};
pub use validator::{ChainValidator, SessionValidator};
