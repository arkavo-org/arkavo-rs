//! Error types for chain-driven KAS validation.

use thiserror::Error;

/// Errors that can occur during chain validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Session not found: {session_id}")]
    SessionNotFound { session_id: String },

    #[error("Session expired at block {expired_at}, current block {current}")]
    SessionExpired { expired_at: u64, current: u64 },

    #[error("Session has been revoked")]
    SessionRevoked,

    #[error("Resource scope mismatch: resource {resource_id} not in session scope")]
    ScopeMismatch { resource_id: String },

    #[error("Header hash mismatch: client provided {client}, server computed {server}")]
    HeaderHashMismatch { client: String, server: String },

    #[error("Invalid signature: {reason}")]
    SignatureInvalid { reason: String },

    #[error("Nonce already used (replay attack detected)")]
    NonceReplay,

    #[error("Chain error: {0}")]
    Chain(#[from] ChainError),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

/// Errors specific to blockchain connectivity and queries.
#[derive(Debug, Error)]
pub enum ChainError {
    #[error("Failed to connect to chain RPC at {url}: {reason}")]
    ConnectionFailed { url: String, reason: String },

    #[error("Chain node is syncing, cannot trust responses")]
    NodeSyncing,

    #[error("Chain node has no peers, may be isolated")]
    NoPeers,

    #[error("Block height regression: current {current} < expected {expected}")]
    BlockRegression { current: u64, expected: u64 },

    #[error("RPC request failed: {0}")]
    RpcError(String),

    #[error("Failed to decode chain storage: {0}")]
    DecodeError(String),

    #[error("Contract not found at address")]
    ContractNotFound,

    #[error("Storage key not found")]
    StorageKeyNotFound,
}

/// Errors related to cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Cache integrity check failed")]
    IntegrityFailed,

    #[error("Redis operation failed: {0}")]
    RedisError(String),
}

impl From<redis::RedisError> for CacheError {
    fn from(e: redis::RedisError) -> Self {
        CacheError::RedisError(e.to_string())
    }
}
