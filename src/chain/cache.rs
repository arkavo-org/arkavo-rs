//! Session grant cache with 6-second TTL for chain queries.
//!
//! This module provides a short-lived cache for SessionGrant data to reduce
//! RPC load while maintaining acceptable revocation propagation times.

use crate::chain::error::CacheError;
use crate::chain::types::SessionGrant;
use moka::future::Cache;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

/// Cache TTL in seconds (one Substrate block time).
const CACHE_TTL_SECONDS: u64 = 6;

/// Redis key prefix for nonce tracking.
const NONCE_KEY_PREFIX: &str = "chain:nonce:";

/// Session cache with in-memory LRU and nonce tracking via Redis.
pub struct SessionCache {
    /// In-memory cache for SessionGrant data.
    cache: Cache<[u8; 32], CachedEntry>,

    /// Server secret for HMAC integrity tags.
    server_secret: [u8; 32],

    /// Redis client for nonce tracking.
    redis_client: Arc<redis::Client>,
}

/// A cached session grant with integrity protection.
#[derive(Clone)]
struct CachedEntry {
    grant: SessionGrant,
    block_number: u64,
    integrity_tag: [u8; 32],
}

impl SessionCache {
    /// Create a new session cache.
    ///
    /// # Arguments
    /// * `server_secret` - 32-byte secret for HMAC integrity tags
    /// * `redis_client` - Redis client for nonce tracking
    pub fn new(server_secret: [u8; 32], redis_client: Arc<redis::Client>) -> Self {
        let cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(CACHE_TTL_SECONDS))
            .build();

        Self {
            cache,
            server_secret,
            redis_client,
        }
    }

    /// Store a session grant in the cache.
    pub async fn store(&self, grant: SessionGrant, block_number: u64) {
        let tag = self.compute_integrity_tag(&grant, block_number);
        let entry = CachedEntry {
            grant,
            block_number,
            integrity_tag: tag,
        };
        self.cache.insert(entry.grant.session_id, entry).await;
    }

    /// Retrieve a session grant from the cache.
    ///
    /// Returns `None` if not found or integrity check fails.
    pub async fn get(&self, session_id: &[u8; 32]) -> Option<SessionGrant> {
        let entry = self.cache.get(session_id).await?;

        // Verify integrity tag
        let expected_tag = self.compute_integrity_tag(&entry.grant, entry.block_number);
        if !constant_time_eq(&entry.integrity_tag, &expected_tag) {
            // Integrity check failed - remove from cache
            self.cache.invalidate(session_id).await;
            return None;
        }

        Some(entry.grant)
    }

    /// Invalidate a specific session in the cache.
    pub async fn invalidate(&self, session_id: &[u8; 32]) {
        self.cache.invalidate(session_id).await;
    }

    /// Check if a nonce has been used and mark it as used if not.
    ///
    /// Returns `true` if the nonce was fresh (not seen before).
    /// Returns `false` if the nonce was already used (replay attack).
    pub async fn check_and_consume_nonce(
        &self,
        session_id: &[u8; 32],
        nonce: u64,
    ) -> Result<bool, CacheError> {
        let key = format!("{}{}:{}", NONCE_KEY_PREFIX, hex::encode(session_id), nonce);

        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;

        // SETNX with TTL - atomic check-and-set
        // TTL of 5 minutes should be enough to prevent replays within session lifetime
        let result: bool = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX") // Only set if not exists
            .arg("EX")
            .arg(300u64) // 5 minute TTL
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::RedisError(e.to_string()))?;

        Ok(result)
    }

    /// Compute HMAC integrity tag for a cached entry.
    fn compute_integrity_tag(&self, grant: &SessionGrant, block_number: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.server_secret);
        hasher.update(grant.session_id);
        hasher.update(&grant.eph_pub_key);
        hasher.update(grant.scope_id);
        hasher.update(grant.expires_at_block.to_le_bytes());
        hasher.update([grant.is_revoked as u8]);
        hasher.update(grant.created_at_block.to_le_bytes());
        hasher.update(block_number.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1u8, 2, 3]));
    }
}
