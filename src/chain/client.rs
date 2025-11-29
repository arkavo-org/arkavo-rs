//! Chain client for arkavo-node blockchain connectivity.
//!
//! This module provides a subxt-based client for querying SessionGrant data
//! from the arkavo-node blockchain's access_registry Ink! contract.

use crate::chain::error::ChainError;
use crate::chain::types::SessionGrant;
use log::{debug, error, info};
use std::sync::atomic::{AtomicU64, Ordering};
use subxt::{OnlineClient, PolkadotConfig};
use tokio::sync::RwLock;

/// Chain client for querying session grants from arkavo-node.
pub struct ChainClient {
    /// The RPC URL for the chain node.
    rpc_url: String,

    /// The subxt online client (lazy-initialized).
    client: RwLock<Option<OnlineClient<PolkadotConfig>>>,

    /// Last known block number for health checking.
    last_known_block: AtomicU64,

    /// Minimum number of peers required for healthy node.
    min_peers: u32,
}

impl ChainClient {
    /// Create a new chain client.
    ///
    /// Connection is established lazily on first query.
    pub fn new(rpc_url: String) -> Self {
        Self {
            rpc_url,
            client: RwLock::new(None),
            last_known_block: AtomicU64::new(0),
            min_peers: 1,
        }
    }

    /// Connect to the chain node.
    pub async fn connect(&self) -> Result<(), ChainError> {
        info!("Connecting to chain RPC at {}", self.rpc_url);

        let client = OnlineClient::<PolkadotConfig>::from_url(&self.rpc_url)
            .await
            .map_err(|e| ChainError::ConnectionFailed {
                url: self.rpc_url.clone(),
                reason: e.to_string(),
            })?;

        // Validate node health on connect
        self.validate_node_health_internal(&client).await?;

        let mut guard = self.client.write().await;
        *guard = Some(client);

        info!("Successfully connected to chain at {}", self.rpc_url);
        Ok(())
    }

    /// Get or create the client connection.
    async fn get_client(&self) -> Result<OnlineClient<PolkadotConfig>, ChainError> {
        // Try to get existing client
        {
            let guard = self.client.read().await;
            if let Some(client) = guard.as_ref() {
                return Ok(client.clone());
            }
        }

        // Need to connect
        self.connect().await?;

        let guard = self.client.read().await;
        guard.clone().ok_or_else(|| ChainError::ConnectionFailed {
            url: self.rpc_url.clone(),
            reason: "Failed to establish connection".to_string(),
        })
    }

    /// Get the current block number.
    pub async fn current_block(&self) -> Result<u64, ChainError> {
        let client = self.get_client().await?;

        let block = client
            .blocks()
            .at_latest()
            .await
            .map_err(|e| ChainError::RpcError(e.to_string()))?;

        let block_number = block.number() as u64;
        self.last_known_block.store(block_number, Ordering::Relaxed);

        Ok(block_number)
    }

    /// Query a session grant from the chain.
    ///
    /// This queries the access_registry contract's storage for the session.
    pub async fn get_session_grant(
        &self,
        session_id: &[u8; 32],
    ) -> Result<Option<SessionGrant>, ChainError> {
        let client = self.get_client().await?;

        // Validate node health before querying
        self.validate_node_health_internal(&client).await?;

        // Query contract storage
        // Note: This is a simplified implementation. In production, you would
        // use subxt's contract API with the proper contract metadata/ABI.
        let storage_key = self.compute_session_storage_key(session_id);

        debug!(
            "Querying session {} with storage key {}",
            hex::encode(session_id),
            hex::encode(&storage_key)
        );

        let block = client
            .blocks()
            .at_latest()
            .await
            .map_err(|e| ChainError::RpcError(e.to_string()))?;

        // Query raw storage
        let storage_data = block
            .storage()
            .fetch_raw(storage_key)
            .await
            .map_err(|e| ChainError::RpcError(e.to_string()))?;

        match storage_data {
            Some(data) => {
                let grant = self.decode_session_grant(session_id, &data)?;
                Ok(Some(grant))
            }
            None => Ok(None),
        }
    }

    /// Validate that the chain node is healthy and synced.
    pub async fn validate_node_health(&self) -> Result<(), ChainError> {
        let client = self.get_client().await?;
        self.validate_node_health_internal(&client).await
    }

    /// Internal health validation.
    async fn validate_node_health_internal(
        &self,
        client: &OnlineClient<PolkadotConfig>,
    ) -> Result<(), ChainError> {
        // Check block height is progressing (simplified health check)
        let block = client
            .blocks()
            .at_latest()
            .await
            .map_err(|e| ChainError::RpcError(e.to_string()))?;

        let current_block = block.number() as u64;
        let last_known = self.last_known_block.load(Ordering::Relaxed);

        // Allow some margin for block time variance
        if last_known > 0 && current_block + 2 < last_known {
            error!(
                "Block regression detected: current {} < last known {}",
                current_block, last_known
            );
            return Err(ChainError::BlockRegression {
                current: current_block,
                expected: last_known,
            });
        }

        self.last_known_block
            .store(current_block, Ordering::Relaxed);
        debug!("Node health OK: block {}", current_block);

        Ok(())
    }

    /// Compute the storage key for a session in the access_registry Ink! contract.
    ///
    /// For Ink! Mapping storage, the key is computed as:
    /// blake2_256(storage_slot_le_bytes ++ SCALE_encoded_map_key)
    ///
    /// Storage slot 1 corresponds to the `sessions` field (second field in contract storage,
    /// after `entitlements`).
    fn compute_session_storage_key(&self, session_id: &[u8; 32]) -> Vec<u8> {
        use blake2::{digest::consts::U32, Blake2b, Digest};
        use scale::Encode;

        // Ink! assigns storage keys based on field order in the contract struct.
        // Storage slot for "sessions" field (second field after entitlements).
        let storage_slot: u32 = 1;

        let mut key_data = Vec::new();
        key_data.extend_from_slice(&storage_slot.to_le_bytes());
        key_data.extend_from_slice(&session_id.encode());

        // Blake2-256 hash of the combined key
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(&key_data);
        let result = hasher.finalize();

        result.to_vec()
    }

    /// Compute TwoX 128-bit hash (Substrate standard for pallet/field names).
    #[allow(dead_code)]
    fn twox_128(data: &[u8]) -> [u8; 16] {
        use std::hash::Hasher;
        use twox_hash::XxHash64;

        // TwoX128 = XxHash64(seed=0) || XxHash64(seed=1)
        let mut h0 = XxHash64::with_seed(0);
        let mut h1 = XxHash64::with_seed(1);
        h0.write(data);
        h1.write(data);

        let r0 = h0.finish();
        let r1 = h1.finish();

        let mut result = [0u8; 16];
        result[..8].copy_from_slice(&r0.to_le_bytes());
        result[8..].copy_from_slice(&r1.to_le_bytes());
        result
    }

    /// Compute Blake2b 128-bit hash.
    #[allow(dead_code)]
    fn blake2_128(data: &[u8]) -> [u8; 16] {
        use blake2::{digest::consts::U16, Blake2b, Digest};

        let mut hasher = Blake2b::<U16>::new();
        hasher.update(data);
        let result = hasher.finalize();

        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&result);
        bytes
    }

    /// Decode a SessionGrant from SCALE-encoded storage data.
    fn decode_session_grant(
        &self,
        session_id: &[u8; 32],
        data: &[u8],
    ) -> Result<SessionGrant, ChainError> {
        use scale::Decode;

        // Decode the session grant structure
        // Note: This assumes the chain storage format matches our SessionGrant
        #[derive(Decode)]
        struct ChainSessionGrant {
            eph_pub_key: Vec<u8>,
            scope_id: [u8; 32],
            expires_at_block: u64,
            is_revoked: bool,
            created_at_block: u64,
        }

        let chain_grant = ChainSessionGrant::decode(&mut &data[..])
            .map_err(|e| ChainError::DecodeError(e.to_string()))?;

        Ok(SessionGrant {
            session_id: *session_id,
            eph_pub_key: chain_grant.eph_pub_key,
            scope_id: chain_grant.scope_id,
            expires_at_block: chain_grant.expires_at_block,
            is_revoked: chain_grant.is_revoked,
            created_at_block: chain_grant.created_at_block,
        })
    }
}

impl std::fmt::Debug for ChainClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainClient")
            .field("rpc_url", &self.rpc_url)
            .field(
                "last_known_block",
                &self.last_known_block.load(Ordering::Relaxed),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_key_computation() {
        let client = ChainClient::new("ws://localhost:9944".to_string());
        let session_id = [0xABu8; 32];
        let key = client.compute_session_storage_key(&session_id);

        // Ink! Mapping storage key is a 32-byte blake2_256 hash
        assert_eq!(key.len(), 32);

        // Verify deterministic output
        let key2 = client.compute_session_storage_key(&session_id);
        assert_eq!(key, key2);

        // Different session_id should produce different key
        let other_session_id = [0xCDu8; 32];
        let other_key = client.compute_session_storage_key(&other_session_id);
        assert_ne!(key, other_key);
    }

    #[test]
    fn test_twox_128() {
        // Test the twox_128 helper function
        let data = b"test_data";
        let hash = ChainClient::twox_128(data);
        assert_eq!(hash.len(), 16);

        // Verify deterministic output
        let hash2 = ChainClient::twox_128(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_blake2_128() {
        // Test the blake2_128 helper function
        let data = b"test_data";
        let hash = ChainClient::blake2_128(data);
        assert_eq!(hash.len(), 16);

        // Verify deterministic output
        let hash2 = ChainClient::blake2_128(data);
        assert_eq!(hash, hash2);
    }
}
