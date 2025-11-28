//! Types for chain-driven KAS validation.

use serde::{Deserialize, Serialize};

/// Session grant from chain storage (matches Ink! contract storage).
///
/// This represents an access session issued by the arkavo-node blockchain.
/// The agent must possess the ephemeral private key corresponding to `eph_pub_key`
/// to prove ownership of the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrant {
    /// Unique session identifier (32 bytes, typically a hash).
    pub session_id: [u8; 32],

    /// Ephemeral public key for this session (33 bytes compressed EC point).
    /// The agent signs requests with the corresponding private key.
    pub eph_pub_key: Vec<u8>,

    /// Resource scope identifier (32 bytes hash).
    /// Defines what resources this session can access.
    pub scope_id: [u8; 32],

    /// Block number when this session expires.
    pub expires_at_block: u64,

    /// Whether this session has been revoked on-chain.
    pub is_revoked: bool,

    /// Block number when this session was created.
    pub created_at_block: u64,
}

/// Chain validation request payload.
///
/// This is the new API format for chain-driven rewrap requests.
#[derive(Debug, Clone)]
pub struct ChainValidationRequest {
    /// Session ID (hex-encoded 32 bytes).
    pub session_id: String,

    /// Resource ID being accessed (hex-encoded).
    pub resource_id: String,

    /// ECDSA signature over the message: Hash(session_id || resource_id || nonce).
    pub signature: Vec<u8>,

    /// Signing algorithm: "ES256", "ES384", or "ES512".
    pub algorithm: String,

    /// Unique nonce for replay prevention.
    pub nonce: u64,
}

impl ChainValidationRequest {
    /// Compute the message that should be signed.
    ///
    /// Message format: SHA256(session_id || resource_id || nonce_le_bytes)
    pub fn compute_signing_message(&self) -> Result<[u8; 32], &'static str> {
        use sha2::{Digest, Sha256};

        let session_bytes = hex::decode(&self.session_id).map_err(|_| "Invalid session_id hex")?;
        let resource_bytes =
            hex::decode(&self.resource_id).map_err(|_| "Invalid resource_id hex")?;

        let mut hasher = Sha256::new();
        hasher.update(&session_bytes);
        hasher.update(&resource_bytes);
        hasher.update(&self.nonce.to_le_bytes());

        Ok(hasher.finalize().into())
    }

    /// Parse session_id as 32-byte array.
    pub fn session_id_bytes(&self) -> Result<[u8; 32], &'static str> {
        let bytes = hex::decode(&self.session_id).map_err(|_| "Invalid session_id hex")?;
        bytes
            .try_into()
            .map_err(|_| "session_id must be 32 bytes")
    }
}

/// Result of successful session validation.
#[derive(Debug, Clone)]
pub struct ValidatedSession {
    /// The validated session grant from chain.
    pub grant: SessionGrant,

    /// Current block number at validation time.
    pub validated_at_block: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_signing_message() {
        let request = ChainValidationRequest {
            session_id: "0".repeat(64), // 32 zero bytes
            resource_id: "1".repeat(64),
            signature: vec![],
            algorithm: "ES256".to_string(),
            nonce: 12345,
        };

        let message = request.compute_signing_message().unwrap();
        assert_eq!(message.len(), 32);
    }

    #[test]
    fn test_session_id_bytes() {
        let request = ChainValidationRequest {
            session_id: "ab".repeat(32), // 32 bytes of 0xAB
            resource_id: String::new(),
            signature: vec![],
            algorithm: "ES256".to_string(),
            nonce: 0,
        };

        let bytes = request.session_id_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|&b| b == 0xAB));
    }
}
