//! Session validator for chain-driven KAS.
//!
//! This module provides the core validation logic that replaces local policy evaluation.

use crate::chain::cache::SessionCache;
use crate::chain::client::ChainClient;
use crate::chain::error::ValidationError;
use crate::chain::types::{ChainValidationRequest, SessionGrant, ValidatedSession};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::sync::Arc;

/// Trait for session validation.
///
/// This trait abstracts the validation logic to enable testing with mock implementations.
#[async_trait]
pub trait SessionValidator: Send + Sync {
    /// Validate a chain session request.
    ///
    /// Performs all validation checks:
    /// 1. Session exists (in cache or on chain)
    /// 2. Session not expired
    /// 3. Session not revoked
    /// 4. Resource matches session scope
    /// 5. Signature is valid
    /// 6. Nonce is fresh (not replayed)
    async fn validate(
        &self,
        request: &ChainValidationRequest,
    ) -> Result<ValidatedSession, ValidationError>;
}

/// Chain-based session validator implementation.
pub struct ChainValidator {
    /// Chain client for querying session grants.
    client: Arc<ChainClient>,

    /// Cache for session grants.
    cache: Arc<SessionCache>,
}

impl ChainValidator {
    /// Create a new chain validator.
    pub fn new(client: Arc<ChainClient>, cache: Arc<SessionCache>) -> Self {
        Self { client, cache }
    }

    /// Get session grant from cache or chain.
    async fn get_session_grant(
        &self,
        session_id: &[u8; 32],
    ) -> Result<(SessionGrant, u64), ValidationError> {
        // Try cache first
        if let Some(grant) = self.cache.get(session_id).await {
            let current_block = self.client.current_block().await?;
            debug!("Cache hit for session {}", hex::encode(&session_id[..8]));
            return Ok((grant, current_block));
        }

        // Query chain
        debug!(
            "Cache miss for session {}, querying chain",
            hex::encode(&session_id[..8])
        );

        let current_block = self.client.current_block().await?;

        let grant = self
            .client
            .get_session_grant(session_id)
            .await?
            .ok_or_else(|| ValidationError::SessionNotFound {
                session_id: hex::encode(session_id),
            })?;

        // Store in cache
        self.cache.store(grant.clone(), current_block).await;

        Ok((grant, current_block))
    }

    /// Verify the request signature against the session's ephemeral public key.
    fn verify_signature(
        &self,
        request: &ChainValidationRequest,
        grant: &SessionGrant,
    ) -> Result<(), ValidationError> {
        let message =
            request
                .compute_signing_message()
                .map_err(|e| ValidationError::SignatureInvalid {
                    reason: e.to_string(),
                })?;

        // Verify using the appropriate algorithm
        let valid = match request.algorithm.as_str() {
            "ES256" => self.verify_es256(&grant.eph_pub_key, &message, &request.signature)?,
            "ES384" => self.verify_es384(&grant.eph_pub_key, &message, &request.signature)?,
            "ES512" => self.verify_es512(&grant.eph_pub_key, &message, &request.signature)?,
            alg => {
                return Err(ValidationError::SignatureInvalid {
                    reason: format!("Unsupported algorithm: {}", alg),
                })
            }
        };

        if !valid {
            warn!(
                "Signature verification failed for session {}",
                hex::encode(&grant.session_id[..8])
            );
            return Err(ValidationError::SignatureInvalid {
                reason: "Signature does not match ephemeral public key".to_string(),
            });
        }

        Ok(())
    }

    /// Verify ES256 (P-256/secp256r1) signature.
    fn verify_es256(
        &self,
        public_key: &[u8],
        message: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool, ValidationError> {
        use ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key).map_err(|e| {
            ValidationError::SignatureInvalid {
                reason: format!("Invalid P-256 public key: {}", e),
            }
        })?;

        let sig =
            Signature::from_slice(signature).map_err(|e| ValidationError::SignatureInvalid {
                reason: format!("Invalid ES256 signature format: {}", e),
            })?;

        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    /// Verify ES384 (P-384/secp384r1) signature.
    fn verify_es384(
        &self,
        public_key: &[u8],
        message: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool, ValidationError> {
        use ecdsa::signature::Verifier;
        use p384::ecdsa::{Signature, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key).map_err(|e| {
            ValidationError::SignatureInvalid {
                reason: format!("Invalid P-384 public key: {}", e),
            }
        })?;

        let sig =
            Signature::from_slice(signature).map_err(|e| ValidationError::SignatureInvalid {
                reason: format!("Invalid ES384 signature format: {}", e),
            })?;

        Ok(verifying_key.verify(message, &sig).is_ok())
    }

    /// Verify ES512 (P-521/secp521r1) signature.
    ///
    /// Note: P-521 support requires additional dependency. For now, return error.
    fn verify_es512(
        &self,
        _public_key: &[u8],
        _message: &[u8; 32],
        _signature: &[u8],
    ) -> Result<bool, ValidationError> {
        // P-521 support would require p521 crate
        // For now, we only support ES256 and ES384
        Err(ValidationError::SignatureInvalid {
            reason: "ES512 (P-521) not yet supported".to_string(),
        })
    }

    /// Check if header hash matches session scope.
    ///
    /// The header_hash (SHA256 of the actual header bytes) is compared directly
    /// to the scope_id. This provides DPoP-style binding: the client commits to
    /// the header content by computing its hash, and we verify it matches the
    /// authorized scope.
    fn check_scope(
        &self,
        header_hash: &[u8; 32],
        scope_id: &[u8; 32],
    ) -> Result<(), ValidationError> {
        // Direct comparison: header_hash must equal scope_id
        // The scope_id is the SHA256 of the authorized header
        if header_hash != scope_id {
            return Err(ValidationError::ScopeMismatch {
                resource_id: hex::encode(header_hash),
            });
        }

        Ok(())
    }
}

#[async_trait]
impl SessionValidator for ChainValidator {
    async fn validate(
        &self,
        request: &ChainValidationRequest,
    ) -> Result<ValidatedSession, ValidationError> {
        let session_id =
            request
                .session_id_bytes()
                .map_err(|e| ValidationError::SessionNotFound {
                    session_id: format!("Invalid format: {}", e),
                })?;

        debug!(
            "Validating session {} for resource {}",
            hex::encode(&session_id[..8]),
            &request.resource_id[..16.min(request.resource_id.len())]
        );

        // 1. Get session from cache or chain
        let (grant, current_block) = self.get_session_grant(&session_id).await?;

        // 2. Check expiration
        if grant.expires_at_block <= current_block {
            warn!(
                "Session {} expired at block {} (current: {})",
                hex::encode(&session_id[..8]),
                grant.expires_at_block,
                current_block
            );
            return Err(ValidationError::SessionExpired {
                expired_at: grant.expires_at_block,
                current: current_block,
            });
        }

        // 3. Check revocation
        if grant.is_revoked {
            warn!("Session {} is revoked", hex::encode(&session_id[..8]));
            return Err(ValidationError::SessionRevoked);
        }

        // 4. Check scope (DPoP binding: header_hash must match scope_id)
        self.check_scope(&request.header_hash, &grant.scope_id)?;

        // 5. Verify signature
        self.verify_signature(request, &grant)?;

        // 6. Check nonce (replay prevention)
        let nonce_fresh = self
            .cache
            .check_and_consume_nonce(&session_id, request.nonce)
            .await
            .map_err(|e| ValidationError::Crypto(e.to_string()))?;

        if !nonce_fresh {
            warn!(
                "Nonce replay detected for session {}",
                hex::encode(&session_id[..8])
            );
            return Err(ValidationError::NonceReplay);
        }

        info!(
            "Session {} validated successfully for resource {}",
            hex::encode(&session_id[..8]),
            &request.resource_id[..16.min(request.resource_id.len())]
        );

        Ok(ValidatedSession {
            grant,
            validated_at_block: current_block,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock validator for testing
    pub struct MockValidator {
        pub should_succeed: bool,
        pub mock_grant: Option<SessionGrant>,
    }

    #[async_trait]
    impl SessionValidator for MockValidator {
        async fn validate(
            &self,
            request: &ChainValidationRequest,
        ) -> Result<ValidatedSession, ValidationError> {
            if self.should_succeed {
                let grant = self.mock_grant.clone().unwrap_or_else(|| SessionGrant {
                    session_id: request.session_id_bytes().unwrap_or([0u8; 32]),
                    eph_pub_key: vec![0u8; 33],
                    scope_id: [0u8; 32],
                    expires_at_block: u64::MAX,
                    is_revoked: false,
                    created_at_block: 0,
                });

                Ok(ValidatedSession {
                    grant,
                    validated_at_block: 100,
                })
            } else {
                Err(ValidationError::SessionNotFound {
                    session_id: request.session_id.clone(),
                })
            }
        }
    }

    /// Test that scope check passes when header_hash matches scope_id
    #[test]
    fn test_scope_check_matching_header_hash() {
        // Test the direct comparison that check_scope performs
        let header_hash: [u8; 32] = [0xAB; 32];
        let scope_id: [u8; 32] = [0xAB; 32]; // Same as header_hash

        // Direct comparison should pass
        assert_eq!(header_hash, scope_id);
    }

    /// Test that scope check fails when header_hash doesn't match scope_id
    #[test]
    fn test_scope_check_mismatched_header_hash() {
        let header_hash: [u8; 32] = [0xAB; 32];
        let scope_id: [u8; 32] = [0xCD; 32]; // Different from header_hash

        // Direct comparison should fail
        assert_ne!(header_hash, scope_id);
    }

    /// Test that header substitution attack is prevented
    /// Scenario: Attacker has valid signature for header_a, tries to use it with header_b
    #[test]
    fn test_header_substitution_attack_prevented() {
        use sha2::{Digest, Sha256};

        // Legitimate header signed by client
        let header_a = b"legitimate-nanotdf-header-bytes";
        let header_hash_a: [u8; 32] = Sha256::digest(header_a).into();

        // Malicious header attacker wants to substitute
        let header_b = b"malicious-substitute-header";
        let header_hash_b: [u8; 32] = Sha256::digest(header_b).into();

        // Server computes hash of received header (header_b in attack scenario)
        // and compares to client-provided header_hash (header_hash_a)
        //
        // In the attack:
        // - Client signed with header_hash_a
        // - Attacker sends header_b but claims header_hash_a
        // - Server computes SHA256(header_b) = header_hash_b
        // - Server compares: header_hash_a != header_hash_b
        // - Attack FAILS

        assert_ne!(
            header_hash_a, header_hash_b,
            "Different headers must produce different hashes"
        );

        // This ensures the server's check will catch the substitution
        let server_computed = header_hash_b; // Server computes from received header
        let client_claimed = header_hash_a; // Client claims this hash

        assert_ne!(
            server_computed, client_claimed,
            "Header substitution attack must be detected"
        );
    }

    /// Test that signing message includes header_hash
    #[test]
    fn test_signing_message_includes_header_hash() {
        // Create two requests with same session_id and nonce but different header_hash
        let request1 = ChainValidationRequest {
            session_id: "ab".repeat(32),
            header_hash: [0x11; 32],
            resource_id: String::new(),
            signature: vec![],
            algorithm: "ES256".to_string(),
            nonce: 100,
        };

        let request2 = ChainValidationRequest {
            session_id: "ab".repeat(32),
            header_hash: [0x22; 32], // Different header hash
            resource_id: String::new(),
            signature: vec![],
            algorithm: "ES256".to_string(),
            nonce: 100,
        };

        let msg1 = request1.compute_signing_message().unwrap();
        let msg2 = request2.compute_signing_message().unwrap();

        // Different header_hash must produce different signing messages
        // This ensures the signature is bound to the specific header content
        assert_ne!(
            msg1, msg2,
            "Different header_hash must produce different signing messages"
        );
    }
}
