//! Session validator for chain-driven KAS.
//!
//! This module provides the core validation logic that replaces local policy evaluation.

use crate::chain::cache::SessionCache;
use crate::chain::client::ChainClient;
use crate::chain::error::ValidationError;
use crate::chain::types::{ChainValidationRequest, SessionGrant, ValidatedSession};
use async_trait::async_trait;
use log::{debug, info, warn};
use sha2::{Digest, Sha256};
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
            debug!(
                "Cache hit for session {}",
                hex::encode(&session_id[..8])
            );
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
        let message = request
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

        let sig = Signature::from_slice(signature).map_err(|e| ValidationError::SignatureInvalid {
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

        let sig = Signature::from_slice(signature).map_err(|e| ValidationError::SignatureInvalid {
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

    /// Check if resource matches session scope.
    fn check_scope(&self, resource_id: &str, scope_id: &[u8; 32]) -> Result<(), ValidationError> {
        // Compute resource hash and compare to scope
        let resource_bytes = hex::decode(resource_id).map_err(|_| ValidationError::ScopeMismatch {
            resource_id: resource_id.to_string(),
        })?;

        let resource_hash: [u8; 32] = Sha256::digest(&resource_bytes).into();

        // Simple scope check: resource hash must equal scope_id
        // In production, this could be extended to support merkle proofs
        // for multiple resources within a scope.
        if resource_hash != *scope_id {
            return Err(ValidationError::ScopeMismatch {
                resource_id: resource_id.to_string(),
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
        let session_id = request.session_id_bytes().map_err(|e| {
            ValidationError::SessionNotFound {
                session_id: format!("Invalid format: {}", e),
            }
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

        // 4. Check scope
        self.check_scope(&request.resource_id, &grant.scope_id)?;

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
}
