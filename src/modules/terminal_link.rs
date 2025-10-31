use chrono::{DateTime, Utc};
use ecdsa::signature::Verifier;
use ecdsa::{Signature, VerifyingKey};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::{error, info, warn};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Terminal Link Claims - outermost JWT wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalLinkClaims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    pub session_id: String,
    pub pe_payload: SignedPayload<PEClaims>,
    pub npe_payload: Option<SignedPayload<NPEClaims>>,
    pub dpop_jti: Option<String>,
}

/// Person Entity Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PEClaims {
    pub user_id: String,
    pub auth_level: AuthLevel,
    pub timestamp: DateTime<Utc>,
    pub did: String,
}

/// Non-Person Entity Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NPEClaims {
    pub platform_code: String,
    pub platform_state: PlatformState,
    pub device_id: String,
    pub app_version: String,
    pub timestamp: DateTime<Utc>,
}

/// Authentication level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthLevel {
    Biometric,
    Password,
    MFA,
    WebAuthn,
}

/// Platform security state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PlatformState {
    Secure,
    Jailbroken,
    DebugMode,
    Unknown,
}

/// Cryptographically signed payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload<T> {
    pub data: T,
    pub signature: String, // Base64URL DER-encoded signature
    pub public_key: String, // Base64URL compressed P-256 public key
    pub timestamp: DateTime<Utc>,
}

/// Result of Terminal Link validation
#[derive(Debug)]
pub enum ValidationResult {
    Valid(ValidatedClaims),
    InvalidSignature(String),
    Expired { exp: i64, now: i64 },
    InvalidIssuer(String),
    MalformedToken(String),
    InvalidPESignature,
    InvalidNPESignature,
}

/// Validated and extracted claims
#[derive(Debug, Clone)]
pub struct ValidatedClaims {
    pub user_id: String,
    pub session_id: String,
    pub auth_level: AuthLevel,
    pub did: String,
    pub device_id: Option<String>,
    pub platform: Option<String>,
    pub platform_state: Option<PlatformState>,
    pub dpop_jti: Option<String>,
}

/// Validate Terminal Link JWT and unwrap nested signatures
pub fn validate_terminal_link(
    token: &str,
    public_key_pem: &[u8],
    expected_issuer: &str,
) -> Result<ValidationResult, Box<dyn std::error::Error>> {
    info!("Validating Terminal Link token");

    // Decode JWT
    let decoding_key = DecodingKey::from_ec_pem(public_key_pem)?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&[expected_issuer]);
    validation.validate_exp = true;

    let token_data = match decode::<TerminalLinkClaims>(token, &decoding_key, &validation) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decode Terminal Link JWT: {}", e);
            return Ok(match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    ValidationResult::Expired {
                        exp: 0,
                        now: Utc::now().timestamp(),
                    }
                }
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    ValidationResult::InvalidIssuer(format!("Expected: {}", expected_issuer))
                }
                _ => ValidationResult::MalformedToken(e.to_string()),
            });
        }
    };

    let claims = token_data.claims;

    info!(
        "Terminal Link JWT valid for user: {} session: {}",
        claims.sub, claims.session_id
    );

    // Verify PE (Person Entity) signature
    if let Err(e) = verify_signed_payload(&claims.pe_payload) {
        warn!("PE signature verification failed: {}", e);
        return Ok(ValidationResult::InvalidPESignature);
    }

    info!("PE signature valid for user: {}", claims.pe_payload.data.user_id);

    // Verify NPE (Non-Person Entity) signature if present
    let (device_id, platform, platform_state) = if let Some(ref npe_payload) = claims.npe_payload {
        if let Err(e) = verify_signed_payload(npe_payload) {
            warn!("NPE signature verification failed: {}", e);
            return Ok(ValidationResult::InvalidNPESignature);
        }

        info!(
            "NPE signature valid for device: {}",
            npe_payload.data.device_id
        );

        (
            Some(npe_payload.data.device_id.clone()),
            Some(npe_payload.data.platform_code.clone()),
            Some(npe_payload.data.platform_state.clone()),
        )
    } else {
        (None, None, None)
    };

    // Extract validated claims
    let validated = ValidatedClaims {
        user_id: claims.pe_payload.data.user_id,
        session_id: claims.session_id,
        auth_level: claims.pe_payload.data.auth_level,
        did: claims.pe_payload.data.did,
        device_id,
        platform,
        platform_state,
        dpop_jti: claims.dpop_jti,
    };

    Ok(ValidationResult::Valid(validated))
}

/// Verify a signed payload's ECDSA signature
fn verify_signed_payload<T: Serialize>(
    payload: &SignedPayload<T>,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // Decode public key from base64url
    let public_key_bytes = URL_SAFE_NO_PAD.decode(&payload.public_key)?;

    // Parse compressed P-256 public key
    let encoded_point = p256::EncodedPoint::from_bytes(&public_key_bytes)?;
    let verifying_key = VerifyingKey::<NistP256>::from_encoded_point(&encoded_point)?;

    // Serialize payload data
    let data_bytes = serde_json::to_vec(&payload.data)?;

    // Hash the data
    let message = Sha256::digest(&data_bytes);

    // Decode signature from base64url
    let signature_bytes = URL_SAFE_NO_PAD.decode(&payload.signature)?;
    let signature = Signature::from_der(&signature_bytes)?;

    // Verify signature
    verifying_key.verify(&message, &signature)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn test_signed_payload_verification() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let pe_claims = PEClaims {
            user_id: "test-user".to_string(),
            auth_level: AuthLevel::WebAuthn,
            timestamp: Utc::now(),
            did: "did:key:test123".to_string(),
        };

        let data_bytes = serde_json::to_vec(&pe_claims).unwrap();
        let message = Sha256::digest(&data_bytes);
        let signature: Signature<NistP256> = signing_key.sign(&message);

        let public_key_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();

        let signed_payload = SignedPayload {
            data: pe_claims,
            signature: URL_SAFE_NO_PAD.encode(&signature.to_der().as_bytes()),
            public_key: URL_SAFE_NO_PAD.encode(&public_key_bytes),
            timestamp: Utc::now(),
        };

        assert!(verify_signed_payload(&signed_payload).is_ok());
    }

    #[test]
    fn test_platform_state_deserialization() {
        let json = r#"{"platform_code":"iOS","platform_state":"secure","device_id":"test","app_version":"1.0.0","timestamp":"2025-10-31T12:00:00Z"}"#;
        let npe: NPEClaims = serde_json::from_str(json).unwrap();
        assert_eq!(npe.platform_state, PlatformState::Secure);
    }
}
