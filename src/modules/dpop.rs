/// DPoP (Demonstrating Proof-of-Possession) validation per RFC 9449
/// https://datatracker.ietf.org/doc/html/rfc9449
///
/// Used with NTDF tokens (Z85-encoded NanoTDF) for proof-of-possession.
/// The `access_token` parameter should be the Z85-encoded NTDF token string.
/// The `ath` claim is validated against SHA-256(Z85_bytes).

use chrono::Utc;
use ecdsa::VerifyingKey;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::{error, info, warn};
use p256::NistP256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// DPoP JWT header
#[derive(Debug, Serialize, Deserialize)]
pub struct DPoPHeader {
    pub typ: String, // Must be "dpop+jwt"
    pub alg: String, // Must be ES256 for ECDSA P-256
    pub jwk: JWK,    // Embedded public key
}

/// JSON Web Key (JWK) for ECDSA P-256
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWK {
    pub kty: String, // "EC"
    pub crv: String, // "P-256"
    pub x: String,   // Base64URL-encoded x-coordinate
    pub y: String,   // Base64URL-encoded y-coordinate
}

/// DPoP JWT claims
#[derive(Debug, Serialize, Deserialize)]
pub struct DPoPClaims {
    pub jti: String,      // Unique identifier (UUID)
    pub htm: String,      // HTTP method (POST, GET, etc.)
    pub htu: String,      // HTTP URI (without query/fragment)
    pub iat: i64,         // Issued at timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>, // Access token hash (base64url(SHA256(access_token)))
}

/// Result of DPoP validation
#[derive(Debug)]
pub enum DPoPValidationResult {
    Valid {
        jti: String,
        jwk_thumbprint: String,
    },
    InvalidType,
    InvalidAlgorithm,
    MethodMismatch {
        expected: String,
        actual: String,
    },
    URIMismatch {
        expected: String,
        actual: String,
    },
    TokenHashMismatch,
    Expired {
        iat: i64,
        now: i64,
    },
    InvalidSignature,
    MalformedProof(String),
    JWKMismatch,
}

/// Validate a DPoP proof
pub fn validate_dpop_proof(
    dpop_proof: &str,
    http_method: &str,
    http_uri: &str,
    access_token: Option<&str>,
    max_age_seconds: i64,
) -> Result<DPoPValidationResult, Box<dyn std::error::Error>> {
    info!(
        "Validating DPoP proof for {} {}",
        http_method, http_uri
    );

    // Decode without verification first to get the header
    let header = jsonwebtoken::decode_header(dpop_proof)?;

    // Verify typ is "dpop+jwt"
    if let Some(typ) = &header.typ {
        if typ != "dpop+jwt" {
            warn!("Invalid DPoP type: {}", typ);
            return Ok(DPoPValidationResult::InvalidType);
        }
    } else {
        warn!("Missing typ header in DPoP proof");
        return Ok(DPoPValidationResult::InvalidType);
    }

    // Verify algorithm is ES256
    if header.alg != Algorithm::ES256 {
        warn!("Invalid DPoP algorithm: {:?}", header.alg);
        return Ok(DPoPValidationResult::InvalidAlgorithm);
    }

    // Extract JWK from JWT (manual parsing)
    let jwk = extract_jwk_from_jwt(dpop_proof)?;

    // Verify JWK is ECDSA P-256
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        warn!("Invalid JWK: kty={}, crv={}", jwk.kty, jwk.crv);
        return Ok(DPoPValidationResult::MalformedProof(
            "JWK must be EC P-256".to_string(),
        ));
    }

    // Construct public key from JWK
    let public_key = construct_public_key_from_jwk(&jwk)?;

    // Decode and verify JWT signature
    let decoding_key = DecodingKey::from_ec_pem(&public_key)?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false; // DPoP doesn't use exp, we check iat manually
    validation.validate_nbf = false;
    validation.set_required_spec_claims(&["jti", "htm", "htu", "iat"]);

    let token_data = match decode::<DPoPClaims>(dpop_proof, &decoding_key, &validation) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decode DPoP proof: {}", e);
            return Ok(DPoPValidationResult::InvalidSignature);
        }
    };

    let claims = token_data.claims;

    info!("DPoP proof decoded successfully, jti={}", claims.jti);

    // Verify timestamp freshness (default: 60 seconds)
    let now = Utc::now().timestamp();
    if now - claims.iat > max_age_seconds {
        warn!(
            "DPoP proof is too old: iat={}, now={}, age={}s",
            claims.iat,
            now,
            now - claims.iat
        );
        return Ok(DPoPValidationResult::Expired {
            iat: claims.iat,
            now,
        });
    }

    // Verify HTTP method matches
    if claims.htm.to_uppercase() != http_method.to_uppercase() {
        warn!(
            "DPoP HTTP method mismatch: expected={}, actual={}",
            http_method, claims.htm
        );
        return Ok(DPoPValidationResult::MethodMismatch {
            expected: http_method.to_string(),
            actual: claims.htm,
        });
    }

    // Verify HTTP URI matches (without query/fragment)
    let normalized_uri = normalize_uri(http_uri);
    let normalized_htu = normalize_uri(&claims.htu);
    if normalized_uri != normalized_htu {
        warn!(
            "DPoP HTTP URI mismatch: expected={}, actual={}",
            normalized_uri, normalized_htu
        );
        return Ok(DPoPValidationResult::URIMismatch {
            expected: normalized_uri,
            actual: normalized_htu,
        });
    }

    // Verify access token hash if present
    if let Some(access_token) = access_token {
        if let Some(ath) = &claims.ath {
            let expected_hash = compute_access_token_hash(access_token);
            if ath != &expected_hash {
                warn!("DPoP access token hash mismatch");
                return Ok(DPoPValidationResult::TokenHashMismatch);
            }
        }
    }

    // Calculate JWK thumbprint (for binding validation)
    let jwk_thumbprint = calculate_jwk_thumbprint(&jwk)?;

    info!(
        "DPoP proof valid: jti={}, thumbprint={}",
        claims.jti, jwk_thumbprint
    );

    Ok(DPoPValidationResult::Valid {
        jti: claims.jti,
        jwk_thumbprint,
    })
}

/// Extract JWK from JWT header by manually parsing the JWT
fn extract_jwk_from_jwt(dpop_proof: &str) -> Result<JWK, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // JWT format: header.payload.signature
    let parts: Vec<&str> = dpop_proof.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".into());
    }

    // Decode header
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes)?;

    // Extract JWK from header
    let jwk_obj = header_json
        .get("jwk")
        .ok_or("Missing jwk in header")?;

    Ok(JWK {
        kty: jwk_obj
            .get("kty")
            .and_then(|v| v.as_str())
            .ok_or("Missing kty")?
            .to_string(),
        crv: jwk_obj
            .get("crv")
            .and_then(|v| v.as_str())
            .ok_or("Missing crv")?
            .to_string(),
        x: jwk_obj
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or("Missing x")?
            .to_string(),
        y: jwk_obj
            .get("y")
            .and_then(|v| v.as_str())
            .ok_or("Missing y")?
            .to_string(),
    })
}

/// Construct PEM-encoded public key from JWK
fn construct_public_key_from_jwk(jwk: &JWK) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // Decode x and y coordinates
    let x_bytes = URL_SAFE_NO_PAD.decode(&jwk.x)?;
    let y_bytes = URL_SAFE_NO_PAD.decode(&jwk.y)?;

    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err("Invalid coordinate length".into());
    }

    // Construct uncompressed point: 0x04 || x || y
    let mut point_bytes = vec![0x04];
    point_bytes.extend_from_slice(&x_bytes);
    point_bytes.extend_from_slice(&y_bytes);

    // Parse as P-256 point
    let encoded_point = p256::EncodedPoint::from_bytes(&point_bytes)?;
    let verifying_key = VerifyingKey::<NistP256>::from_encoded_point(&encoded_point)?;

    // Convert to PEM using pem::encode_config
    let public_key_der = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let pem_string = pem::encode(&pem::Pem::new("PUBLIC KEY", public_key_der));

    Ok(pem_string.as_bytes().to_vec())
}

/// Normalize URI by removing query and fragment
fn normalize_uri(uri: &str) -> String {
    uri.split('?').next().unwrap_or(uri).split('#').next().unwrap_or(uri).to_string()
}

/// Compute SHA-256 hash of access token, base64url-encoded
fn compute_access_token_hash(access_token: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let hash = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Calculate JWK thumbprint per RFC 7638
fn calculate_jwk_thumbprint(jwk: &JWK) -> Result<String, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // Canonical JSON representation (lexicographically sorted)
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );

    let hash = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_uri() {
        assert_eq!(
            normalize_uri("https://example.com/path?query=1"),
            "https://example.com/path"
        );
        assert_eq!(
            normalize_uri("https://example.com/path#fragment"),
            "https://example.com/path"
        );
        assert_eq!(
            normalize_uri("https://example.com/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_compute_access_token_hash() {
        let hash = compute_access_token_hash("test-token");
        assert!(!hash.is_empty());
        // Verify it's base64url (no padding)
        assert!(!hash.contains('='));
    }

    #[test]
    fn test_jwk_thumbprint() {
        let jwk = JWK {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "test_x".to_string(),
            y: "test_y".to_string(),
        };
        let thumbprint = calculate_jwk_thumbprint(&jwk).unwrap();
        assert!(!thumbprint.is_empty());
        assert!(!thumbprint.contains('='));
    }
}
