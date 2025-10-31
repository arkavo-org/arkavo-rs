/// NTDF Token - NanoTDF-based authentication token
///
/// Replaces JWT Bearer tokens with NanoTDF format for:
/// - Policy binding
/// - Provenance tracking
/// - Optional confidentiality
/// - DPoP proof-of-possession binding
///
/// Wire Format: Authorization: NTDF <Z85-encoded-nanotdf>

use crate::modules::crypto;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use chrono::Utc;
use hkdf::Hkdf;
use log::{info, warn};
use nanotdf::BinaryParser;
use p256::{EncodedPoint, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Cursor;

/// NTDF Token payload (encrypted with AEAD, AAD = Header||Policy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtdfTokenPayload {
    /// Subject ID (user UUID)
    pub sub_id: [u8; 16],

    /// Capability flags bitfield
    pub flags: u64,

    /// OAuth scopes
    pub scopes: Vec<String>,

    /// Custom attributes (type, value) pairs
    pub attrs: Vec<(u8, u32)>,

    /// DPoP JTI for binding (prevents token theft)
    pub dpop_jti: Option<[u8; 16]>,

    /// Issued at timestamp
    pub iat: i64,

    /// Expiration timestamp
    pub exp: i64,

    /// Audience (target service)
    pub aud: String,

    /// Session ID for tracking
    pub session_id: Option<[u8; 16]>,

    /// Device ID from NPE attestation
    pub device_id: Option<String>,

    /// DID (Decentralized Identifier)
    pub did: Option<String>,
}

/// Capability flags for NTDF tokens
pub mod capability_flags {
    /// User can access profile data
    pub const PROFILE: u64 = 1 << 0;

    /// OpenID Connect authentication
    pub const OPENID: u64 = 1 << 1;

    /// Email access
    pub const EMAIL: u64 = 1 << 2;

    /// Offline access (refresh token)
    pub const OFFLINE_ACCESS: u64 = 1 << 3;

    /// Device attestation present
    pub const DEVICE_ATTESTED: u64 = 1 << 4;

    /// Biometric authentication used
    pub const BIOMETRIC_AUTH: u64 = 1 << 5;

    /// WebAuthn/Passkey authentication
    pub const WEBAUTHN: u64 = 1 << 6;

    /// Platform secure (not jailbroken/rooted)
    pub const PLATFORM_SECURE: u64 = 1 << 7;
}

/// Attribute types for custom claims
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    /// Age for content rating
    Age = 0,

    /// User tier (free=0, basic=1, premium=2)
    SubscriptionTier = 1,

    /// Security level (baseline=0, main=1, high=2)
    SecurityLevel = 2,

    /// Platform code (iOS=0, Android=1, macOS=2, etc.)
    PlatformCode = 3,
}

/// Result of NTDF token validation
#[derive(Debug)]
pub enum ValidationResult {
    Valid(ValidatedNtdfToken),
    InvalidFormat(String),
    InvalidSignature,
    Expired { exp: i64, now: i64 },
    InvalidAudience { expected: String, actual: String },
    DecryptionFailed(String),
    PolicyViolation(String),
}

/// Validated NTDF token claims
#[derive(Debug, Clone)]
pub struct ValidatedNtdfToken {
    pub sub_id: [u8; 16],
    pub session_id: Option<[u8; 16]>,
    pub flags: u64,
    pub scopes: Vec<String>,
    pub dpop_jti: Option<[u8; 16]>,
    pub device_id: Option<String>,
    pub did: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

impl NtdfTokenPayload {
    /// Serialize payload to bytes (before encryption)
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();

        // sub_id (16 bytes)
        bytes.extend_from_slice(&self.sub_id);

        // flags (8 bytes, little-endian)
        bytes.extend_from_slice(&self.flags.to_le_bytes());

        // scopes_count (2 bytes)
        bytes.extend_from_slice(&(self.scopes.len() as u16).to_le_bytes());

        // scopes (length-prefixed strings)
        for scope in &self.scopes {
            let scope_bytes = scope.as_bytes();
            bytes.push(scope_bytes.len() as u8);
            bytes.extend_from_slice(scope_bytes);
        }

        // attrs_count (2 bytes)
        bytes.extend_from_slice(&(self.attrs.len() as u16).to_le_bytes());

        // attrs (type: u8, value: u32)
        for (attr_type, attr_value) in &self.attrs {
            bytes.push(*attr_type);
            bytes.extend_from_slice(&attr_value.to_le_bytes());
        }

        // dpop_jti (1 byte present flag + optional 16 bytes)
        if let Some(jti) = &self.dpop_jti {
            bytes.push(1);
            bytes.extend_from_slice(jti);
        } else {
            bytes.push(0);
        }

        // iat (8 bytes)
        bytes.extend_from_slice(&self.iat.to_le_bytes());

        // exp (8 bytes)
        bytes.extend_from_slice(&self.exp.to_le_bytes());

        // aud (length-prefixed string)
        let aud_bytes = self.aud.as_bytes();
        bytes.extend_from_slice(&(aud_bytes.len() as u16).to_le_bytes());
        bytes.extend_from_slice(aud_bytes);

        // session_id (1 byte present flag + optional 16 bytes)
        if let Some(sid) = &self.session_id {
            bytes.push(1);
            bytes.extend_from_slice(sid);
        } else {
            bytes.push(0);
        }

        // device_id (1 byte present flag + optional length-prefixed string)
        if let Some(device_id) = &self.device_id {
            bytes.push(1);
            let device_bytes = device_id.as_bytes();
            bytes.push(device_bytes.len() as u8);
            bytes.extend_from_slice(device_bytes);
        } else {
            bytes.push(0);
        }

        // did (1 byte present flag + optional length-prefixed string)
        if let Some(did) = &self.did {
            bytes.push(1);
            let did_bytes = did.as_bytes();
            bytes.extend_from_slice(&(did_bytes.len() as u16).to_le_bytes());
            bytes.extend_from_slice(did_bytes);
        } else {
            bytes.push(0);
        }

        Ok(bytes)
    }

    /// Deserialize payload from bytes (after decryption)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cursor = Cursor::new(bytes);

        // Helper to read bytes
        use std::io::Read;
        let mut read_exact = |size: usize| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut buf = vec![0u8; size];
            cursor.read_exact(&mut buf)?;
            Ok(buf)
        };

        // sub_id
        let sub_id: [u8; 16] = read_exact(16)?.try_into().unwrap();

        // flags
        let flags = u64::from_le_bytes(read_exact(8)?.try_into().unwrap());

        // scopes
        let scopes_count = u16::from_le_bytes(read_exact(2)?.try_into().unwrap());
        let mut scopes = Vec::with_capacity(scopes_count as usize);
        for _ in 0..scopes_count {
            let scope_len = read_exact(1)?[0] as usize;
            let scope_bytes = read_exact(scope_len)?;
            scopes.push(String::from_utf8(scope_bytes)?);
        }

        // attrs
        let attrs_count = u16::from_le_bytes(read_exact(2)?.try_into().unwrap());
        let mut attrs = Vec::with_capacity(attrs_count as usize);
        for _ in 0..attrs_count {
            let attr_type = read_exact(1)?[0];
            let attr_value = u32::from_le_bytes(read_exact(4)?.try_into().unwrap());
            attrs.push((attr_type, attr_value));
        }

        // dpop_jti
        let dpop_jti = if read_exact(1)?[0] == 1 {
            Some(read_exact(16)?.try_into().unwrap())
        } else {
            None
        };

        // iat
        let iat = i64::from_le_bytes(read_exact(8)?.try_into().unwrap());

        // exp
        let exp = i64::from_le_bytes(read_exact(8)?.try_into().unwrap());

        // aud
        let aud_len = u16::from_le_bytes(read_exact(2)?.try_into().unwrap()) as usize;
        let aud = String::from_utf8(read_exact(aud_len)?)?;

        // session_id
        let session_id = if read_exact(1)?[0] == 1 {
            Some(read_exact(16)?.try_into().unwrap())
        } else {
            None
        };

        // device_id
        let device_id = if read_exact(1)?[0] == 1 {
            let device_len = read_exact(1)?[0] as usize;
            Some(String::from_utf8(read_exact(device_len)?)?)
        } else {
            None
        };

        // did
        let did = if read_exact(1)?[0] == 1 {
            let did_len = u16::from_le_bytes(read_exact(2)?.try_into().unwrap()) as usize;
            Some(String::from_utf8(read_exact(did_len)?)?)
        } else {
            None
        };

        Ok(NtdfTokenPayload {
            sub_id,
            flags,
            scopes,
            attrs,
            dpop_jti,
            iat,
            exp,
            aud,
            session_id,
            device_id,
            did,
        })
    }
}

/// Validate NTDF token
///
/// Steps:
/// 1. Decode Z85 to raw bytes
/// 2. Parse NanoTDF header
/// 3. Perform ECDH and decrypt payload
/// 4. Deserialize and validate claims
pub fn validate_ntdf_token(
    z85_token: &str,
    kas_private_key_pem: &[u8],
    expected_audience: &str,
) -> Result<ValidationResult, Box<dyn std::error::Error>> {
    info!("Validating NTDF token for audience: {}", expected_audience);

    // 1. Decode Z85
    let nanotdf_bytes = z85::decode(z85_token)
        .map_err(|e| format!("Z85 decode failed: {}", e))?;

    info!("Decoded NTDF token: {} bytes", nanotdf_bytes.len());

    // 2. Detect NanoTDF version and compute salt
    let version = crypto::detect_nanotdf_version(&nanotdf_bytes)
        .ok_or("Invalid NanoTDF version")?;
    let salt = crypto::compute_nanotdf_salt(version);

    info!("Detected NanoTDF version: 0x{:02X}", version);

    // 3. Parse NanoTDF header
    let mut parser = BinaryParser::new(&nanotdf_bytes);
    let header = parser.parse_header()
        .map_err(|e| format!("Failed to parse NanoTDF header: {:?}", e))?;

    info!("Parsed NanoTDF header");

    // 4. Load KAS private key
    let kas_private_key = parse_ec_private_key(kas_private_key_pem)?;

    // 5. Extract ephemeral public key from header
    let ephemeral_public_key = parse_ephemeral_public_key(header.get_ephemeral_key())?;

    // 6. Perform ECDH to get shared secret
    let shared_secret = crypto::custom_ecdh(&kas_private_key, &ephemeral_public_key)?;

    info!("ECDH shared secret derived: {} bytes", shared_secret.len());

    // 7. Derive AES key using HKDF
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &shared_secret);
    let mut aes_key = [0u8; 32];
    hkdf.expand(b"", &mut aes_key)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    // 8. Read encrypted payload manually (parser.read is private)
    // Skip header and read payload length + ciphertext directly
    let payload_start = parser.position;
    if payload_start + 3 > nanotdf_bytes.len() {
        return Ok(ValidationResult::InvalidFormat("Truncated payload length".to_string()));
    }

    let payload_length_bytes = &nanotdf_bytes[payload_start..payload_start + 3];
    let payload_length = u32::from_be_bytes([
        0,
        payload_length_bytes[0],
        payload_length_bytes[1],
        payload_length_bytes[2],
    ]) as usize;

    info!("Payload length: {} bytes", payload_length);

    // Read ciphertext + tag (last 16 bytes are auth tag)
    if payload_length < 16 {
        return Ok(ValidationResult::InvalidFormat(
            "Payload too short for auth tag".to_string(),
        ));
    }

    let ciphertext_start = payload_start + 3;
    if ciphertext_start + payload_length > nanotdf_bytes.len() {
        return Ok(ValidationResult::InvalidFormat("Truncated ciphertext".to_string()));
    }

    let ciphertext_with_tag = &nanotdf_bytes[ciphertext_start..ciphertext_start + payload_length];

    let ciphertext_len = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..ciphertext_len];
    let tag = &ciphertext_with_tag[ciphertext_len..];

    // Combine ciphertext + tag for AES-GCM
    let mut encrypted_payload = ciphertext.to_vec();
    encrypted_payload.extend_from_slice(tag);

    // 9. Decrypt payload with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| format!("Failed to create cipher: {}", e))?;

    // Use zero nonce (NanoTDF uses ephemeral keys, so nonce reuse isn't a concern)
    let nonce = Nonce::from_slice(&[0u8; 12]);

    let decrypted = cipher
        .decrypt(nonce, encrypted_payload.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    info!("Decrypted payload: {} bytes", decrypted.len());

    // 10. Deserialize payload
    let payload = NtdfTokenPayload::from_bytes(&decrypted)?;

    info!("Deserialized payload for sub_id: {:?}", payload.sub_id);

    // 11. Validate claims
    let now = Utc::now().timestamp();

    // Check expiration
    if payload.exp < now {
        warn!("NTDF token expired: exp={}, now={}", payload.exp, now);
        return Ok(ValidationResult::Expired {
            exp: payload.exp,
            now,
        });
    }

    // Check audience
    if payload.aud != expected_audience {
        warn!(
            "NTDF token audience mismatch: expected={}, actual={}",
            expected_audience, payload.aud
        );
        return Ok(ValidationResult::InvalidAudience {
            expected: expected_audience.to_string(),
            actual: payload.aud,
        });
    }

    // TODO: Verify Ed25519 signature over (Header||Policy||Payload)

    info!("NTDF token validated successfully");

    Ok(ValidationResult::Valid(ValidatedNtdfToken {
        sub_id: payload.sub_id,
        session_id: payload.session_id,
        flags: payload.flags,
        scopes: payload.scopes,
        dpop_jti: payload.dpop_jti,
        device_id: payload.device_id,
        did: payload.did,
        iat: payload.iat,
        exp: payload.exp,
    }))
}

/// Parse EC private key from PEM format
fn parse_ec_private_key(pem_bytes: &[u8]) -> Result<SecretKey, Box<dyn std::error::Error>> {
    use p256::pkcs8::DecodePrivateKey;
    let pem_str = std::str::from_utf8(pem_bytes)?;
    SecretKey::from_pkcs8_pem(pem_str).map_err(|e| format!("Failed to parse EC private key: {}", e).into())
}

/// Parse ephemeral public key from compressed or uncompressed format
fn parse_ephemeral_public_key(key_bytes: &[u8]) -> Result<PublicKey, Box<dyn std::error::Error>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let encoded_point = EncodedPoint::from_bytes(key_bytes)
        .map_err(|e| format!("Failed to parse ephemeral public key: {}", e))?;
    PublicKey::from_sec1_bytes(encoded_point.as_bytes())
        .map_err(|e| format!("Invalid ephemeral public key: {}", e).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_serialization_roundtrip() {
        let payload = NtdfTokenPayload {
            sub_id: [1u8; 16],
            flags: capability_flags::WEBAUTHN | capability_flags::PLATFORM_SECURE,
            scopes: vec!["openid".to_string(), "profile".to_string()],
            attrs: vec![
                (AttributeType::Age as u8, 25),
                (AttributeType::SubscriptionTier as u8, 2),
            ],
            dpop_jti: Some([0xABu8; 16]),
            iat: 1234567890,
            exp: 1234567890 + 3600,
            aud: "https://kas.example.com".to_string(),
            session_id: Some([0xCDu8; 16]),
            device_id: Some("iPhone14,2".to_string()),
            did: Some("did:key:z6MkTest".to_string()),
        };

        let bytes = payload.to_bytes().unwrap();
        let decoded = NtdfTokenPayload::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.sub_id, payload.sub_id);
        assert_eq!(decoded.flags, payload.flags);
        assert_eq!(decoded.scopes, payload.scopes);
        assert_eq!(decoded.attrs, payload.attrs);
        assert_eq!(decoded.dpop_jti, payload.dpop_jti);
        assert_eq!(decoded.iat, payload.iat);
        assert_eq!(decoded.exp, payload.exp);
        assert_eq!(decoded.aud, payload.aud);
        assert_eq!(decoded.session_id, payload.session_id);
        assert_eq!(decoded.device_id, payload.device_id);
        assert_eq!(decoded.did, payload.did);
    }

    #[test]
    fn test_minimal_payload() {
        let payload = NtdfTokenPayload {
            sub_id: [0u8; 16],
            flags: 0,
            scopes: vec![],
            attrs: vec![],
            dpop_jti: None,
            iat: 0,
            exp: 0,
            aud: "test".to_string(),
            session_id: None,
            device_id: None,
            did: None,
        };

        let bytes = payload.to_bytes().unwrap();
        let decoded = NtdfTokenPayload::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.sub_id, payload.sub_id);
        assert_eq!(decoded.scopes.len(), 0);
        assert_eq!(decoded.dpop_jti, None);
    }
}
