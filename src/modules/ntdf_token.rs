//! NTDF Token Validation Module
//!
//! Validates NTDF (NanoTDF-based) authentication tokens per the specification:
//! <https://github.com/arkavo-org/specifications/ntdf-token>
//!
//! Wire format: `Authorization: NTDF <Z85-encoded-nanotdf>`

use crate::modules::crypto::custom_ecdh;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::{Aead, Key};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use log::{debug, info, warn};
use opentdf_protocol::binary::BinaryRead;
use opentdf_protocol::binary::BinaryWrite;
use opentdf_protocol::nanotdf::{Header, HKDF_SALT};
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use std::io::{Cursor, Read};
use thiserror::Error;

/// Capability flags for NTDF token payload
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CapabilityFlag {
    Profile = 0x01,
    OpenId = 0x02,
    Email = 0x04,
    OfflineAccess = 0x08,
    DeviceAttested = 0x10,
    BiometricAuth = 0x20,
    WebAuthn = 0x40,
    PlatformSecure = 0x80,
}

/// Attribute types for NTDF token payload
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AttributeType {
    Age = 0,
    SubscriptionTier = 1,
    SecurityLevel = 2,
    PlatformCode = 3,
}

/// Decrypted NTDF token payload containing authentication claims
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NtdfTokenPayload {
    /// Subject UUID (16 bytes)
    pub sub_id: [u8; 16],
    /// Capability flags (bitfield)
    pub flags: u64,
    /// OAuth scopes
    pub scopes: Vec<String>,
    /// Typed attributes (type, value)
    pub attrs: Vec<(u8, u32)>,
    /// DPoP JTI for proof-of-possession binding (optional)
    pub dpop_jti: Option<[u8; 16]>,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration (Unix timestamp)
    pub exp: i64,
    /// Audience (target service)
    pub aud: String,
    /// Session tracking ID (optional)
    pub session_id: Option<[u8; 16]>,
    /// Device identifier (optional)
    pub device_id: Option<String>,
    /// Decentralized Identifier (optional)
    pub did: Option<String>,
}

impl NtdfTokenPayload {
    /// Check if a capability flag is set
    #[allow(dead_code)]
    pub fn has_capability(&self, flag: CapabilityFlag) -> bool {
        (self.flags & flag as u64) != 0
    }

    /// Get an attribute value by type
    #[allow(dead_code)]
    pub fn get_attribute(&self, attr_type: AttributeType) -> Option<u32> {
        self.attrs
            .iter()
            .find(|(t, _)| *t == attr_type as u8)
            .map(|(_, v)| *v)
    }

    /// Get the subject ID as hex string
    pub fn sub_id_hex(&self) -> String {
        hex::encode(self.sub_id)
    }

    /// Deserialize from binary format per NTDF spec
    fn from_bytes(data: &[u8]) -> Result<Self, NtdfTokenError> {
        let mut cursor = Cursor::new(data);

        // sub_id (16 bytes)
        let mut sub_id = [0u8; 16];
        cursor
            .read_exact(&mut sub_id)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;

        // flags (8 bytes, u64 little-endian)
        let mut flags_bytes = [0u8; 8];
        cursor
            .read_exact(&mut flags_bytes)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let flags = u64::from_le_bytes(flags_bytes);

        // scopes_count (2 bytes, u16 little-endian)
        let mut scopes_count_bytes = [0u8; 2];
        cursor
            .read_exact(&mut scopes_count_bytes)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let scopes_count = u16::from_le_bytes(scopes_count_bytes) as usize;

        // scopes (length-prefixed strings)
        let mut scopes = Vec::with_capacity(scopes_count);
        for _ in 0..scopes_count {
            let mut len_byte = [0u8; 1];
            cursor
                .read_exact(&mut len_byte)
                .map_err(|_| NtdfTokenError::PayloadTooShort)?;
            let len = len_byte[0] as usize;

            let mut scope_bytes = vec![0u8; len];
            cursor
                .read_exact(&mut scope_bytes)
                .map_err(|_| NtdfTokenError::PayloadTooShort)?;
            let scope = String::from_utf8(scope_bytes)
                .map_err(|_| NtdfTokenError::InvalidPayload("Invalid UTF-8 in scope".into()))?;
            scopes.push(scope);
        }

        // attrs_count (2 bytes, u16 little-endian)
        let mut attrs_count_bytes = [0u8; 2];
        cursor
            .read_exact(&mut attrs_count_bytes)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let attrs_count = u16::from_le_bytes(attrs_count_bytes) as usize;

        // attrs (type: 1 byte, value: 4 bytes)
        let mut attrs = Vec::with_capacity(attrs_count);
        for _ in 0..attrs_count {
            let mut attr_type = [0u8; 1];
            cursor
                .read_exact(&mut attr_type)
                .map_err(|_| NtdfTokenError::PayloadTooShort)?;

            let mut attr_value = [0u8; 4];
            cursor
                .read_exact(&mut attr_value)
                .map_err(|_| NtdfTokenError::PayloadTooShort)?;

            attrs.push((attr_type[0], u32::from_le_bytes(attr_value)));
        }

        // dpop_jti_present (1 byte)
        let mut dpop_jti_present = [0u8; 1];
        cursor
            .read_exact(&mut dpop_jti_present)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let dpop_jti = if dpop_jti_present[0] != 0 {
            let mut jti = [0u8; 16];
            cursor
                .read_exact(&mut jti)
                .map_err(|_| NtdfTokenError::PayloadTooShort)?;
            Some(jti)
        } else {
            None
        };

        // iat (8 bytes, i64 little-endian)
        let mut iat_bytes = [0u8; 8];
        cursor
            .read_exact(&mut iat_bytes)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let iat = i64::from_le_bytes(iat_bytes);

        // exp (8 bytes, i64 little-endian)
        let mut exp_bytes = [0u8; 8];
        cursor
            .read_exact(&mut exp_bytes)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let exp = i64::from_le_bytes(exp_bytes);

        // aud_length (2 bytes, u16 little-endian)
        let mut aud_len_bytes = [0u8; 2];
        cursor
            .read_exact(&mut aud_len_bytes)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let aud_len = u16::from_le_bytes(aud_len_bytes) as usize;

        // aud (variable, UTF-8 string)
        let mut aud_bytes = vec![0u8; aud_len];
        cursor
            .read_exact(&mut aud_bytes)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let aud = String::from_utf8(aud_bytes)
            .map_err(|_| NtdfTokenError::InvalidPayload("Invalid UTF-8 in audience".into()))?;

        // session_id_present (1 byte)
        let mut session_id_present = [0u8; 1];
        cursor
            .read_exact(&mut session_id_present)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let session_id = if session_id_present[0] != 0 {
            let mut sid = [0u8; 16];
            cursor
                .read_exact(&mut sid)
                .map_err(|_| NtdfTokenError::PayloadTooShort)?;
            Some(sid)
        } else {
            None
        };

        // device_id_present (1 byte)
        let mut device_id_present = [0u8; 1];
        cursor
            .read_exact(&mut device_id_present)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let device_id =
            if device_id_present[0] != 0 {
                let mut len_byte = [0u8; 1];
                cursor
                    .read_exact(&mut len_byte)
                    .map_err(|_| NtdfTokenError::PayloadTooShort)?;
                let len = len_byte[0] as usize;

                let mut device_id_bytes = vec![0u8; len];
                cursor
                    .read_exact(&mut device_id_bytes)
                    .map_err(|_| NtdfTokenError::PayloadTooShort)?;
                Some(String::from_utf8(device_id_bytes).map_err(|_| {
                    NtdfTokenError::InvalidPayload("Invalid UTF-8 in device_id".into())
                })?)
            } else {
                None
            };

        // did_present (1 byte)
        let mut did_present = [0u8; 1];
        cursor
            .read_exact(&mut did_present)
            .map_err(|_| NtdfTokenError::PayloadTooShort)?;
        let did = if did_present[0] != 0 {
            let mut len_bytes = [0u8; 2];
            cursor
                .read_exact(&mut len_bytes)
                .map_err(|_| NtdfTokenError::PayloadTooShort)?;
            let len = u16::from_le_bytes(len_bytes) as usize;

            let mut did_bytes = vec![0u8; len];
            cursor
                .read_exact(&mut did_bytes)
                .map_err(|_| NtdfTokenError::PayloadTooShort)?;
            Some(
                String::from_utf8(did_bytes)
                    .map_err(|_| NtdfTokenError::InvalidPayload("Invalid UTF-8 in DID".into()))?,
            )
        } else {
            None
        };

        Ok(Self {
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

/// Errors that can occur during NTDF token validation
#[derive(Debug, Error)]
pub enum NtdfTokenError {
    #[error("Invalid authorization header format")]
    InvalidHeaderFormat,

    #[error("Z85 decoding failed: {0}")]
    Z85DecodeError(String),

    #[error("Invalid NanoTDF format: {0}")]
    InvalidNanoTdf(String),

    #[error("ECDH key agreement failed: {0}")]
    EcdhError(String),

    #[error("AES-GCM decryption failed")]
    DecryptionFailed,

    #[error("Payload too short")]
    PayloadTooShort,

    #[error("Invalid payload: {0}")]
    InvalidPayload(String),

    #[error("Token expired: exp={exp}, now={now}")]
    Expired { exp: i64, now: i64 },

    #[error("Invalid audience: expected={expected}, got={got}")]
    InvalidAudience { expected: String, got: String },
}

/// Validates an NTDF token from an Authorization header
///
/// # Arguments
/// * `auth_header` - The full Authorization header value (e.g., "NTDF <z85-token>")
/// * `kas_private_key` - The KAS EC private key for ECDH
/// * `expected_audience` - The expected audience claim
///
/// # Returns
/// The validated token payload or an error
pub fn validate_ntdf_token(
    auth_header: &str,
    kas_private_key: &SecretKey,
    expected_audience: &str,
) -> Result<NtdfTokenPayload, NtdfTokenError> {
    info!("Validating NTDF token");

    // 1. Extract Z85 token from header
    let z85_token = auth_header
        .strip_prefix("NTDF ")
        .ok_or(NtdfTokenError::InvalidHeaderFormat)?;

    debug!("Z85 token length: {} chars", z85_token.len());

    // 2. Z85 decode
    let nanotdf_bytes =
        z85::decode(z85_token).map_err(|e| NtdfTokenError::Z85DecodeError(e.to_string()))?;

    debug!("Decoded NanoTDF: {} bytes", nanotdf_bytes.len());

    // 3. Parse NanoTDF header using opentdf_protocol
    let mut cursor = Cursor::new(&nanotdf_bytes);
    let header = Header::read_from(&mut cursor)
        .map_err(|e| NtdfTokenError::InvalidNanoTdf(format!("Header parse error: {}", e)))?;

    debug!(
        "NanoTDF header parsed: KAS={:?}, ECC={:?}",
        header.kas, header.ecc_and_binding_mode.ecc_mode
    );

    // 4. Extract ephemeral public key from header
    let ephemeral_key_bytes = &header.ephemeral_public_key;
    if ephemeral_key_bytes.len() < 33 {
        return Err(NtdfTokenError::InvalidNanoTdf(format!(
            "Invalid ephemeral key size: {} (expected >= 33)",
            ephemeral_key_bytes.len()
        )));
    }

    let ephemeral_public_key = PublicKey::from_sec1_bytes(ephemeral_key_bytes)
        .map_err(|e| NtdfTokenError::InvalidNanoTdf(format!("Invalid ephemeral key: {}", e)))?;

    // 5. ECDH key agreement
    let shared_secret = custom_ecdh(kas_private_key, &ephemeral_public_key)
        .map_err(|e| NtdfTokenError::EcdhError(e.to_string()))?;

    debug!("ECDH key agreement successful");

    // 6. HKDF key derivation using opentdf_protocol's HKDF_SALT
    let hkdf = Hkdf::<Sha256>::new(Some(&HKDF_SALT), &shared_secret);
    let mut aes_key = [0u8; 32];
    hkdf.expand(b"", &mut aes_key)
        .map_err(|_| NtdfTokenError::InvalidNanoTdf("HKDF expansion failed".into()))?;

    // 7. Calculate header size using BinaryWrite trait and extract encrypted payload
    let header_size = header.serialized_size();
    let payload_data = &nanotdf_bytes[header_size..];

    if payload_data.len() < 3 + 16 {
        return Err(NtdfTokenError::PayloadTooShort);
    }

    // Payload length is 3 bytes big-endian
    let payload_len = ((payload_data[0] as usize) << 16)
        | ((payload_data[1] as usize) << 8)
        | (payload_data[2] as usize);

    let encrypted_start = 3;
    let encrypted_end = encrypted_start + payload_len;

    if encrypted_end > payload_data.len() {
        return Err(NtdfTokenError::PayloadTooShort);
    }

    let encrypted = &payload_data[encrypted_start..encrypted_end];

    // 8. AES-256-GCM decryption (zero nonce per NanoTDF spec)
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let key = Key::<Aes256Gcm>::from(aes_key);
    let cipher = Aes256Gcm::new(&key);

    let plaintext = cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| NtdfTokenError::DecryptionFailed)?;

    debug!("Decrypted payload: {} bytes", plaintext.len());

    // 9. Deserialize payload
    let payload = NtdfTokenPayload::from_bytes(&plaintext)?;

    // 10. Validate expiration
    let now = chrono::Utc::now().timestamp();
    if now >= payload.exp {
        warn!("NTDF token expired: exp={}, now={}", payload.exp, now);
        return Err(NtdfTokenError::Expired {
            exp: payload.exp,
            now,
        });
    }

    // 11. Validate audience
    if payload.aud != expected_audience {
        warn!(
            "NTDF token audience mismatch: expected={}, got={}",
            expected_audience, payload.aud
        );
        return Err(NtdfTokenError::InvalidAudience {
            expected: expected_audience.to_string(),
            got: payload.aud.clone(),
        });
    }

    info!(
        "NTDF token valid: sub_id={}, flags=0x{:X}, scopes={:?}",
        payload.sub_id_hex(),
        payload.flags,
        payload.scopes
    );

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_deserialization() {
        // Minimal valid payload
        let mut payload_bytes = Vec::new();

        // sub_id (16 bytes)
        payload_bytes.extend_from_slice(&[0x01; 16]);

        // flags (8 bytes, u64 LE) - WEBAUTHN | PROFILE
        payload_bytes.extend_from_slice(&0x41u64.to_le_bytes());

        // scopes_count (2 bytes) - 1 scope
        payload_bytes.extend_from_slice(&1u16.to_le_bytes());
        // scope: "openid" (6 bytes)
        payload_bytes.push(6);
        payload_bytes.extend_from_slice(b"openid");

        // attrs_count (2 bytes) - 1 attr
        payload_bytes.extend_from_slice(&1u16.to_le_bytes());
        // attr: Age = 25
        payload_bytes.push(0); // Age type
        payload_bytes.extend_from_slice(&25u32.to_le_bytes());

        // dpop_jti_present (1 byte) - absent
        payload_bytes.push(0);

        // iat (8 bytes)
        payload_bytes.extend_from_slice(&1700000000i64.to_le_bytes());

        // exp (8 bytes) - far future
        payload_bytes.extend_from_slice(&2700000000i64.to_le_bytes());

        // aud_length (2 bytes) + aud
        let aud = "https://test.example.com";
        payload_bytes.extend_from_slice(&(aud.len() as u16).to_le_bytes());
        payload_bytes.extend_from_slice(aud.as_bytes());

        // session_id_present (1 byte) - absent
        payload_bytes.push(0);

        // device_id_present (1 byte) - absent
        payload_bytes.push(0);

        // did_present (1 byte) - absent
        payload_bytes.push(0);

        let payload = NtdfTokenPayload::from_bytes(&payload_bytes).unwrap();

        assert_eq!(payload.sub_id, [0x01; 16]);
        assert_eq!(payload.flags, 0x41);
        assert!(payload.has_capability(CapabilityFlag::WebAuthn));
        assert!(payload.has_capability(CapabilityFlag::Profile));
        assert!(!payload.has_capability(CapabilityFlag::Email));
        assert_eq!(payload.scopes, vec!["openid"]);
        assert_eq!(payload.get_attribute(AttributeType::Age), Some(25));
        assert_eq!(payload.aud, "https://test.example.com");
    }

    #[test]
    fn test_invalid_header_format() {
        let kas_key = SecretKey::random(&mut rand_core::OsRng);
        let result = validate_ntdf_token("Bearer xyz", &kas_key, "https://test.com");
        assert!(matches!(result, Err(NtdfTokenError::InvalidHeaderFormat)));
    }
}
