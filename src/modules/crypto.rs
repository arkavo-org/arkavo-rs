// Suppress deprecation warnings for generic_array 0.x used by aes_gcm dependency
// TODO: Upgrade to aes_gcm version using generic_array 1.x when available
#![allow(deprecated)]

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::{Aead, Key};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::error::Error;

/// NanoTDF version constants
pub const NANOTDF_MAGIC: &[u8] = b"L1"; // Magic number prefix
pub const NANOTDF_VERSION_V12: u8 = 0x4C; // 'L' - version 1.2
pub const NANOTDF_VERSION_V13: u8 = 0x4D; // 'M' - version 1.3

/// Computes the HKDF salt for a given NanoTDF version
/// Per NanoTDF spec section 4: salt = SHA256(MAGIC_NUMBER + VERSION)
///
/// # Arguments
/// * `version` - The NanoTDF version byte (0x4C for v12 "L1L", 0x4D for v13 "L1M")
///
/// # Returns
/// 32-byte salt for HKDF key derivation
pub fn compute_nanotdf_salt(version: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NANOTDF_MAGIC);
    hasher.update([version]);
    hasher.finalize().into()
}

/// Detects NanoTDF version from header magic bytes
///
/// # Arguments
/// * `header` - NanoTDF header bytes (must be at least 3 bytes)
///
/// # Returns
/// Version byte if valid NanoTDF header, None otherwise
pub fn detect_nanotdf_version(header: &[u8]) -> Option<u8> {
    if header.len() < 3 {
        return None;
    }
    // Check magic number "L1"
    if &header[0..2] != NANOTDF_MAGIC {
        return None;
    }
    // Return version byte
    match header[2] {
        NANOTDF_VERSION_V12 | NANOTDF_VERSION_V13 => Some(header[2]),
        _ => None,
    }
}

/// Performs ECDH key agreement and returns x-coordinate as shared secret
/// This matches the behavior of OpenTDFKit's custom_ecdh
///
/// # Arguments
/// * `private_key` - The local private key
/// * `public_key` - The remote public key
///
/// # Returns
/// The x-coordinate of the shared point (32 bytes for P-256)
pub fn custom_ecdh(
    private_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use elliptic_curve::point::AffineCoordinates;
    let scalar = private_key.to_nonzero_scalar();
    let public_key_point = public_key.to_projective();
    let shared_point = (public_key_point * *scalar).to_affine();
    let x_coordinate = shared_point.x();
    Ok(x_coordinate.to_vec())
}

/// Performs NanoTDF-compatible rewrap operation
/// Encrypts the DEK (Data Encryption Key) using HKDF-derived symmetric key
///
/// # Arguments
/// * `dek_shared_secret` - The shared secret from ECDH between KAS and TDF ephemeral keys
/// * `session_shared_secret` - The shared secret from session ECDH (for WebSocket) or request ECDH (for HTTP)
/// * `salt` - HKDF salt (use version-based salt from compute_nanotdf_salt for compatibility)
/// * `info` - HKDF info parameter (empty for NanoTDF spec compliance)
///
/// # Returns
/// Tuple of (nonce, wrapped_dek) where wrapped_dek includes ciphertext + tag
pub fn rewrap_dek(
    dek_shared_secret: &[u8],
    session_shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    // Derive symmetric key using HKDF
    let hkdf = Hkdf::<Sha256>::new(Some(salt), session_shared_secret);
    let mut derived_key = [0u8; 32];
    hkdf.expand(info, &mut derived_key)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    // Generate random nonce (12 bytes for AES-GCM)
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga = GenericArray::from_slice(&nonce);

    // Encrypt DEK with AES-256-GCM
    let key = Key::<Aes256Gcm>::from(derived_key);
    let cipher = Aes256Gcm::new(&key);
    let wrapped_dek = cipher
        .encrypt(nonce_ga, dek_shared_secret)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    Ok((nonce.to_vec(), wrapped_dek))
}

/// Performs simple rewrap operation for RSA-unwrapped DEKs
/// Encrypts the DEK (Data Encryption Key) directly with session shared secret
///
/// # Arguments
/// * `dek` - The unwrapped Data Encryption Key (from RSA decryption)
/// * `session_shared_secret` - The shared secret from session ECDH
///
/// # Returns
/// Tuple of (nonce, wrapped_dek) where wrapped_dek includes ciphertext + tag
pub fn rewrap_dek_simple(
    dek: &[u8],
    session_shared_secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    // Derive symmetric key using HKDF (no salt, empty info for simplicity)
    let hkdf = Hkdf::<Sha256>::new(None, session_shared_secret);
    let mut derived_key = [0u8; 32];
    hkdf.expand(b"", &mut derived_key)
        .map_err(|e| format!("HKDF expansion failed: {}", e))?;

    // Generate random nonce (12 bytes for AES-GCM)
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_ga = GenericArray::from_slice(&nonce);

    // Encrypt DEK with AES-256-GCM
    let key = Key::<Aes256Gcm>::from(derived_key);
    let cipher = Aes256Gcm::new(&key);
    let wrapped_dek = cipher
        .encrypt(nonce_ga, dek)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    Ok((nonce.to_vec(), wrapped_dek))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_nanotdf_salt_v12() {
        let salt = compute_nanotdf_salt(NANOTDF_VERSION_V12);
        // The salt should be SHA256("L1L")
        let expected = Sha256::digest(b"L1L");
        assert_eq!(salt.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_compute_nanotdf_salt_v13() {
        let salt = compute_nanotdf_salt(NANOTDF_VERSION_V13);
        // The salt should be SHA256("L1M")
        let expected = Sha256::digest(b"L1M");
        assert_eq!(salt.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_detect_nanotdf_version() {
        // Valid v12 header
        let header_v12 = b"L1L";
        assert_eq!(
            detect_nanotdf_version(header_v12),
            Some(NANOTDF_VERSION_V12)
        );

        // Valid v13 header
        let header_v13 = b"L1M";
        assert_eq!(
            detect_nanotdf_version(header_v13),
            Some(NANOTDF_VERSION_V13)
        );

        // Invalid magic
        let header_invalid = b"XXL";
        assert_eq!(detect_nanotdf_version(header_invalid), None);

        // Too short
        let header_short = b"L1";
        assert_eq!(detect_nanotdf_version(header_short), None);

        // Unknown version
        let header_unknown = b"L1Z";
        assert_eq!(detect_nanotdf_version(header_unknown), None);
    }

    #[test]
    fn test_rewrap_dek() {
        let dek = b"test_data_encryption_key_32bytes";
        let session_secret = b"test_session_shared_secret__32b";
        let salt = compute_nanotdf_salt(NANOTDF_VERSION_V12);
        let info = b""; // Empty per NanoTDF spec

        let result = rewrap_dek(dek, session_secret, &salt, info);
        assert!(result.is_ok());

        let (nonce, wrapped) = result.unwrap();
        assert_eq!(nonce.len(), 12);
        // Wrapped should be ciphertext + 16-byte tag
        assert_eq!(wrapped.len(), dek.len() + 16);
    }

    #[test]
    fn test_rewrap_dek_simple() {
        let dek = b"test_data_encryption_key_32bytes";
        let session_secret = b"test_session_shared_secret__32b";

        let result = rewrap_dek_simple(dek, session_secret);
        assert!(result.is_ok());

        let (nonce, wrapped) = result.unwrap();
        assert_eq!(nonce.len(), 12);
        // Wrapped should be ciphertext + 16-byte auth tag
        assert_eq!(wrapped.len(), dek.len() + 16);
    }
}

// ==================== Utility Functions ====================

/// Parse a PEM-formatted P-256 public key
pub fn parse_pem_public_key(pem: &str) -> Result<PublicKey, Box<dyn Error>> {
    let pem_parsed = pem::parse(pem)?;
    let public_key = PublicKey::from_sec1_bytes(pem_parsed.contents())?;
    Ok(public_key)
}

/// Convert a P-256 public key to PEM format
pub fn public_key_to_pem(public_key: &PublicKey) -> Result<String, Box<dyn Error>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let encoded_point = public_key.to_encoded_point(false);
    let sec1_bytes = encoded_point.as_bytes();
    let pem_encoded = pem::Pem::new("PUBLIC KEY", sec1_bytes.to_vec());
    Ok(pem::encode(&pem_encoded))
}

/// Base64 encode data using standard encoding
pub fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(data)
}

/// Base64 decode data using standard encoding
pub fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(data)
}

// ==================== ECDSA Signature Verification ====================

/// Error type for signature verification operations.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Verification failed")]
    VerificationFailed,
}

/// Verify an ECDSA signature.
///
/// # Arguments
/// * `algorithm` - The signing algorithm: "ES256", "ES384", or "ES512"
/// * `public_key` - The public key in SEC1/X9.62 format (compressed or uncompressed)
/// * `message` - The message that was signed
/// * `signature` - The signature bytes (r || s format, or DER)
///
/// # Returns
/// `Ok(true)` if signature is valid, `Ok(false)` if invalid, `Err` on format errors.
pub fn verify_ecdsa_signature(
    algorithm: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignatureError> {
    match algorithm {
        "ES256" => verify_es256(public_key, message, signature),
        "ES384" => verify_es384(public_key, message, signature),
        "ES512" => Err(SignatureError::UnsupportedAlgorithm(
            "ES512 (P-521) not yet supported".to_string(),
        )),
        _ => Err(SignatureError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

/// Verify ES256 (P-256/secp256r1) signature.
fn verify_es256(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, SignatureError> {
    use ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

    // Try to parse signature - could be raw (r||s) or DER encoded
    let sig = parse_ecdsa_signature::<64>(signature)?;

    let p256_sig = Signature::from_slice(&sig).map_err(|e| SignatureError::InvalidSignatureFormat(e.to_string()))?;

    Ok(verifying_key.verify(message, &p256_sig).is_ok())
}

/// Verify ES384 (P-384/secp384r1) signature.
fn verify_es384(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, SignatureError> {
    use ecdsa::signature::Verifier;
    use p384::ecdsa::{Signature, VerifyingKey};

    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

    // Try to parse signature - could be raw (r||s) or DER encoded
    let sig = parse_ecdsa_signature::<96>(signature)?;

    let p384_sig = Signature::from_slice(&sig).map_err(|e| SignatureError::InvalidSignatureFormat(e.to_string()))?;

    Ok(verifying_key.verify(message, &p384_sig).is_ok())
}

/// Parse ECDSA signature from either raw (r||s) or DER format.
///
/// The generic parameter N is the expected raw signature length (64 for P-256, 96 for P-384).
fn parse_ecdsa_signature<const N: usize>(signature: &[u8]) -> Result<[u8; N], SignatureError> {
    // If already the right size, assume raw format
    if signature.len() == N {
        let mut result = [0u8; N];
        result.copy_from_slice(signature);
        return Ok(result);
    }

    // Try to parse as DER
    if signature.len() > 6 && signature[0] == 0x30 {
        // DER SEQUENCE tag
        let der_result = parse_der_signature::<N>(signature);
        if der_result.is_ok() {
            return der_result;
        }
    }

    Err(SignatureError::InvalidSignatureFormat(format!(
        "Expected {} bytes raw or DER encoded, got {} bytes",
        N,
        signature.len()
    )))
}

/// Parse DER-encoded ECDSA signature to raw (r||s) format.
fn parse_der_signature<const N: usize>(der: &[u8]) -> Result<[u8; N], SignatureError> {
    // DER format: 0x30 <length> 0x02 <r_len> <r> 0x02 <s_len> <s>
    if der.len() < 8 || der[0] != 0x30 {
        return Err(SignatureError::InvalidSignatureFormat(
            "Invalid DER sequence".to_string(),
        ));
    }

    let component_len = N / 2;
    let mut result = [0u8; N];

    let mut pos = 2; // Skip SEQUENCE tag and length

    // Parse R
    if der[pos] != 0x02 {
        return Err(SignatureError::InvalidSignatureFormat(
            "Invalid DER R tag".to_string(),
        ));
    }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;

    // Handle potential leading zero for positive integers
    let r_start = if r_len > component_len && der[pos] == 0x00 {
        pos + 1
    } else {
        pos
    };
    let r_actual_len = if r_len > component_len {
        r_len - 1
    } else {
        r_len
    };

    // Copy R with proper padding
    let r_dest_start = component_len.saturating_sub(r_actual_len);
    result[r_dest_start..component_len].copy_from_slice(&der[r_start..r_start + r_actual_len.min(component_len)]);

    pos += r_len;

    // Parse S
    if der[pos] != 0x02 {
        return Err(SignatureError::InvalidSignatureFormat(
            "Invalid DER S tag".to_string(),
        ));
    }
    pos += 1;
    let s_len = der[pos] as usize;
    pos += 1;

    // Handle potential leading zero
    let s_start = if s_len > component_len && der[pos] == 0x00 {
        pos + 1
    } else {
        pos
    };
    let s_actual_len = if s_len > component_len {
        s_len - 1
    } else {
        s_len
    };

    // Copy S with proper padding
    let s_dest_start = component_len + component_len.saturating_sub(s_actual_len);
    result[s_dest_start..].copy_from_slice(&der[s_start..s_start + s_actual_len.min(component_len)]);

    Ok(result)
}

#[cfg(test)]
mod signature_tests {
    use super::*;

    #[test]
    fn test_verify_es256_raw_signature() {
        // Test with a known good signature (generated externally)
        // This is a placeholder - in production, use actual test vectors
        let public_key = [0u8; 33]; // Would be a real compressed P-256 key
        let message = b"test message";
        let signature = [0u8; 64]; // Would be a real signature

        // This will fail because key/sig are invalid, but tests the code path
        let result = verify_es256(&public_key, message, &signature);
        assert!(result.is_err()); // Invalid key format
    }

    #[test]
    fn test_parse_ecdsa_signature_raw() {
        let raw_sig = [0x42u8; 64];
        let result = parse_ecdsa_signature::<64>(&raw_sig);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), raw_sig);
    }

    #[test]
    fn test_unsupported_algorithm() {
        let result = verify_ecdsa_signature("ES512", &[], &[], &[]);
        assert!(matches!(result, Err(SignatureError::UnsupportedAlgorithm(_))));
    }
}
