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
