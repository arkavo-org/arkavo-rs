//! FLV Payload Encryption/Decryption for NTDF-RTMP
//!
//! Per NTDF-RTMP spec, encrypted FLV payloads have the format:
//! `IV (12 bytes) + Ciphertext + AuthTag (16 bytes)`
//!
//! Uses AES-256-GCM consistent with the existing crypto module.

#![allow(deprecated)]

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::{Aead, Key};
use aes_gcm::Aes256Gcm;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use std::error::Error;
use std::fmt;

use crate::modules::crypto;

/// Encryption error types
#[derive(Debug)]
pub enum EncryptionError {
    /// Payload is too short to contain IV and auth tag
    PayloadTooShort,
    /// AES-GCM encryption failed
    EncryptionFailed(String),
    /// AES-GCM decryption failed (invalid ciphertext or auth tag)
    DecryptionFailed(String),
    /// ECDH key agreement failed
    KeyAgreementFailed(String),
    /// Invalid public key format
    InvalidPublicKey(String),
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::PayloadTooShort => write!(f, "Payload too short for decryption"),
            EncryptionError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            EncryptionError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            EncryptionError::KeyAgreementFailed(msg) => write!(f, "Key agreement failed: {}", msg),
            EncryptionError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
        }
    }
}

impl Error for EncryptionError {}

/// Minimum encrypted payload size: 12 (IV) + 16 (auth tag)
pub const MIN_ENCRYPTED_SIZE: usize = 28;

/// IV size for AES-256-GCM
pub const IV_SIZE: usize = 12;

/// Auth tag size for AES-256-GCM
pub const AUTH_TAG_SIZE: usize = 16;

/// Derive DEK from NanoTDF manifest ephemeral key and KAS private key
///
/// Performs ECDH key agreement between the KAS private key and the
/// ephemeral public key from the NanoTDF manifest.
///
/// # Arguments
/// * `ephemeral_key` - Compressed P-256 public key (33 bytes) from manifest
/// * `kas_private_key` - KAS EC private key (32 bytes)
///
/// # Returns
/// 32-byte DEK suitable for AES-256-GCM
pub fn derive_dek(
    ephemeral_key: &[u8],
    kas_private_key: &[u8; 32],
) -> Result<[u8; 32], EncryptionError> {
    // Parse ephemeral public key
    let ephemeral_pubkey = PublicKey::from_sec1_bytes(ephemeral_key)
        .map_err(|e| EncryptionError::InvalidPublicKey(e.to_string()))?;

    // Parse KAS private key
    let kas_secret = SecretKey::from_bytes(&(*kas_private_key).into())
        .map_err(|e| EncryptionError::InvalidPublicKey(format!("Invalid KAS key: {}", e)))?;

    // Perform ECDH - use custom_ecdh for x-coordinate extraction
    let shared_secret = crypto::custom_ecdh(&kas_secret, &ephemeral_pubkey)
        .map_err(|e| EncryptionError::KeyAgreementFailed(e.to_string()))?;

    // Ensure we have 32 bytes
    if shared_secret.len() != 32 {
        return Err(EncryptionError::KeyAgreementFailed(format!(
            "Expected 32-byte shared secret, got {}",
            shared_secret.len()
        )));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&shared_secret);
    Ok(dek)
}

/// Encrypt FLV payload for NTDF-RTMP
///
/// Encrypts plaintext using AES-256-GCM and returns:
/// `IV (12 bytes) + ciphertext + auth_tag (16 bytes)`
///
/// # Arguments
/// * `dek` - Data Encryption Key (32 bytes)
/// * `plaintext` - Raw FLV payload data
///
/// # Returns
/// Encrypted payload with IV prefix and auth tag suffix
pub fn encrypt_payload(dek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    // Generate random IV
    let mut iv = [0u8; IV_SIZE];
    OsRng.fill_bytes(&mut iv);

    // Create cipher
    let key = Key::<Aes256Gcm>::from(*dek);
    let cipher = Aes256Gcm::new(&key);
    let nonce = GenericArray::from_slice(&iv);

    // Encrypt (ciphertext includes auth tag at the end)
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    // Combine: IV + ciphertext (with auth tag)
    let mut result = Vec::with_capacity(IV_SIZE + ciphertext.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt FLV payload for NTDF-RTMP
///
/// Decrypts payload that was encrypted with `encrypt_payload`.
/// Expects format: `IV (12 bytes) + ciphertext + auth_tag (16 bytes)`
///
/// # Arguments
/// * `dek` - Data Encryption Key (32 bytes)
/// * `encrypted` - Encrypted payload from RTMP stream
///
/// # Returns
/// Decrypted plaintext FLV payload
pub fn decrypt_payload(dek: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if encrypted.len() < MIN_ENCRYPTED_SIZE {
        return Err(EncryptionError::PayloadTooShort);
    }

    // Extract IV and ciphertext
    let iv = &encrypted[..IV_SIZE];
    let ciphertext = &encrypted[IV_SIZE..];

    // Create cipher
    let key = Key::<Aes256Gcm>::from(*dek);
    let cipher = Aes256Gcm::new(&key);
    let nonce = GenericArray::from_slice(iv);

    // Decrypt (aes-gcm verifies auth tag internally)
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dek = [0x42u8; 32];
        let plaintext = b"Hello NTDF-RTMP! This is a test video frame payload.";

        let encrypted = encrypt_payload(&dek, plaintext).expect("Encryption should succeed");

        // Verify format
        assert!(encrypted.len() >= MIN_ENCRYPTED_SIZE);
        assert_eq!(encrypted.len(), IV_SIZE + plaintext.len() + AUTH_TAG_SIZE);

        let decrypted = decrypt_payload(&dek, &encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_decrypt_payload_too_short() {
        let dek = [0x42u8; 32];
        let short_payload = [0u8; 20]; // Less than MIN_ENCRYPTED_SIZE

        let result = decrypt_payload(&dek, &short_payload);
        assert!(matches!(result, Err(EncryptionError::PayloadTooShort)));
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let dek1 = [0x42u8; 32];
        let dek2 = [0x43u8; 32];
        let plaintext = b"Secret data";

        let encrypted = encrypt_payload(&dek1, plaintext).expect("Encryption should succeed");
        let result = decrypt_payload(&dek2, &encrypted);

        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let dek = [0x42u8; 32];
        let plaintext = b"Secret data";

        let mut encrypted = encrypt_payload(&dek, plaintext).expect("Encryption should succeed");

        // Tamper with ciphertext
        if encrypted.len() > IV_SIZE + 5 {
            encrypted[IV_SIZE + 5] ^= 0xFF;
        }

        let result = decrypt_payload(&dek, &encrypted);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
    }

    #[test]
    fn test_empty_plaintext() {
        let dek = [0x42u8; 32];
        let plaintext = b"";

        let encrypted = encrypt_payload(&dek, plaintext).expect("Encryption should succeed");
        assert_eq!(encrypted.len(), IV_SIZE + AUTH_TAG_SIZE);

        let decrypted = decrypt_payload(&dek, &encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_unique_ivs() {
        let dek = [0x42u8; 32];
        let plaintext = b"Same plaintext";

        let encrypted1 = encrypt_payload(&dek, plaintext).expect("Encryption should succeed");
        let encrypted2 = encrypt_payload(&dek, plaintext).expect("Encryption should succeed");

        // IVs should be different (random)
        assert_ne!(&encrypted1[..IV_SIZE], &encrypted2[..IV_SIZE]);
        // Ciphertexts should also be different due to different IVs
        assert_ne!(encrypted1, encrypted2);
    }
}
