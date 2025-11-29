//! NanoTDF Collection-based Encryption for NTDF-RTMP
//!
//! Uses opentdf-rs NanoTdfCollection API for production-grade encryption:
//! - Thread-safe atomic IV counter (CAS-based)
//! - Rotation threshold warnings at 8M items
//! - Wire format: [IV (3B)][ciphertext][tag] - 13 bytes smaller than POC format
//!
//! # Wire Format Comparison
//!
//! POC (deprecated):  [IV (12B)][ciphertext][tag (16B)]
//! Collection:        [IV (3B)][ciphertext][tag (12B)]
//!
//! Savings: 13 bytes per frame (at 30fps = ~1.4MB/hour)

use opentdf_crypto::tdf::{
    NanoTdfCollection, NanoTdfCollectionBuilder, NanoTdfCollectionDecryptor, NanoTdfError,
};
use opentdf_protocol::nanotdf::CollectionItem;
use std::error::Error;
use std::fmt;

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
    /// Collection creation or operation failed
    CollectionError(String),
    /// IV counter exhausted (need new collection)
    IvExhausted,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::PayloadTooShort => write!(f, "Payload too short for decryption"),
            EncryptionError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            EncryptionError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            EncryptionError::KeyAgreementFailed(msg) => write!(f, "Key agreement failed: {}", msg),
            EncryptionError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
            EncryptionError::CollectionError(msg) => write!(f, "Collection error: {}", msg),
            EncryptionError::IvExhausted => write!(f, "IV counter exhausted - create new collection"),
        }
    }
}

impl Error for EncryptionError {}

impl From<NanoTdfError> for EncryptionError {
    fn from(e: NanoTdfError) -> Self {
        match e {
            NanoTdfError::IvExhausted => EncryptionError::IvExhausted,
            other => EncryptionError::CollectionError(other.to_string()),
        }
    }
}

impl From<std::io::Error> for EncryptionError {
    fn from(e: std::io::Error) -> Self {
        EncryptionError::CollectionError(e.to_string())
    }
}

/// Container framing constants for Collection wire format
/// Wire format: [IV (3B)][ciphertext][tag (12B default)]
pub const IV_SIZE: usize = 3;
pub const DEFAULT_TAG_SIZE: usize = 12; // 96-bit tag (Aes256Gcm96)
pub const MIN_ENCRYPTED_SIZE: usize = IV_SIZE + DEFAULT_TAG_SIZE;

/// Create a NanoTDF Collection for publisher-side encryption
///
/// Performs ECDH + HKDF once to derive DEK. All subsequent `encrypt_item()`
/// calls reuse the derived key with atomic IV counter.
///
/// # Arguments
/// * `kas_url` - KAS URL for key rewrap requests
/// * `policy` - Policy bytes (embedded in header)
/// * `kas_public_key` - KAS public key for ECDH (33 bytes compressed P-256)
///
/// # Returns
/// A thread-safe `NanoTdfCollection` for encrypting stream items
pub fn create_collection(
    kas_url: &str,
    policy: &[u8],
    kas_public_key: &[u8],
) -> Result<NanoTdfCollection, EncryptionError> {
    NanoTdfCollectionBuilder::new()
        .kas_url(kas_url)
        .policy_plaintext(policy.to_vec())
        .build(kas_public_key)
        .map_err(|e| EncryptionError::CollectionError(e.to_string()))
}

/// Get the NanoTDF header bytes from a collection (manifest for late joiners)
///
/// # Arguments
/// * `collection` - The NanoTDF collection
///
/// # Returns
/// Raw header bytes to be sent to subscribers
pub fn collection_header_bytes(collection: &NanoTdfCollection) -> Result<Vec<u8>, EncryptionError> {
    collection
        .to_header_bytes()
        .map_err(|e| EncryptionError::CollectionError(e.to_string()))
}

/// Create a decryptor for subscriber-side decryption (KAS-side with private key)
///
/// # Arguments
/// * `header_bytes` - Raw NanoTDF header bytes from manifest
/// * `kas_private_key` - KAS EC private key (PKCS#8 DER format)
///
/// # Returns
/// A `NanoTdfCollectionDecryptor` for decrypting stream items
pub fn create_decryptor_kas(
    header_bytes: &[u8],
    kas_private_key: &[u8],
) -> Result<NanoTdfCollectionDecryptor, EncryptionError> {
    NanoTdfCollectionDecryptor::from_header_with_kas_key(header_bytes, kas_private_key)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

/// Create a decryptor with pre-derived DEK (client-side after KAS rewrap)
///
/// # Arguments
/// * `header_bytes` - Raw NanoTDF header bytes from manifest
/// * `dek` - 32-byte DEK returned from KAS rewrap
///
/// # Returns
/// A `NanoTdfCollectionDecryptor` for decrypting stream items
pub fn create_decryptor_dek(
    header_bytes: &[u8],
    dek: &[u8],
) -> Result<NanoTdfCollectionDecryptor, EncryptionError> {
    NanoTdfCollectionDecryptor::from_header_with_dek(header_bytes, dek)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

/// Encrypt a single FLV payload (thread-safe via atomic IV counter)
///
/// Uses container framing format: [IV (3B)][ciphertext][tag]
///
/// # Arguments
/// * `collection` - The NanoTDF collection (thread-safe)
/// * `plaintext` - Raw FLV payload data
///
/// # Returns
/// Encrypted bytes in container framing format
pub fn encrypt_item(
    collection: &NanoTdfCollection,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let item = collection.encrypt_item(plaintext)?;
    Ok(item.to_bytes())
}

/// Decrypt a single FLV payload
///
/// Expects container framing format: [IV (3B)][ciphertext][tag]
///
/// # Arguments
/// * `decryptor` - The collection decryptor
/// * `encrypted` - Encrypted bytes in container framing format
///
/// # Returns
/// Decrypted plaintext FLV payload
pub fn decrypt_item(
    decryptor: &NanoTdfCollectionDecryptor,
    encrypted: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let item = CollectionItem::from_bytes(encrypted)?;
    decryptor
        .decrypt_item(&item)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

/// Check if collection rotation threshold reached (early warning at 8M items)
///
/// When this returns true, consider initiating key rotation for the stream.
pub fn rotation_threshold_reached(collection: &NanoTdfCollection) -> bool {
    collection.rotation_threshold_reached()
}

/// Check if collection IV space is exhausted (hard limit at 16.7M items)
///
/// When this returns true, no more items can be encrypted. A new collection
/// must be created.
pub fn is_exhausted(collection: &NanoTdfCollection) -> bool {
    collection.is_exhausted()
}

/// Get remaining capacity before IV exhaustion
pub fn remaining_capacity(collection: &NanoTdfCollection) -> u32 {
    collection.remaining_capacity()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generate test keypair for P-256
    fn generate_test_keypair() -> (Vec<u8>, Vec<u8>) {
        use p256::pkcs8::EncodePrivateKey;
        use p256::SecretKey;
        use rand_core::OsRng;

        let secret = SecretKey::random(&mut OsRng);
        let public = secret.public_key().to_sec1_bytes().to_vec();
        let private = secret.to_pkcs8_der().unwrap().as_bytes().to_vec();
        (public, private)
    }

    #[test]
    fn test_collection_encrypt_decrypt_roundtrip() {
        let (public_key, private_key) = generate_test_keypair();
        let plaintext = b"Hello NTDF-RTMP! This is a test video frame payload.";

        // Create collection
        let collection = create_collection(
            "https://kas.example.com/kas",
            b"test-policy",
            &public_key,
        )
        .expect("Collection creation should succeed");

        // Get header bytes
        let header_bytes = collection_header_bytes(&collection).expect("Header serialization");

        // Encrypt
        let encrypted = encrypt_item(&collection, plaintext).expect("Encryption should succeed");

        // Verify wire format: [IV (3B)][ciphertext][tag (12B)]
        assert!(encrypted.len() >= MIN_ENCRYPTED_SIZE);
        assert_eq!(
            encrypted.len(),
            IV_SIZE + plaintext.len() + DEFAULT_TAG_SIZE
        );

        // Create decryptor
        let decryptor =
            create_decryptor_kas(&header_bytes, &private_key).expect("Decryptor creation");

        // Decrypt
        let decrypted = decrypt_item(&decryptor, &encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_decrypt_payload_too_short() {
        let (public_key, private_key) = generate_test_keypair();

        let collection = create_collection(
            "https://kas.example.com/kas",
            b"test-policy",
            &public_key,
        )
        .expect("Collection creation should succeed");

        let header_bytes = collection_header_bytes(&collection).expect("Header serialization");
        let decryptor = create_decryptor_kas(&header_bytes, &private_key).expect("Decryptor");

        let short_payload = [0u8; 2]; // Less than MIN_ENCRYPTED_SIZE
        let result = decrypt_item(&decryptor, &short_payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_unique_ivs() {
        let (public_key, _private_key) = generate_test_keypair();
        let plaintext = b"Same plaintext";

        let collection = create_collection(
            "https://kas.example.com/kas",
            b"test-policy",
            &public_key,
        )
        .expect("Collection creation should succeed");

        let encrypted1 = encrypt_item(&collection, plaintext).expect("Encryption should succeed");
        let encrypted2 = encrypt_item(&collection, plaintext).expect("Encryption should succeed");

        // IVs should be different (counter-based, incrementing)
        assert_ne!(&encrypted1[..IV_SIZE], &encrypted2[..IV_SIZE]);
        // Ciphertexts should also be different due to different IVs
        assert_ne!(encrypted1, encrypted2);

        // Verify IV values are sequential (1, 2)
        let iv1 = u32::from_be_bytes([0, encrypted1[0], encrypted1[1], encrypted1[2]]);
        let iv2 = u32::from_be_bytes([0, encrypted2[0], encrypted2[1], encrypted2[2]]);
        assert_eq!(iv1, 1);
        assert_eq!(iv2, 2);
    }

    #[test]
    fn test_rotation_threshold() {
        let (public_key, _private_key) = generate_test_keypair();

        // Set threshold to 5 - will be reached when IV counter reaches 5
        let collection = NanoTdfCollectionBuilder::new()
            .kas_url("https://kas.example.com/kas")
            .policy_plaintext(b"test-policy".to_vec())
            .rotation_threshold(5)
            .build(&public_key)
            .expect("Collection creation should succeed");

        // IV starts at 1, so rotation_threshold_reached returns current_iv >= threshold
        // After N encryptions: current_iv = N + 1 (because counter increments after returning value)
        assert!(!rotation_threshold_reached(&collection)); // current_iv = 1

        // Encrypt 3 items: IV goes from 1 -> 2 -> 3 -> 4
        for i in 0..3 {
            encrypt_item(&collection, b"test").expect("Encrypt");
            // After encryption i: current_iv = i + 2
            let should_be_reached = (i + 2) >= 5;
            assert_eq!(
                rotation_threshold_reached(&collection),
                should_be_reached,
                "After {} encryptions, current_iv should be {}",
                i + 1,
                i + 2
            );
        }

        // After 3 items, current_iv = 4, still below threshold
        assert!(!rotation_threshold_reached(&collection));

        // Fourth item: IV goes from 4 -> 5
        encrypt_item(&collection, b"test").expect("Encrypt");
        // Now current_iv = 5, which equals threshold
        assert!(rotation_threshold_reached(&collection));
    }

    #[test]
    fn test_remaining_capacity() {
        let (public_key, _private_key) = generate_test_keypair();

        let collection = create_collection(
            "https://kas.example.com/kas",
            b"test-policy",
            &public_key,
        )
        .expect("Collection creation should succeed");

        // Initial capacity is MAX_IV (16,777,215)
        let initial = remaining_capacity(&collection);
        assert_eq!(initial, 0x00FF_FFFF);

        // After encrypting one item
        encrypt_item(&collection, b"test").expect("Encrypt");
        assert_eq!(remaining_capacity(&collection), initial - 1);
    }

    #[test]
    fn test_empty_plaintext() {
        let (public_key, private_key) = generate_test_keypair();
        let plaintext = b"";

        let collection = create_collection(
            "https://kas.example.com/kas",
            b"test-policy",
            &public_key,
        )
        .expect("Collection creation should succeed");

        let header_bytes = collection_header_bytes(&collection).expect("Header");
        let encrypted = encrypt_item(&collection, plaintext).expect("Encryption should succeed");
        assert_eq!(encrypted.len(), IV_SIZE + DEFAULT_TAG_SIZE);

        let decryptor = create_decryptor_kas(&header_bytes, &private_key).expect("Decryptor");
        let decrypted = decrypt_item(&decryptor, &encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
