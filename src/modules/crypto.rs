use p256::PublicKey;
use std::error::Error;

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

#[allow(dead_code)]
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
#[allow(dead_code)]
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
fn verify_es256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignatureError> {
    use ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

    // Try to parse signature - could be raw (r||s) or DER encoded
    let sig = parse_ecdsa_signature::<64>(signature)?;

    let p256_sig = Signature::from_slice(&sig)
        .map_err(|e| SignatureError::InvalidSignatureFormat(e.to_string()))?;

    Ok(verifying_key.verify(message, &p256_sig).is_ok())
}

/// Verify ES384 (P-384/secp384r1) signature.
fn verify_es384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, SignatureError> {
    use ecdsa::signature::Verifier;
    use p384::ecdsa::{Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?;

    // Try to parse signature - could be raw (r||s) or DER encoded
    let sig = parse_ecdsa_signature::<96>(signature)?;

    let p384_sig = Signature::from_slice(&sig)
        .map_err(|e| SignatureError::InvalidSignatureFormat(e.to_string()))?;

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
    result[r_dest_start..component_len]
        .copy_from_slice(&der[r_start..r_start + r_actual_len.min(component_len)]);

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
    result[s_dest_start..]
        .copy_from_slice(&der[s_start..s_start + s_actual_len.min(component_len)]);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(
            result,
            Err(SignatureError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn test_verify_es256_invalid_key() {
        let public_key = [0u8; 33]; // Invalid key
        let message = b"test message";
        let signature = [0u8; 64];

        let result = verify_es256(&public_key, message, &signature);
        assert!(result.is_err());
    }
}
