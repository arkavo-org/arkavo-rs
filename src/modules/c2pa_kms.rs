//! C2PA claim signer whose P-256 key never leaves a key service (arkavo-rs#104).
//!
//! c2pa hands the signer the COSE `Sig_structure`; we hash it locally, ask the key
//! service to sign the SHA-256 digest, and convert the DER ECDSA signature it returns
//! into the raw `r || s` form COSE ES256 needs. The certificate chain stays a PEM file
//! because it is public.
use std::sync::Arc;

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use c2pa::{Signer, SigningAlg};
use sha2::{Digest, Sha256};

/// Upper bound on one key-service signing call.
const KMS_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A non-exportable P-256 key that signs SHA-256 digests.
pub trait DigestSigner: Send + Sync {
    /// Sign a SHA-256 digest, returning a DER-encoded ECDSA signature.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String>;
}

/// c2pa [`Signer`] backed by a [`DigestSigner`].
pub struct RemoteKeySigner {
    key: Arc<dyn DigestSigner>,
    certs: Vec<Vec<u8>>,
    tsa_url: Option<String>,
}

impl RemoteKeySigner {
    /// `cert_chain_pem` is the signer certificate first, then its CA.
    pub fn new(
        key: Arc<dyn DigestSigner>,
        cert_chain_pem: &[u8],
        tsa_url: Option<String>,
    ) -> Result<Self, String> {
        let certs: Vec<Vec<u8>> = pem::parse_many(cert_chain_pem)
            .map_err(|e| format!("Signing certificate chain is not PEM: {}", e))?
            .into_iter()
            .filter(|block| block.tag() == "CERTIFICATE")
            .map(|block| block.into_contents())
            .collect();
        if certs.is_empty() {
            return Err("Signing certificate chain has no certificate".to_string());
        }
        Ok(Self {
            key,
            certs,
            tsa_url,
        })
    }
}

impl Signer for RemoteKeySigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        let digest: [u8; 32] = Sha256::digest(data).into();
        let der = self
            .key
            .sign_digest(&digest)
            .map_err(|e| c2pa::Error::OtherError(e.into()))?;
        let signature = p256::ecdsa::Signature::from_der(&der)
            .map_err(|e| c2pa::Error::OtherError(format!("Bad ECDSA signature: {}", e).into()))?;
        Ok(signature.to_bytes().to_vec())
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        Ok(self.certs.clone())
    }

    /// Mirrors c2pa's own estimate: signature, certificates, COSE framing and, with a
    /// TSA, room for the timestamp token.
    fn reserve_size(&self) -> usize {
        const RAW_SIGNATURE: usize = 64;
        const COSE_OVERHEAD: usize = 1024;
        const TIME_STAMP_RESERVE: usize = 10000;
        let certs: usize = self.certs.iter().map(Vec::len).sum();
        let time_stamp = if self.tsa_url.is_some() {
            TIME_STAMP_RESERVE
        } else {
            0
        };
        RAW_SIGNATURE + certs + COSE_OVERHEAD + time_stamp
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

/// An AWS KMS `ECC_NIST_P256` signing key.
pub struct KmsKey {
    client: aws_sdk_kms::Client,
    key_id: String,
    runtime: tokio::runtime::Handle,
}

impl KmsKey {
    /// Load AWS credentials from the environment and check that `key_id` is the key
    /// whose public half is in the signer certificate.
    pub async fn connect(key_id: String, signer_cert_der: &[u8]) -> Result<Self, String> {
        let shared = aws_config::load_from_env().await;
        let timeouts = aws_config::timeout::TimeoutConfig::builder()
            .operation_timeout(KMS_CALL_TIMEOUT)
            .build();
        let conf = aws_sdk_kms::config::Builder::from(&shared)
            .timeout_config(timeouts)
            .build();
        let key = Self {
            client: aws_sdk_kms::Client::from_conf(conf),
            key_id,
            runtime: tokio::runtime::Handle::current(),
        };

        let public_key = key
            .client
            .get_public_key()
            .key_id(&key.key_id)
            .send()
            .await
            .map_err(|e| {
                format!(
                    "KMS GetPublicKey failed: {}",
                    aws_sdk_kms::error::DisplayErrorContext(e)
                )
            })?;
        let spki = public_key
            .public_key()
            .ok_or("KMS GetPublicKey returned no public key")?;
        if spki.as_ref() != cert_spki(signer_cert_der)? {
            return Err(
                "The KMS key does not match the signer certificate's public key".to_string(),
            );
        }
        Ok(key)
    }
}

impl DigestSigner for KmsKey {
    /// Blocks on the KMS call; only call from a blocking thread (sign requests run on
    /// `spawn_blocking`).
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
        let request = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send();
        let output = self.runtime.block_on(request).map_err(|e| {
            format!(
                "KMS Sign failed: {}",
                aws_sdk_kms::error::DisplayErrorContext(e)
            )
        })?;
        output
            .signature()
            .map(|signature| signature.as_ref().to_vec())
            .ok_or_else(|| "KMS Sign returned no signature".to_string())
    }
}

/// The DER SubjectPublicKeyInfo of a certificate.
pub fn cert_spki(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("Signer certificate does not parse: {}", e))?;
    Ok(cert.public_key().raw.to_vec())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    /// A local P-256 key standing in for KMS: signs digests, returns DER.
    pub struct LocalKey(pub p256::ecdsa::SigningKey);

    impl DigestSigner for LocalKey {
        fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
            let signature: p256::ecdsa::Signature =
                self.0.sign_prehash(digest).map_err(|e| e.to_string())?;
            Ok(signature.to_der().as_bytes().to_vec())
        }
    }

    /// The signer turns the key service's DER signature into a raw r||s signature that
    /// verifies over the original data.
    #[test]
    fn test_remote_signer_returns_raw_signature() {
        use p256::ecdsa::signature::Verifier;

        let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let verifying = *key.verifying_key();
        let cert = rcgen::generate_simple_self_signed(vec!["test".to_string()]).unwrap();
        let signer =
            RemoteKeySigner::new(Arc::new(LocalKey(key)), cert.cert.pem().as_bytes(), None)
                .unwrap();

        let data = b"COSE Sig_structure bytes";
        let raw = signer.sign(data).unwrap();
        assert_eq!(raw.len(), 64);
        let signature = p256::ecdsa::Signature::from_slice(&raw).unwrap();
        verifying.verify(data, &signature).unwrap();
        assert_eq!(signer.certs().unwrap().len(), 1);
    }

    #[test]
    fn test_remote_signer_reserves_room_for_timestamp() {
        let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let cert = rcgen::generate_simple_self_signed(vec!["test".to_string()]).unwrap();
        let pem = cert.cert.pem();
        let key: Arc<dyn DigestSigner> = Arc::new(LocalKey(key));
        let plain = RemoteKeySigner::new(key.clone(), pem.as_bytes(), None).unwrap();
        let stamped =
            RemoteKeySigner::new(key, pem.as_bytes(), Some("http://tsa".to_string())).unwrap();
        assert_eq!(stamped.reserve_size() - plain.reserve_size(), 10000);
        assert_eq!(stamped.time_authority_url().as_deref(), Some("http://tsa"));
    }

    #[test]
    fn test_remote_signer_needs_a_certificate() {
        let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        assert!(RemoteKeySigner::new(Arc::new(LocalKey(key)), b"no pem here", None).is_err());
    }
}
