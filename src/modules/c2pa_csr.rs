//! Certificate request (PKCS #10) for the C2PA claim signing certificate, signed by
//! the KMS key (arkavo-rs#131).
//!
//! The request follows the C2PA Assurance Level 1 CSR profile
//! (conformance-public `docs/v0.2/cert-profiles/claimSigningLeaf.al1.csr.schema.json`):
//! subject C, O and CN, and these requested extensions:
//!
//! | Extension | Critical | Value |
//! |---|---|---|
//! | basicConstraints | yes | cA false |
//! | keyUsage | yes | digitalSignature, contentCommitment |
//! | extKeyUsage | no | c2pa-kp-claimSigning, id-kp-emailProtection |
//! | certificatePolicies | no | c2pa certificate policy |
//! | c2pa-al | no | c2pa-assuranceLevel-1 |
//! | c2pa-cpl-record | no | Conforming Products List record UUID |

use crate::modules::c2pa_kms::DigestSigner;
use p256::pkcs8::DecodePublicKey;
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair, RemoteKeyPair,
    SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];
const OID_EXT_KEY_USAGE: &[u64] = &[2, 5, 29, 37];
const OID_CERTIFICATE_POLICIES: &[u64] = &[2, 5, 29, 32];
const OID_C2PA_AL: &[u64] = &[1, 3, 6, 1, 4, 1, 62558, 3];
const OID_C2PA_CPL_RECORD: &[u64] = &[1, 3, 6, 1, 4, 1, 62558, 4];

const OID_KP_C2PA_CLAIM_SIGNING: &[u64] = &[1, 3, 6, 1, 4, 1, 62558, 2, 1];
const OID_KP_EMAIL_PROTECTION: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 4];
const OID_C2PA_CERTIFICATE_POLICY: &[u64] = &[1, 3, 6, 1, 4, 1, 62558, 1, 1];
const OID_C2PA_ASSURANCE_LEVEL_1: &[u64] = &[1, 3, 6, 1, 4, 1, 62558, 3, 10];

/// The certificate subject. It must match the product's Conforming Products List
/// record exactly.
pub struct CsrSubject {
    pub country: String,
    pub organization: String,
    pub common_name: String,
}

/// Builds the AL1 claim signing CSR for the key `spki_der` (DER SubjectPublicKeyInfo,
/// as KMS `GetPublicKey` returns it), signed by `signer`. Returns PEM.
///
/// Blocks on `signer`; with the KMS key, call it from a blocking thread.
pub fn al1_claim_signing_csr(
    signer: Arc<dyn DigestSigner>,
    spki_der: &[u8],
    subject: &CsrSubject,
    cpl_record: &uuid::Uuid,
) -> Result<String, String> {
    if subject.country.len() != 2 || !subject.country.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(format!(
            "country must be a two-letter ISO 3166 code, got {:?}",
            subject.country
        ));
    }
    if subject.organization.trim().is_empty() || subject.common_name.trim().is_empty() {
        return Err("organization and common name are required".to_string());
    }
    let public_key = p256::PublicKey::from_public_key_der(spki_der)
        .map_err(|e| format!("the key is not a P-256 public key: {}", e))?;
    let key = KeyPair::from_remote(Box::new(RemoteKey {
        public_raw: public_key.to_sec1_bytes().to_vec(),
        signer,
    }))
    .map_err(|e| e.to_string())?;

    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CountryName, subject.country.as_str());
    name.push(DnType::OrganizationName, subject.organization.as_str());
    name.push(DnType::CommonName, subject.common_name.as_str());
    params.distinguished_name = name;
    params.custom_extensions = al1_extensions(cpl_record);

    let csr = params
        .serialize_request(&key)
        .map_err(|e| format!("CSR signing failed: {}", e))?;
    csr.pem().map_err(|e| e.to_string())
}

fn al1_extensions(cpl_record: &uuid::Uuid) -> Vec<CustomExtension> {
    let extension = |oid: &[u64], critical: bool, value: Vec<u8>| {
        let mut ext = CustomExtension::from_oid_content(oid, value);
        ext.set_criticality(critical);
        ext
    };
    vec![
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }; cA false is
        // the default, so DER omits it.
        extension(OID_BASIC_CONSTRAINTS, true, tlv(0x30, &[])),
        // KeyUsage BIT STRING: digitalSignature (bit 0) and contentCommitment (bit 1);
        // six unused bits.
        extension(OID_KEY_USAGE, true, tlv(0x03, &[0x06, 0b1100_0000])),
        extension(
            OID_EXT_KEY_USAGE,
            false,
            tlv(
                0x30,
                &[oid(OID_KP_C2PA_CLAIM_SIGNING), oid(OID_KP_EMAIL_PROTECTION)].concat(),
            ),
        ),
        // certificatePolicies ::= SEQUENCE OF PolicyInformation { policyIdentifier }
        extension(
            OID_CERTIFICATE_POLICIES,
            false,
            tlv(0x30, &tlv(0x30, &oid(OID_C2PA_CERTIFICATE_POLICY))),
        ),
        extension(OID_C2PA_AL, false, oid(OID_C2PA_ASSURANCE_LEVEL_1)),
        // UTF8String (SIZE 36): the hyphenated lowercase UUID
        extension(
            OID_C2PA_CPL_RECORD,
            false,
            tlv(0x0c, cpl_record.hyphenated().to_string().as_bytes()),
        ),
    ]
}

/// One DER element; `content` is under 64 KiB here.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n <= 0xff => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// A DER OBJECT IDENTIFIER.
fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut groups = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            groups.push((rest & 0x7f) as u8 | 0x80);
            rest >>= 7;
        }
        content.extend(groups.iter().rev());
    }
    tlv(0x06, &content)
}

const USAGE: &str = "usage: arks c2pa-csr (--kms-key-id <id> | --key-file <pkcs8.pem>) \
--country <CC> --organization <O> --common-name <CN> --cpl-record <uuid> [--out <req.pem>]

Writes the C2PA AL1 claim signing CSR (PEM) to --out, or to stdout. --kms-key-id uses
AWS credentials from the environment and needs kms:GetPublicKey and kms:Sign on the
key. --key-file takes a P-256 PKCS#8 PEM key, for rehearsals only.";

/// `arks c2pa-csr ...`: writes the CSR and prints the key's SPKI SHA-256 to stderr.
pub async fn run_cli(args: Vec<String>) -> Result<(), String> {
    let mut flags = std::collections::HashMap::new();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let name = flag
            .strip_prefix("--")
            .filter(|n| {
                [
                    "kms-key-id",
                    "key-file",
                    "country",
                    "organization",
                    "common-name",
                    "cpl-record",
                    "out",
                ]
                .contains(n)
            })
            .ok_or_else(|| format!("unknown argument {:?}\n\n{}", flag, USAGE))?
            .to_string();
        let value = it
            .next()
            .ok_or_else(|| format!("--{} needs a value\n\n{}", name, USAGE))?;
        if flags.insert(name.clone(), value).is_some() {
            return Err(format!("--{} given twice", name));
        }
    }
    let required = |name: &str| {
        flags
            .get(name)
            .cloned()
            .ok_or_else(|| format!("--{} is required\n\n{}", name, USAGE))
    };
    let subject = CsrSubject {
        country: required("country")?,
        organization: required("organization")?,
        common_name: required("common-name")?,
    };
    let cpl_record: uuid::Uuid = required("cpl-record")?
        .parse()
        .map_err(|e| format!("--cpl-record is not a UUID: {}", e))?;

    let (signer, spki): (Arc<dyn DigestSigner>, Vec<u8>) =
        match (flags.get("kms-key-id"), flags.get("key-file")) {
            (Some(key_id), None) => {
                let (key, spki) = crate::modules::c2pa_kms::KmsKey::open(key_id.clone())
                    .await
                    .map_err(|e| format!("{:?}", e))?;
                (Arc::new(key), spki)
            }
            (None, Some(path)) => {
                let pem = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read {}: {}", path, e))?;
                let key = FileKey::from_pem(&pem)?;
                let spki = key.spki()?;
                (Arc::new(key), spki)
            }
            _ => {
                return Err(format!(
                    "give exactly one of --kms-key-id and --key-file\n\n{}",
                    USAGE
                ))
            }
        };

    // The KMS signer blocks on the runtime, so sign off the async workers
    let spki_for_csr = spki.clone();
    let pem = tokio::task::spawn_blocking(move || {
        al1_claim_signing_csr(signer, &spki_for_csr, &subject, &cpl_record)
    })
    .await
    .map_err(|e| e.to_string())??;

    match flags.get("out") {
        Some(path) => {
            std::fs::write(path, &pem).map_err(|e| format!("cannot write {}: {}", path, e))?
        }
        None => print!("{}", pem),
    }
    eprintln!("key SPKI SHA-256: {}", hex::encode(Sha256::digest(&spki)));
    Ok(())
}

/// A local P-256 key from a PKCS#8 PEM file, for rehearsing the procedure.
struct FileKey(p256::ecdsa::SigningKey);

impl FileKey {
    fn from_pem(pem: &str) -> Result<Self, String> {
        use p256::pkcs8::DecodePrivateKey;
        p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
            .map(Self)
            .map_err(|e| format!("not a P-256 PKCS#8 private key: {}", e))
    }

    fn spki(&self) -> Result<Vec<u8>, String> {
        use p256::pkcs8::EncodePublicKey;
        self.0
            .verifying_key()
            .to_public_key_der()
            .map(|d| d.as_bytes().to_vec())
            .map_err(|e| e.to_string())
    }
}

impl DigestSigner for FileKey {
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: p256::ecdsa::Signature =
            self.0.sign_prehash(digest).map_err(|e| e.to_string())?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// The KMS key as rcgen's remote key: rcgen hands over the CertificationRequestInfo
/// and expects a DER ECDSA P-256 SHA-256 signature.
struct RemoteKey {
    public_raw: Vec<u8>,
    signer: Arc<dyn DigestSigner>,
}

impl RemoteKeyPair for RemoteKey {
    fn public_key(&self) -> &[u8] {
        &self.public_raw
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let digest: [u8; 32] = Sha256::digest(msg).into();
        self.signer
            .sign_digest(&digest)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::c2pa_kms::tests::LocalKey;
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::EncodePublicKey;
    use x509_parser::prelude::*;

    const RECORD: &str = "0f6b6c1e-6a3e-4d55-9b1b-2c4c8f0f7a11";

    fn request() -> (String, Vec<u8>) {
        let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let subject = CsrSubject {
            country: "US".into(),
            organization: "Arkavo LLC".into(),
            common_name: "Arkavo Creator".into(),
        };
        let pem = al1_claim_signing_csr(
            Arc::new(LocalKey(key)),
            &spki,
            &subject,
            &RECORD.parse().unwrap(),
        )
        .unwrap();
        (pem, spki)
    }

    #[test]
    fn oid_encoding_matches_der() {
        // 1.3.6.1.4.1.62558.2.1: 62558 needs three base-128 groups
        assert_eq!(
            oid(OID_KP_C2PA_CLAIM_SIGNING),
            [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xe8, 0x5e, 0x02, 0x01]
        );
        assert_eq!(
            oid(OID_KP_EMAIL_PROTECTION),
            [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04]
        );
    }

    #[test]
    fn csr_is_self_signed_by_the_key_and_carries_its_public_key() {
        let (pem, spki) = request();
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let (_, csr) = X509CertificationRequest::from_der(&pem.contents).unwrap();
        let info = &csr.certification_request_info;
        assert_eq!(info.subject_pki.raw, spki.as_slice());
        let verifying = p256::ecdsa::VerifyingKey::from_public_key_der(&spki).unwrap();
        let signature = p256::ecdsa::Signature::from_der(&csr.signature_value.data).unwrap();
        verifying
            .verify(info.raw, &signature)
            .expect("signature over CertificationRequestInfo");
        assert_eq!(
            csr.signature_algorithm.algorithm.to_id_string(),
            "1.2.840.10045.4.3.2"
        );
    }

    #[test]
    fn csr_follows_the_al1_profile() {
        let (pem, _) = request();
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        let (_, csr) = X509CertificationRequest::from_der(&pem.contents).unwrap();
        let info = &csr.certification_request_info;

        let subject: Vec<(String, String)> = info
            .subject
            .iter_attributes()
            .map(|a| {
                (
                    a.attr_type().to_id_string(),
                    a.as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            subject,
            [
                ("2.5.4.6".to_string(), "US".to_string()),
                ("2.5.4.10".to_string(), "Arkavo LLC".to_string()),
                ("2.5.4.3".to_string(), "Arkavo Creator".to_string()),
            ]
        );

        let extensions: Vec<_> = csr.requested_extensions().unwrap().collect();
        assert_eq!(extensions.len(), 6, "only the AL1 extensions are requested");
        let mut seen = std::collections::HashMap::new();
        for ext in csr.requested_extensions().unwrap() {
            match ext {
                ParsedExtension::BasicConstraints(bc) => {
                    assert!(!bc.ca);
                    seen.insert("bc", ());
                }
                ParsedExtension::KeyUsage(ku) => {
                    assert!(ku.digital_signature() && ku.non_repudiation());
                    assert_eq!(ku.flags, 0b11, "no other key usage bits");
                    seen.insert("ku", ());
                }
                ParsedExtension::ExtendedKeyUsage(eku) => {
                    assert!(eku.email_protection);
                    let other: Vec<String> = eku.other.iter().map(|o| o.to_id_string()).collect();
                    assert_eq!(other, ["1.3.6.1.4.1.62558.2.1"]);
                    seen.insert("eku", ());
                }
                ParsedExtension::CertificatePolicies(policies) => {
                    let ids: Vec<String> = policies
                        .iter()
                        .map(|p| p.policy_id.to_id_string())
                        .collect();
                    assert_eq!(ids, ["1.3.6.1.4.1.62558.1.1"]);
                    seen.insert("cp", ());
                }
                ParsedExtension::UnsupportedExtension { .. } => {}
                other => panic!("unexpected extension {:?}", other),
            }
        }
        assert_eq!(seen.len(), 4);

        // Criticality and the two C2PA extensions, from the raw extension list
        let raw = info
            .attributes()
            .iter()
            .find_map(|a| match a.parsed_attribute() {
                ParsedCriAttribute::ExtensionRequest(req) => Some(&req.extensions),
                _ => None,
            })
            .unwrap();
        let by_oid: std::collections::HashMap<String, &X509Extension> =
            raw.iter().map(|e| (e.oid.to_id_string(), e)).collect();
        for (id, critical) in [
            ("2.5.29.19", true),
            ("2.5.29.15", true),
            ("2.5.29.37", false),
            ("2.5.29.32", false),
            ("1.3.6.1.4.1.62558.3", false),
            ("1.3.6.1.4.1.62558.4", false),
        ] {
            assert_eq!(by_oid[id].critical, critical, "{id} criticality");
        }
        assert_eq!(
            by_oid["1.3.6.1.4.1.62558.3"].value,
            oid(OID_C2PA_ASSURANCE_LEVEL_1).as_slice()
        );
        let record = by_oid["1.3.6.1.4.1.62558.4"].value;
        assert_eq!(&record[..2], &[0x0c, 36]);
        assert_eq!(&record[2..], RECORD.as_bytes());
    }

    #[test]
    fn rejects_a_bad_subject_or_key() {
        let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let spki = key.verifying_key().to_public_key_der().unwrap();
        let signer: Arc<dyn DigestSigner> = Arc::new(LocalKey(key));
        let record = RECORD.parse().unwrap();
        let subject = |c: &str| CsrSubject {
            country: c.into(),
            organization: "Arkavo LLC".into(),
            common_name: "Arkavo Creator".into(),
        };
        assert!(
            al1_claim_signing_csr(signer.clone(), spki.as_bytes(), &subject("usa"), &record)
                .is_err()
        );
        assert!(al1_claim_signing_csr(signer, b"not a key", &subject("US"), &record).is_err());
    }
}
