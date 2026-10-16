//! Env → license state. Missing credentials fail closed (key requests 503),
//! they never fall back to issuing unauthorized keys.

use super::pdp::PlatformPdp;
use super::person_token::PersonTokenVerifier;
use super::tdf_policy::normalize_kas_url;
use crate::modules::authzen::cose_keys::CoseKeyCache;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;

pub struct LicenseAuthz {
    pub pdp: PlatformPdp,
    pub kas_urls: Vec<String>,
    pub lease_secs: u32,
    /// The KSM-only wrapping key for the key-envelope profile
    /// (`MEDIA_ENVELOPE_RSA_KEY_PATH`). Unset: envelope manifests are refused.
    pub envelope_rsa: Option<Arc<RsaPrivateKey>>,
}

fn envelope_key_from_env() -> Result<Option<Arc<RsaPrivateKey>>, String> {
    let Ok(path) = std::env::var("MEDIA_ENVELOPE_RSA_KEY_PATH") else {
        log::info!("FairPlay key-envelope profile disabled: MEDIA_ENVELOPE_RSA_KEY_PATH is unset");
        return Ok(None);
    };
    let pem = std::fs::read_to_string(&path)
        .map_err(|e| format!("MEDIA_ENVELOPE_RSA_KEY_PATH unreadable: {e}"))?;
    let key = RsaPrivateKey::from_pkcs8_pem(&pem)
        .map_err(|_| "MEDIA_ENVELOPE_RSA_KEY_PATH is not a PKCS#8 RSA private key".to_string())?;
    Ok(Some(Arc::new(key)))
}

fn issuer() -> String {
    std::env::var("OIDC_ISSUER").unwrap_or_else(|_| "https://identity.arkavo.net".to_string())
}

pub fn person_verifier_from_env() -> PersonTokenVerifier {
    let iss = issuer();
    let keys_url = format!("{}/.well-known/cose-keys", iss.trim_end_matches('/'));
    let aud = std::env::var("MEDIA_PLATFORM_AUDIENCE")
        .unwrap_or_else(|_| "https://platform.arkavo.net".to_string());
    PersonTokenVerifier::new(CoseKeyCache::new(keys_url), iss, aud)
}

pub fn license_authz_from_env(platform_url: Option<&str>) -> Result<Option<LicenseAuthz>, String> {
    let Some(platform_url) = platform_url else {
        log::warn!("FairPlay licensing disabled: OPENTDF_PLATFORM_URL is unset");
        return Ok(None);
    };
    let Ok(secret) = std::env::var("ARKS_MEDIA_CLIENT_SECRET") else {
        log::warn!("FairPlay licensing disabled: ARKS_MEDIA_CLIENT_SECRET is unset");
        return Ok(None);
    };
    let client_id =
        std::env::var("ARKS_MEDIA_CLIENT_ID").unwrap_or_else(|_| "arks-media".to_string());
    let token_url = format!("{}/oauth/token", issuer().trim_end_matches('/'));
    let raw_kas = std::env::var("MEDIA_KAS_URLS")
        .unwrap_or_else(|_| "https://platform.arkavo.net".to_string());
    let kas_urls = raw_kas
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| normalize_kas_url(s).ok_or_else(|| format!("invalid MEDIA_KAS_URLS entry: {s}")))
        .collect::<Result<Vec<_>, _>>()?;
    let lease_secs = match std::env::var("MEDIA_FPS_LEASE_SECONDS") {
        Ok(s) => s
            .parse::<u32>()
            .map_err(|_| format!("invalid MEDIA_FPS_LEASE_SECONDS: {s}"))?,
        Err(_) => 3600,
    };
    if lease_secs == 0 {
        return Err("MEDIA_FPS_LEASE_SECONDS must be > 0 (0 means no lease)".into());
    }
    let envelope_rsa = envelope_key_from_env()?;
    let pdp = PlatformPdp::new(platform_url, token_url, client_id, secret)?;
    Ok(Some(LicenseAuthz {
        pdp,
        kas_urls,
        lease_secs,
        envelope_rsa,
    }))
}

/// The key-envelope DEK must be wrapped to a key only the KSM holds: one the
/// KAS also holds would let any entitled viewer rewrap the DEK and read the
/// raw track keys, bypassing FairPlay.
pub fn check_envelope_key(
    envelope: Option<&RsaPrivateKey>,
    kas: Option<&RsaPrivateKey>,
) -> Result<(), String> {
    if let (Some(envelope), Some(kas)) = (envelope, kas) {
        if RsaPublicKey::from(envelope) == RsaPublicKey::from(kas) {
            return Err("MEDIA_ENVELOPE_RSA_KEY_PATH must not be the KAS RSA key: \
                        the platform KAS would release envelope DEKs to any entitled viewer."
                .to_string());
        }
    }
    Ok(())
}

/// Licensing gates RSA-wrapped TDF keys behind a platform decision. The local
/// OpenTDF-compat `/kas/v2/rewrap` shim would unwrap the same keys with no
/// decision, so with licensing and the RSA key both live, that route must be
/// forwarded to the platform instead.
pub fn check_rewrap_exposure(
    licensing: bool,
    rsa_loaded: bool,
    forwards_rest: bool,
) -> Result<(), String> {
    if licensing && rsa_loaded && !forwards_rest {
        return Err(
            "FairPlay licensing requires KAS_PROXY_MODE=rest|both: the local \
                    /kas/v2/rewrap shim would release the same RSA-wrapped keys without \
                    a policy decision."
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_key_must_differ_from_the_kas_key() {
        let f = super::super::fixtures::fixtures();
        let kas = RsaPrivateKey::from_pkcs8_pem(&f.key_pem).unwrap();
        let envelope = RsaPrivateKey::from_pkcs8_pem(&f.envelope_key_pem).unwrap();
        let msg = check_envelope_key(Some(&kas), Some(&kas)).unwrap_err();
        assert!(msg.contains("MEDIA_ENVELOPE_RSA_KEY_PATH"), "{msg}");
        assert!(check_envelope_key(Some(&envelope), Some(&kas)).is_ok());
        assert!(check_envelope_key(None, Some(&kas)).is_ok());
        assert!(check_envelope_key(Some(&envelope), None).is_ok());
    }

    #[test]
    fn rewrap_exposure_refuses_only_licensing_with_rsa_and_local_rest() {
        for licensing in [false, true] {
            for rsa_loaded in [false, true] {
                for forwards_rest in [false, true] {
                    let r = check_rewrap_exposure(licensing, rsa_loaded, forwards_rest);
                    if licensing && rsa_loaded && !forwards_rest {
                        let msg = r.unwrap_err();
                        assert!(msg.contains("KAS_PROXY_MODE=rest|both"), "{msg}");
                        assert!(msg.contains("/kas/v2/rewrap"), "{msg}");
                    } else {
                        assert!(
                            r.is_ok(),
                            "licensing={licensing} rsa={rsa_loaded} rest={forwards_rest}"
                        );
                    }
                }
            }
        }
    }
}
