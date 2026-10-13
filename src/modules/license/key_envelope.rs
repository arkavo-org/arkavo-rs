//! Arkavo FairPlay key-envelope profile over a single standard OpenTDF segment.
//! The consumer receives a CKC only. Neither the envelope nor its keys are returned.
use super::*;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use zeroize::Zeroizing;

const PROFILE: &str = "urn:arkavo:fairplay:key-envelope:1";
const MAX_PLAINTEXT: usize = 2_097_152;

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct MediaFile {
    name: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Track {
    id: String,
    key: String,
    iv: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    profile: String,
    asset_id: String,
    content_key_id: String,
    tracks: Vec<Track>,
    files: Vec<MediaFile>,
}

fn bytes(value: &Value) -> Result<Vec<u8>, LicenseError> {
    let encoded = value.as_str().ok_or(FORBIDDEN_MANIFEST)?;
    let decoded = STANDARD.decode(encoded).map_err(|_| FORBIDDEN_MANIFEST)?;
    if STANDARD.encode(&decoded) != encoded {
        return Err(FORBIDDEN_MANIFEST);
    }
    Ok(decoded)
}

pub(super) fn check(
    manifest: &Value,
    policy: &Value,
    policy_b64: &str,
    encrypted: Option<&[u8]>,
    rsa: &RsaPrivateKey,
    kas_urls: &[String],
) -> Result<CheckedPolicy, LicenseError> {
    let ei = &manifest["encryptionInformation"];
    if policy["arkavo:fpsProfile"] != PROFILE
        || manifest["schemaVersion"] != "4.3.0"
        || manifest["payload"]["type"] != "reference"
        || manifest["payload"]["url"] != "0.payload"
        || manifest["payload"]["protocol"] != "zip"
        || manifest["payload"]["isEncrypted"] != true
        || manifest["payload"]["mimeType"] != "application/json"
        || ei["type"] != "split"
        || ei["method"]["algorithm"] != "AES-256-GCM"
        || ei["method"]["isStreamable"] != true
        || ei["method"]["iv"] != ""
    {
        return Err(FORBIDDEN_MANIFEST);
    }
    let encrypted = encrypted
        .filter(|p| (29..=MAX_PLAINTEXT + 28).contains(&p.len()))
        .ok_or(FORBIDDEN_MANIFEST)?;
    let kaos = ei["keyAccess"].as_array().ok_or(FORBIDDEN_MANIFEST)?;
    let [kao] = kaos.as_slice() else {
        return Err(FORBIDDEN_MANIFEST);
    };
    if kao["protocol"] != "kas"
        || kao["policyBinding"]["alg"] != "HS256"
        || kao.get("encryptedMetadata").is_some()
        || kao.get("sid").is_some_and(|s| s != "")
    {
        return Err(FORBIDDEN_MANIFEST);
    }
    let dek = Zeroizing::new(unwrap_key(kao, rsa, kas_urls)?);
    if dek.len() != 32 {
        return Err(FORBIDDEN_MANIFEST);
    }
    verify_policy_binding(kao, &dek, policy_b64)?;
    let integrity = &ei["integrityInformation"];
    let segments = integrity["segments"].as_array().ok_or(FORBIDDEN_MANIFEST)?;
    let [segment] = segments.as_slice() else {
        return Err(FORBIDDEN_MANIFEST);
    };
    if integrity["segmentHashAlg"] != "GMAC"
        || integrity["rootSignature"]["alg"] != "HS256"
        || integrity["segmentSizeDefault"] != MAX_PLAINTEXT
        || integrity["encryptedSegmentSizeDefault"] != MAX_PLAINTEXT + 28
        || segment["segmentSize"] != encrypted.len() - 28
        || segment["encryptedSegmentSize"] != encrypted.len()
    {
        return Err(FORBIDDEN_MANIFEST);
    }
    let hash = bytes(&segment["hash"])?;
    if hash.as_slice() != &encrypted[encrypted.len() - 16..] {
        return Err(FORBIDDEN_MANIFEST);
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&dek).map_err(|_| FORBIDDEN_MANIFEST)?;
    mac.update(&hash);
    mac.verify_slice(&bytes(&integrity["rootSignature"]["sig"])?)
        .map_err(|_| FORBIDDEN_MANIFEST)?;
    let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|_| FORBIDDEN_MANIFEST)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
            .map_err(|_| FORBIDDEN_MANIFEST)?,
    );
    if !has_unique_keys(&plaintext) {
        return Err(FORBIDDEN_MANIFEST);
    }
    let envelope: Envelope = serde_json::from_slice(&plaintext).map_err(|_| FORBIDDEN_MANIFEST)?;
    let (policy_uuid, fqns) = policy_subject(policy)?;
    if uuid::Uuid::parse_str(&policy_uuid).is_err()
        || envelope.profile != PROFILE
        || envelope.content_key_id != policy_uuid
        || envelope.asset_id.is_empty()
        || envelope.asset_id.len() > 1024
    {
        return Err(FORBIDDEN_MANIFEST);
    }
    let files: Vec<MediaFile> =
        serde_json::from_value(policy["arkavo:media"].clone()).map_err(|_| FORBIDDEN_MANIFEST)?;
    if files.is_empty() || files.len() > 8191 || envelope.files != files {
        return Err(FORBIDDEN_MANIFEST);
    }
    let mut names = HashSet::new();
    for f in files {
        if !safe_name(&f.name)
            || !names.insert(f.name)
            || bytes(&Value::String(f.sha256))?.len() != 32
        {
            return Err(FORBIDDEN_MANIFEST);
        }
    }
    if !names.contains("master.m3u8") {
        return Err(FORBIDDEN_MANIFEST);
    }
    let shape = component_shape(&policy[COMPONENTS_KEY])?;
    let ivs: BTreeMap<String, String> = serde_json::from_value(policy["arkavo:mediaIVs"].clone())
        .map_err(|_| FORBIDDEN_MANIFEST)?;
    if shape.len() != envelope.tracks.len() || ivs.len() != shape.len() {
        return Err(FORBIDDEN_MANIFEST);
    }
    let mut components: Vec<CheckedComponent> = Vec::new();
    for ((kind, binding), track) in shape.into_iter().zip(envelope.tracks) {
        if track.id != kind.as_str() || ivs.get(&track.id) != Some(&track.iv) {
            return Err(FORBIDDEN_MANIFEST);
        }
        let key: [u8; 16] = bytes(&Value::String(track.key))?
            .try_into()
            .map_err(|_| FORBIDDEN_MANIFEST)?;
        let iv: [u8; 16] = bytes(&Value::String(track.iv))?
            .try_into()
            .map_err(|_| FORBIDDEN_MANIFEST)?;
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(|_| FORBIDDEN_MANIFEST)?;
        mac.update(KEY_BINDING_PREFIX.as_bytes());
        mac.update(track.id.as_bytes());
        mac.verify_slice(&binding).map_err(|_| FORBIDDEN_MANIFEST)?;
        if components.iter().any(|c| c.key == key) {
            return Err(FORBIDDEN_MANIFEST);
        }
        components.push(CheckedComponent {
            id: track.id,
            kind,
            key,
            content_iv: Some(iv),
        });
    }
    Ok(CheckedPolicy {
        keys: PolicyKeys::Components(components),
        policy_uuid,
        fqns,
        content_iv: [0; 16],
    })
}

fn safe_name(name: &str) -> bool {
    if name == "master.m3u8" {
        return true;
    }
    for track in ["video", "audio"] {
        if name == format!("{track}.m3u8") || name == format!("{track}-init.mp4") {
            return true;
        }
        if let Some(index) = name
            .strip_prefix(&format!("{track}-segment"))
            .and_then(|s| s.strip_suffix(".m4s"))
        {
            if let Ok(number) = index.parse::<u32>() {
                return number <= 4092 && number.to_string() == index;
            }
        }
    }
    false
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::modules::license::fixtures::fixtures;
    use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, RsaPublicKey};
    use serde_json::json;

    const DEK: [u8; 32] = [0x41; 32];
    fn hmac(key: &[u8], data: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        STANDARD.encode(mac.finalize().into_bytes())
    }
    fn key() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(&fixtures().key_pem).unwrap()
    }
    fn seal(manifest: &mut Value, plaintext: &Value) -> Vec<u8> {
        let plaintext = serde_json::to_vec(plaintext).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&DEK).unwrap();
        let mut payload = vec![0x23; 12];
        payload.extend(
            cipher
                .encrypt(Nonce::from_slice(&[0x23; 12]), plaintext.as_slice())
                .unwrap(),
        );
        let tag = &payload[payload.len() - 16..];
        manifest["encryptionInformation"]["integrityInformation"] = json!({
            "segmentHashAlg":"GMAC", "segmentSizeDefault":MAX_PLAINTEXT,
            "encryptedSegmentSizeDefault":MAX_PLAINTEXT+28,
            "rootSignature":{"alg":"HS256", "sig":hmac(&DEK,tag)},
            "segments":[{"hash":STANDARD.encode(tag),"segmentSize":plaintext.len(),"encryptedSegmentSize":payload.len()}]
        });
        payload
    }
    fn bind(manifest: &mut Value, policy: &Value) {
        let b64 = STANDARD.encode(serde_json::to_vec(policy).unwrap());
        manifest["encryptionInformation"]["keyAccess"][0]["policyBinding"]["hash"] =
            json!(hmac(&DEK, b64.as_bytes()));
        manifest["encryptionInformation"]["policy"] = json!(b64);
    }
    pub(super) fn fixture() -> (Value, Value, Value, Vec<u8>) {
        let uuid = "3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b";
        let files = json!([{"name":"master.m3u8","sha256":STANDARD.encode([0x11;32])}]);
        let tracks = json!([
            {"id":"video","key":STANDARD.encode([1;16]),"iv":STANDARD.encode([3;16])},
            {"id":"audio","key":STANDARD.encode([2;16]),"iv":STANDARD.encode([4;16])}
        ]);
        let policy = json!({"uuid":uuid,"body":{"dataAttributes":[{"attribute":"https://patreon.arkavo.com/attr/campaign/value/1"}],"dissem":[]},
        "arkavo:fpsProfile":PROFILE, "arkavo:media":files,
        "arkavo:mediaIVs":{"video":STANDARD.encode([3;16]),"audio":STANDARD.encode([4;16])},
        "arkavo:components":[
            {"id":"video","kind":"video","keyBinding":hmac(&[1;16],format!("{KEY_BINDING_PREFIX}video").as_bytes())},
            {"id":"audio","kind":"audio","keyBinding":hmac(&[2;16],format!("{KEY_BINDING_PREFIX}audio").as_bytes())}
        ]});
        let envelope = json!({"profile":PROFILE,"assetId":"recording-1","contentKeyId":uuid,"tracks":tracks,"files":files});
        let wrapped = RsaPublicKey::from(&key())
            .encrypt(&mut OsRng, Oaep::new::<Sha1>(), &DEK)
            .unwrap();
        let mut manifest = json!({"schemaVersion":"4.3.0", "payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true,"mimeType":"application/json"},
            "encryptionInformation":{"type":"split", "method":{"algorithm":"AES-256-GCM","isStreamable":true,"iv":""},
            "keyAccess":[{"type":"wrapped","protocol":"kas","url":"https://platform.arkavo.net","wrappedKey":STANDARD.encode(wrapped),"policyBinding":{"alg":"HS256","hash":""}}]}});
        bind(&mut manifest, &policy);
        let payload = seal(&mut manifest, &envelope);
        (manifest, policy, envelope, payload)
    }
    fn verify(manifest: &Value, payload: Option<&[u8]>) -> Result<CheckedPolicy, LicenseError> {
        check_manifest_with_payload(
            &serde_json::to_vec(manifest).unwrap(),
            payload,
            &key(),
            &["https://platform.arkavo.net".into()],
        )
    }
    /// Run against the Swift packager's exported test fixture; no test key is committed.
    #[test]
    #[ignore = "requires ARKAVO_ENVELOPE_FIXTURE_DIR from ArkavoMediaKit exporter"]
    fn producer_generated_archive() {
        let directory =
            std::path::PathBuf::from(std::env::var("ARKAVO_ENVELOPE_FIXTURE_DIR").unwrap());
        let pem = std::fs::read_to_string(directory.join("test-kas-private.pem")).unwrap();
        let key = RsaPrivateKey::from_pkcs8_pem(&pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
            .unwrap();
        let manifest = std::fs::read(directory.join("manifest.json")).unwrap();
        let encrypted = std::fs::read(directory.join("0.payload")).unwrap();
        let checked = check_manifest_with_payload(
            &manifest,
            Some(&encrypted),
            &key,
            &["https://platform.arkavo.net".into()],
        )
        .unwrap();
        let PolicyKeys::Components(tracks) = checked.keys else {
            panic!("expected components")
        };
        let expected: Envelope =
            serde_json::from_slice(&std::fs::read(directory.join("test-envelope.json")).unwrap())
                .unwrap();
        assert_eq!(tracks.len(), expected.tracks.len());
        for (actual, expected) in tracks.iter().zip(expected.tracks) {
            assert_eq!(actual.id, expected.id);
            assert_eq!(
                actual.key.as_slice(),
                STANDARD.decode(expected.key).unwrap()
            );
            assert_eq!(
                actual.content_iv.unwrap().as_slice(),
                STANDARD.decode(expected.iv).unwrap()
            );
        }
    }

    #[test]
    fn envelope_selects_distinct_keys_and_ivs_without_returning_dek() {
        let (manifest, _, _, payload) = fixture();
        let policy = verify(&manifest, Some(&payload)).unwrap();
        let PolicyKeys::Components(tracks) = policy.keys else {
            panic!("envelope must yield components")
        };
        assert_eq!(tracks.len(), 2);
        assert_eq!(tracks[0].key, [1; 16]);
        assert_eq!(tracks[1].key, [2; 16]);
        assert_eq!(tracks[0].content_iv, Some([3; 16]));
        assert_eq!(tracks[1].content_iv, Some([4; 16]));
    }
    #[test]
    fn rejects_missing_truncated_tampered_and_oversized_payload() {
        let (manifest, _, _, payload) = fixture();
        assert!(verify(&manifest, None).is_err());
        assert!(verify(&manifest, Some(&payload[..payload.len() - 1])).is_err());
        for index in [0, 12, payload.len() - 1] {
            let mut tampered = payload.clone();
            tampered[index] ^= 1;
            assert!(verify(&manifest, Some(&tampered)).is_err());
        }
        assert!(verify(&manifest, Some(&vec![0; MAX_PLAINTEXT + 29])).is_err());
    }
    #[test]
    fn rejects_invalid_standard_manifest_fields() {
        let (manifest, _, _, payload) = fixture();
        for (pointer, value) in [
            ("/schemaVersion", json!("4.2.2")),
            ("/payload/url", json!("different")),
            (
                "/encryptionInformation/method/algorithm",
                json!("AES-128-CBC"),
            ),
            (
                "/encryptionInformation/integrityInformation/rootSignature/sig",
                json!(STANDARD.encode([0; 32])),
            ),
            (
                "/encryptionInformation/integrityInformation/segmentSizeDefault",
                json!(1),
            ),
            (
                "/encryptionInformation/integrityInformation/segments/0/segmentSize",
                json!(1),
            ),
            (
                "/encryptionInformation/keyAccess/0/policyBinding/hash",
                json!(STANDARD.encode([0; 32])),
            ),
        ] {
            let mut bad = manifest.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(verify(&bad, Some(&payload)).is_err(), "{pointer}");
        }
        let mut bad = manifest.clone();
        bad["encryptionInformation"]["keyAccess"][0]["encryptedMetadata"] = json!("plaintext");
        assert!(verify(&bad, Some(&payload)).is_err());
        let mut bad = manifest.clone();
        let kao = bad["encryptionInformation"]["keyAccess"][0].clone();
        bad["encryptionInformation"]["keyAccess"]
            .as_array_mut()
            .unwrap()
            .push(kao);
        assert!(verify(&bad, Some(&payload)).is_err());
    }
    #[test]
    fn authenticated_envelope_must_match_bound_policy() {
        let (manifest, _, envelope, _) = fixture();
        for (pointer, value) in [
            ("/profile", json!("unsupported")),
            ("/contentKeyId", json!("different")),
            ("/tracks/0/id", json!("audio")),
            ("/tracks/0/key", json!(STANDARD.encode([9; 16]))),
            ("/tracks/0/iv", json!(STANDARD.encode([9; 16]))),
            ("/files/0/sha256", json!(STANDARD.encode([9; 32]))),
        ] {
            let mut bad = manifest.clone();
            let mut altered = envelope.clone();
            *altered.pointer_mut(pointer).unwrap() = value;
            let payload = seal(&mut bad, &altered);
            assert!(verify(&bad, Some(&payload)).is_err(), "{pointer}");
        }
    }
    #[test]
    fn inventory_refuses_unsafe_names_and_unknown_profile() {
        let (mut manifest, mut policy, mut envelope, _) = fixture();
        policy["arkavo:media"][0]["name"] = json!("../master.m3u8");
        envelope["files"] = policy["arkavo:media"].clone();
        bind(&mut manifest, &policy);
        let payload = seal(&mut manifest, &envelope);
        assert!(verify(&manifest, Some(&payload)).is_err());
        for bad in [
            "../video.m3u8",
            "video-segment00.m4s",
            "video-segment4093.m4s",
            "evil.mp4",
        ] {
            assert!(!safe_name(bad));
        }
        for good in [
            "master.m3u8",
            "video.m3u8",
            "audio-init.mp4",
            "video-segment4092.m4s",
        ] {
            assert!(safe_name(good));
        }
        policy["arkavo:fpsProfile"] = json!("unknown");
        bind(&mut manifest, &policy);
        assert!(verify(&manifest, Some(&payload)).is_err());
    }
}

#[cfg(test)]
pub(super) fn test_fixture() -> (Value, Vec<u8>) {
    let (m, _, _, p) = tests::fixture();
    (m, p)
}
