//! The APNs hint (arkavo-ios ADR-0074): a generic alert telling the owner a
//! request is waiting. Token-based provider authentication with a `.p8` key.
//! Nothing identifying goes into the payload, because it passes through
//! Apple. Device tokens are never logged.

use async_trait::async_trait;
use nanotdf::warn;
use std::time::{Duration, Instant};

pub const ALERT_TEXT: &str = "Someone is asking to open a file you protected.";

/// A provider token is reused for this long (Apple: refresh between 20 and
/// 60 minutes; more often is refused with `TooManyProviderTokenUpdates`).
const PROVIDER_TOKEN_TTL: Duration = Duration::from_secs(50 * 60);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    Sent,
    /// APNs says the token is no longer valid: delete it.
    Unregistered,
    Failed,
}

#[async_trait]
pub trait Pusher: Send + Sync {
    /// `expires_at`: unix seconds after which APNs should drop the alert.
    async fn alert(
        &self,
        device_token: &str,
        environment: &str,
        collapse_id: &str,
        expires_at: i64,
    ) -> PushOutcome;
}

pub struct ApnsConfig {
    pub key_pem: String,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
}

pub struct ApnsPusher {
    config: ApnsConfig,
    key: p256::ecdsa::SigningKey,
    http: reqwest::Client,
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
}

impl ApnsPusher {
    pub fn new(config: ApnsConfig) -> Result<Self, String> {
        use p256::pkcs8::DecodePrivateKey;
        let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&config.key_pem)
            .map_err(|_| "APNs key is not a PKCS#8 P-256 key".to_string())?;
        // APNs negotiates TLS 1.3 and h2 (checked 2026-11-08), so the shared
        // TLS 1.3-only builder applies.
        let http = crate::modules::http_client::builder()
            .timeout(SEND_TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            config,
            key,
            http,
            token: tokio::sync::Mutex::new(None),
        })
    }

    async fn provider_token(&self, renew: bool) -> Option<String> {
        let mut cached = self.token.lock().await;
        if !renew
            && let Some((t, at)) = cached.as_ref()
            && at.elapsed() < PROVIDER_TOKEN_TTL
        {
            return Some(t.clone());
        }
        let header = serde_json::json!({ "alg": "ES256", "kid": self.config.key_id });
        let claims = serde_json::json!({
            "iss": self.config.team_id,
            "iat": chrono::Utc::now().timestamp(),
        });
        let t = super::token::sign_es256_jws(&self.key, &header, &claims);
        *cached = Some((t.clone(), Instant::now()));
        Some(t)
    }

    async fn send(
        &self,
        device_token: &str,
        environment: &str,
        collapse_id: &str,
        expires_at: i64,
        provider: &str,
    ) -> Result<(u16, String), String> {
        // The key is production-only (arkavo-ios ADR-0074 decision 7): the
        // push route admits only production tokens, and nothing goes to the
        // sandbox host.
        let _ = environment;
        let host = "api.push.apple.com";
        let resp = self
            .http
            .post(format!("https://{host}/3/device/{device_token}"))
            .bearer_auth(provider)
            .header("apns-push-type", "alert")
            .header("apns-topic", &self.config.topic)
            .header("apns-collapse-id", collapse_id)
            .header("apns-priority", "10")
            .header("apns-expiration", expires_at.to_string())
            .json(&payload())
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        let status = resp.status().as_u16();
        let reason = if status == 200 {
            String::new()
        } else {
            resp.json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|v| v.get("reason")?.as_str().map(str::to_string))
                .unwrap_or_default()
        };
        Ok((status, reason))
    }
}

pub fn payload() -> serde_json::Value {
    serde_json::json!({ "aps": { "alert": { "body": ALERT_TEXT } } })
}

/// What an APNs answer means for the token.
pub fn classify(status: u16, reason: &str) -> PushOutcome {
    match (status, reason) {
        (200, _) => PushOutcome::Sent,
        (410, _) | (400, "BadDeviceToken") | (400, "DeviceTokenNotForTopic") => {
            PushOutcome::Unregistered
        }
        _ => PushOutcome::Failed,
    }
}

#[async_trait]
impl Pusher for ApnsPusher {
    async fn alert(
        &self,
        device_token: &str,
        environment: &str,
        collapse_id: &str,
        expires_at: i64,
    ) -> PushOutcome {
        let mut renewed = false;
        loop {
            let Some(provider) = self.provider_token(renewed).await else {
                return PushOutcome::Failed;
            };
            match self
                .send(
                    device_token,
                    environment,
                    collapse_id,
                    expires_at,
                    &provider,
                )
                .await
            {
                Ok((403, reason))
                    if !renewed
                        && matches!(
                            reason.as_str(),
                            "ExpiredProviderToken" | "InvalidProviderToken"
                        ) =>
                {
                    renewed = true;
                }
                Ok((status, reason)) => {
                    let outcome = classify(status, &reason);
                    if outcome == PushOutcome::Failed {
                        warn!("APNs alert refused: {status} {reason}");
                    }
                    return outcome;
                }
                Err(e) => {
                    warn!("APNs alert not sent: {e}");
                    return PushOutcome::Failed;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_names_no_one() {
        assert_eq!(
            payload(),
            serde_json::json!({ "aps": { "alert": {
                "body": "Someone is asking to open a file you protected."
            } } })
        );
    }

    #[test]
    fn unregistered_tokens_are_recognized() {
        assert_eq!(classify(200, ""), PushOutcome::Sent);
        assert_eq!(classify(410, "Unregistered"), PushOutcome::Unregistered);
        assert_eq!(classify(400, "BadDeviceToken"), PushOutcome::Unregistered);
        assert_eq!(classify(400, "BadCollapseId"), PushOutcome::Failed);
        assert_eq!(classify(429, "TooManyRequests"), PushOutcome::Failed);
    }

    #[test]
    fn a_p8_key_loads_and_signs() {
        use p256::pkcs8::EncodePrivateKey;
        let pem = p256::SecretKey::from_slice(&[3u8; 32])
            .unwrap()
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap();
        let pusher = ApnsPusher::new(ApnsConfig {
            key_pem: pem.to_string(),
            key_id: "ABC123DEFG".into(),
            team_id: "M8GS7ZT95Y".into(),
            topic: "com.arkavo.Arkavo".into(),
        })
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let a = rt.block_on(pusher.provider_token(false)).unwrap();
        let b = rt.block_on(pusher.provider_token(false)).unwrap();
        assert_eq!(a, b, "cached");
        let key = p256::SecretKey::from_slice(&[3u8; 32])
            .unwrap()
            .public_key();
        let claims = crate::modules::owner_kas::token::verify_es256_jws(&a, &key.into()).unwrap();
        assert_eq!(claims["iss"], "M8GS7ZT95Y");
        let header: serde_json::Value = serde_json::from_slice(
            &base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                a.split('.').next().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(header["kid"], "ABC123DEFG");
    }
}

/// Checks a real `.p8` against APNs production with a made-up device token:
/// `OWNER_KAS_APNS_PROBE=<key path> APNS_KEY_ID=… APNS_TEAM_ID=… cargo test
/// --bin arks apns_probe -- --nocapture`. A valid key gets 400
/// BadDeviceToken; a bad key, team or environment gets 403. Skipped when
/// unset; nothing reaches a device.
#[cfg(test)]
mod probe {
    use super::*;

    #[tokio::test]
    async fn apns_probe() {
        let Ok(path) = std::env::var("OWNER_KAS_APNS_PROBE") else {
            return;
        };
        let pusher = ApnsPusher::new(ApnsConfig {
            key_pem: std::fs::read_to_string(path).unwrap(),
            key_id: std::env::var("APNS_KEY_ID").unwrap(),
            team_id: std::env::var("APNS_TEAM_ID").unwrap(),
            topic: crate::modules::owner_kas::DEFAULT_APNS_TOPIC.into(),
        })
        .unwrap();
        let provider = pusher.provider_token(false).await.unwrap();
        let fake = "0".repeat(64);
        let exp = chrono::Utc::now().timestamp() + 60;
        let (status, reason) = pusher
            .send(
                &fake,
                "production",
                "01JC0000000000000000000000",
                exp,
                &provider,
            )
            .await
            .unwrap();
        println!("APNs production: {status} {reason}");
        assert_eq!((status, reason.as_str()), (400, "BadDeviceToken"));
    }
}
