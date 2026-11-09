//! Identity's route directory (authnz-rs#148, identity 0.31.0; arkavo-ios
//! design §4.2/§4.3 at 43bbd68): the owner's route record and APNs token live
//! at identity, which owns account deletion and retires routes. The relay
//! reads, per route, `{owner_sub, apns_token?, environment?}` with its own
//! `client_credentials` token (the `owner-kas-relay` client, not
//! `arks-media`), sent as `X-Auth-Token`, and deletes a push token APNs
//! reports as unregistered.
//!
//! A positive answer is reused for [`FRESH`]; while identity is unreachable,
//! one up to [`STALE_LIMIT`] old still serves. Unknown or retired routes are
//! never cached.

use super::store::Push;
use super::token::is_bare_subject;
use async_trait::async_trait;
use nanotdf::warn;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const FRESH: Duration = Duration::from_secs(60);
/// The owner-KAS token's lifetime: a route known this recently was live when
/// the bearer was minted.
const STALE_LIMIT: Duration = Duration::from_secs(900);
const TIMEOUT: Duration = Duration::from_secs(10);
/// Refresh a service token this long before it expires.
const REFRESH_MARGIN: Duration = Duration::from_secs(30);
const MAX_CACHED_ROUTES: usize = 10_000;
/// Identity's service gate reads the access token here, not `Authorization`.
const SERVICE_TOKEN_HEADER: &str = "x-auth-token";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInfo {
    /// The owner's bare lowercase account UUID.
    pub owner_sub: String,
    /// A production APNs registration, if the owner has one.
    pub push: Option<Push>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// Identity answered 404: never registered.
    Unknown,
    /// Identity answered 410: sharing turned off, the account deleted, or the
    /// owner's account no longer live.
    Retired,
    /// Identity could not be asked, and nothing usable is cached.
    Unavailable,
}

#[async_trait]
pub trait RouteDirectory: Send + Sync {
    async fn route(&self, route_id: &str) -> Result<RouteInfo, LookupError>;
    /// Delete the route's push token after APNs reported `apns_token`
    /// unregistered; identity keeps a token the owner has set since.
    async fn delete_push(&self, route_id: &str, apns_token: &str);
}

pub struct IdentityDirectoryConfig {
    /// `{route_id}` is replaced; e.g. `{issuer}/owner-kas/routes/{route_id}/relay`.
    pub relay_url: String,
    /// `{route_id}` is replaced; the service `DELETE` of the push token,
    /// e.g. `{issuer}/owner-kas/routes/{route_id}/relay/push`.
    pub push_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// Sent as `audience` on the token request when set (identity 0.31.0
    /// needs none).
    pub audience: Option<String>,
}

pub struct IdentityDirectory {
    config: IdentityDirectoryConfig,
    http: reqwest::Client,
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
    cache: tokio::sync::Mutex<HashMap<String, (Instant, RouteInfo)>>,
}

#[derive(Deserialize)]
struct RelayView {
    owner_sub: String,
    apns_token: Option<String>,
    environment: Option<String>,
}

fn info_from(view: RelayView) -> Option<RouteInfo> {
    if !is_bare_subject(&view.owner_sub) {
        return None;
    }
    // The APNs key is production-only (ADR-0074 decision 7).
    let push = match (view.apns_token, view.environment.as_deref()) {
        (Some(t), Some("production"))
            if (64..=200).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Some(Push {
                apns_token: t.to_ascii_lowercase(),
                environment: "production".into(),
            })
        }
        _ => None,
    };
    Some(RouteInfo {
        owner_sub: view.owner_sub,
        push,
    })
}

impl IdentityDirectory {
    pub fn new(config: IdentityDirectoryConfig) -> Self {
        Self {
            config,
            http: crate::modules::http_client::builder()
                .timeout(TIMEOUT)
                .build()
                .expect("reqwest client"),
            token: tokio::sync::Mutex::new(None),
            cache: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    fn url(template: &str, route_id: &str) -> String {
        template.replace("{route_id}", route_id)
    }

    async fn service_token(&self, force: bool) -> Option<String> {
        let mut guard = self.token.lock().await;
        if !force
            && let Some((t, exp)) = guard.as_ref()
                && Instant::now() + REFRESH_MARGIN < *exp {
                    return Some(t.clone());
                }
        let mut form = vec![("grant_type", "client_credentials".to_string())];
        if let Some(aud) = &self.config.audience {
            form.push(("audience", aud.clone()));
        }
        let resp = match self
            .http
            .post(&self.config.token_url)
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&form)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "owner-kas: service token request failed: {}",
                    e.without_url()
                );
                return None;
            }
        };
        if !resp.status().is_success() {
            warn!("owner-kas: service token refused: HTTP {}", resp.status());
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        let token = body.get("access_token")?.as_str()?.to_string();
        let ttl = body
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(300);
        *guard = Some((token.clone(), Instant::now() + Duration::from_secs(ttl)));
        Some(token)
    }

    /// One read at identity. A 401 renews the service token once.
    async fn fetch(&self, route_id: &str) -> Result<RouteInfo, LookupError> {
        let url = Self::url(&self.config.relay_url, route_id);
        let mut renewed = false;
        loop {
            let token = self
                .service_token(renewed)
                .await
                .ok_or(LookupError::Unavailable)?;
            let resp = self
                .http
                .get(&url)
                .header(SERVICE_TOKEN_HEADER, &token)
                .send()
                .await
                .map_err(|e| {
                    warn!("owner-kas: route read failed: {}", e.without_url());
                    LookupError::Unavailable
                })?;
            match resp.status().as_u16() {
                200 => {
                    let view: RelayView = resp.json().await.map_err(|_| {
                        warn!("owner-kas: route read unparseable");
                        LookupError::Unavailable
                    })?;
                    return info_from(view).ok_or_else(|| {
                        warn!("owner-kas: route read has an invalid owner_sub");
                        LookupError::Unavailable
                    });
                }
                404 => return Err(LookupError::Unknown),
                410 => return Err(LookupError::Retired),
                401 if !renewed => renewed = true,
                other => {
                    // 403: this client isn't on OWNER_KAS_RELAY_CLIENT_IDS.
                    warn!("owner-kas: route read refused: HTTP {other}");
                    return Err(LookupError::Unavailable);
                }
            }
        }
    }
}

#[async_trait]
impl RouteDirectory for IdentityDirectory {
    async fn route(&self, route_id: &str) -> Result<RouteInfo, LookupError> {
        let cached = self.cache.lock().await.get(route_id).cloned();
        if let Some((at, info)) = &cached
            && at.elapsed() < FRESH {
                return Ok(info.clone());
            }
        match self.fetch(route_id).await {
            Ok(info) => {
                let mut cache = self.cache.lock().await;
                if cache.len() >= MAX_CACHED_ROUTES {
                    cache.retain(|_, (at, _)| at.elapsed() < STALE_LIMIT);
                    if cache.len() >= MAX_CACHED_ROUTES {
                        cache.clear();
                    }
                }
                cache.insert(route_id.to_string(), (Instant::now(), info.clone()));
                Ok(info)
            }
            Err(e @ (LookupError::Unknown | LookupError::Retired)) => {
                self.cache.lock().await.remove(route_id);
                Err(e)
            }
            Err(LookupError::Unavailable) => match cached {
                Some((at, info)) if at.elapsed() < STALE_LIMIT => Ok(info),
                _ => Err(LookupError::Unavailable),
            },
        }
    }

    async fn delete_push(&self, route_id: &str, apns_token: &str) {
        if let Some((_, info)) = self.cache.lock().await.get_mut(route_id)
            && info
                .push
                .as_ref()
                .is_some_and(|p| p.apns_token == apns_token)
            {
                info.push = None;
            }
        let Some(token) = self.service_token(false).await else {
            return;
        };
        match self
            .http
            .delete(Self::url(&self.config.push_url, route_id))
            .header(SERVICE_TOKEN_HEADER, &token)
            .json(&serde_json::json!({ "apns_token": apns_token }))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => warn!("owner-kas: push token delete refused: HTTP {}", r.status()),
            Err(e) => warn!("owner-kas: push token delete failed: {}", e.without_url()),
        }
    }
}

#[cfg(test)]
pub(crate) mod memory {
    use super::*;
    use std::sync::Mutex;

    /// Routes as identity would answer; `None` behaves as unreachable.
    #[derive(Default)]
    pub struct MemoryDirectory {
        pub routes: Mutex<Option<HashMap<String, RouteInfo>>>,
        pub deleted: Mutex<Vec<(String, String)>>,
        /// Routes identity reports as retired (410).
        pub retired: Mutex<Vec<String>>,
    }

    impl MemoryDirectory {
        pub fn with(route_id: &str, info: RouteInfo) -> Self {
            let d = Self::default();
            *d.routes.lock().unwrap() = Some(HashMap::from([(route_id.to_string(), info)]));
            d
        }
    }

    #[async_trait]
    impl RouteDirectory for MemoryDirectory {
        async fn route(&self, route_id: &str) -> Result<RouteInfo, LookupError> {
            if self.retired.lock().unwrap().iter().any(|r| r == route_id) {
                return Err(LookupError::Retired);
            }
            match self.routes.lock().unwrap().as_ref() {
                None => Err(LookupError::Unavailable),
                Some(m) => m.get(route_id).cloned().ok_or(LookupError::Unknown),
            }
        }

        async fn delete_push(&self, route_id: &str, apns_token: &str) {
            self.deleted
                .lock()
                .unwrap()
                .push((route_id.into(), apns_token.into()));
            if let Some(m) = self.routes.lock().unwrap().as_mut() {
                if let Some(r) = m.get_mut(route_id) {
                    if r.push.as_ref().is_some_and(|p| p.apns_token == apns_token) {
                        r.push = None;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUB: &str = "0a1b2c3d-0000-4000-8000-0000000000aa";
    const TOKEN: &str = "a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1";

    fn view(sub: &str, token: Option<&str>, env: Option<&str>) -> RelayView {
        RelayView {
            owner_sub: sub.into(),
            apns_token: token.map(Into::into),
            environment: env.map(Into::into),
        }
    }

    #[test]
    fn only_production_tokens_are_kept() {
        let info = info_from(view(SUB, Some(TOKEN), Some("production"))).unwrap();
        assert_eq!(info.push.unwrap().apns_token, TOKEN);
        assert_eq!(
            info_from(view(SUB, Some(TOKEN), Some("development")))
                .unwrap()
                .push,
            None
        );
        assert_eq!(
            info_from(view(SUB, Some("zz"), Some("production")))
                .unwrap()
                .push,
            None
        );
        assert_eq!(info_from(view(SUB, None, None)).unwrap().push, None);
    }

    #[test]
    fn owner_sub_must_be_bare() {
        assert!(info_from(view(&format!("arkavo:{SUB}"), None, None)).is_none());
        assert!(info_from(view(&SUB.to_uppercase(), None, None)).is_none());
    }

    /// One-shot HTTP server on loopback: answers each request in `responses`
    /// in order and records the request lines.
    async fn server(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            for (status, body) in responses {
                let (mut s, _) = listener.accept().await.unwrap();
                // Read the head, then the body its content-length names.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = s.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len || n == 0 {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).to_string());
                let res = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                s.write_all(res.as_bytes()).await.unwrap();
            }
        });
        (format!("http://{addr}"), seen)
    }

    fn directory(base: &str) -> IdentityDirectory {
        let mut d = IdentityDirectory::new(IdentityDirectoryConfig {
            relay_url: format!("{base}/owner-kas/routes/{{route_id}}/relay"),
            push_url: format!("{base}/owner-kas/routes/{{route_id}}/relay/push"),
            token_url: format!("{base}/oauth/token"),
            client_id: "owner-kas-relay".into(),
            client_secret: "s".into(),
            audience: None,
        });
        // Loopback test server is plain HTTP.
        d.http = reqwest::Client::new();
        d
    }

    const ROUTE: &str = "01JC5Z8Q4M7N2P3R6S9T0V1W2X";
    const TOKEN_OK: &str = r#"{"access_token":"svc","expires_in":300}"#;

    #[tokio::test]
    async fn reads_caches_and_falls_back_while_identity_is_down() {
        let body: &'static str = Box::leak(
            format!(r#"{{"owner_sub":"{SUB}","apns_token":"{TOKEN}","environment":"production"}}"#)
                .into_boxed_str(),
        );
        let (base, seen) = server(vec![(200, TOKEN_OK), (200, body)]).await;
        let d = directory(&base);
        let info = d.route(ROUTE).await.unwrap();
        assert_eq!(info.owner_sub, SUB);
        assert!(info.push.is_some());
        // Fresh: no second read.
        assert_eq!(d.route(ROUTE).await.unwrap(), info);
        assert_eq!(seen.lock().unwrap().len(), 2);
        let read = seen.lock().unwrap()[1].clone();
        assert!(read.starts_with(&format!("GET /owner-kas/routes/{ROUTE}/relay HTTP/1.1")));
        assert!(read.to_ascii_lowercase().contains("x-auth-token: svc"));
        assert!(!read.to_ascii_lowercase().contains("authorization:"));
        // Stale, and identity is gone: the stale answer serves.
        d.cache.lock().await.get_mut(ROUTE).unwrap().0 -= FRESH;
        assert_eq!(d.route(ROUTE).await.unwrap(), info);
        // Too stale: unavailable.
        d.cache.lock().await.get_mut(ROUTE).unwrap().0 -= STALE_LIMIT;
        assert_eq!(d.route(ROUTE).await, Err(LookupError::Unavailable));
    }

    #[tokio::test]
    async fn unknown_and_retired_routes_are_unknown() {
        let (base, _) = server(vec![(200, TOKEN_OK), (404, "{}"), (410, "{}")]).await;
        let d = directory(&base);
        assert_eq!(d.route(ROUTE).await, Err(LookupError::Unknown));
        assert_eq!(d.route(ROUTE).await, Err(LookupError::Retired));
    }

    #[tokio::test]
    async fn a_401_renews_the_service_token_once() {
        let body: &'static str = Box::leak(format!(r#"{{"owner_sub":"{SUB}"}}"#).into_boxed_str());
        let (base, seen) = server(vec![
            (200, TOKEN_OK),
            (401, "{}"),
            (200, TOKEN_OK),
            (200, body),
        ])
        .await;
        let d = directory(&base);
        assert_eq!(d.route(ROUTE).await.unwrap().push, None);
        assert_eq!(seen.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn unregistered_tokens_are_deleted_at_identity() {
        let (base, seen) = server(vec![(200, TOKEN_OK), (204, "")]).await;
        let d = directory(&base);
        d.delete_push(ROUTE, TOKEN).await;
        let seen = seen.lock().unwrap();
        assert!(seen[1].starts_with(&format!(
            "DELETE /owner-kas/routes/{ROUTE}/relay/push HTTP/1.1"
        )));
        assert!(seen[1].contains(&format!(r#"{{"apns_token":"{TOKEN}"}}"#)));
        assert!(seen[1].to_ascii_lowercase().contains("x-auth-token: svc"));
    }
}
