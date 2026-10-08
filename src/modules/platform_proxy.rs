//! Reverse proxy to upstream opentdf-platform KAS.
//!
//! See `docs/platform-proxy.md` for operator config and design rationale.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

/// Which arks routes get forwarded to opentdf-platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    /// No forwarding; arks handles everything locally.
    Off,
    /// Forward only ConnectRPC routes (`/kas.AccessService/*`).
    Connect,
    /// Forward only legacy REST routes (`/kas/v2/rewrap`, `/kas/v2/kas_public_key`).
    /// The platform has no REST public-key route, so `/kas/v2/kas_public_key`
    /// is translated to ConnectRPC `PublicKey` (see [`kas_public_key`]).
    Rest,
    /// Forward both Connect and REST routes.
    Both,
}

impl FromStr for ProxyMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "" => Ok(ProxyMode::Off),
            "connect" => Ok(ProxyMode::Connect),
            "rest" => Ok(ProxyMode::Rest),
            "both" => Ok(ProxyMode::Both),
            other => Err(format!("invalid KAS_PROXY_MODE: {other}")),
        }
    }
}

impl ProxyMode {
    pub fn forwards_connect(self) -> bool {
        matches!(self, ProxyMode::Connect | ProxyMode::Both)
    }

    pub fn forwards_rest(self) -> bool {
        matches!(self, ProxyMode::Rest | ProxyMode::Both)
    }

    /// `/.well-known/opentdf-configuration` is platform-authoritative discovery.
    /// Whenever any proxying is on, defer to the upstream document.
    pub fn forwards_discovery(self) -> bool {
        !matches!(self, ProxyMode::Off)
    }
}

/// Shared state for the reverse-proxy handler.
#[derive(Debug)]
pub struct PlatformProxyState {
    pub client: Client,
    /// Upstream base URL with no trailing slash, e.g. `https://platform.svc:8443`.
    pub upstream_base: String,
}

impl PlatformProxyState {
    pub fn new(upstream: &str) -> Result<Arc<Self>, String> {
        let parsed = Url::parse(upstream).map_err(|e| format!("invalid upstream URL: {e}"))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(format!("invalid upstream URL scheme: {}", parsed.scheme()));
        }
        let upstream_base = upstream.trim_end_matches('/').to_string();
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(16)
            .build()
            .map_err(|e| format!("failed to build reqwest client: {e}"))?;
        Ok(Arc::new(Self {
            client,
            upstream_base,
        }))
    }
}

/// Per-request body cap (16 MiB). Matches `MAX_NANOTDF_SIZE` in `main.rs`
/// and bounds memory used buffering an inbound request before forwarding.
const MAX_PROXY_BODY: usize = 16 * 1024 * 1024;

/// Axum handler that forwards any inbound request to `state.upstream_base + path_and_query`.
pub async fn proxy(
    State(state): State<Arc<PlatformProxyState>>,
    req: Request,
) -> Result<Response, StatusCode> {
    let path_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", state.upstream_base, path_query);

    let (parts, body) = req.into_parts();

    let body_bytes: Bytes = axum::body::to_bytes(body, MAX_PROXY_BODY)
        .await
        .map_err(|e| {
            log::warn!("proxy request body read error: {e}");
            StatusCode::PAYLOAD_TOO_LARGE
        })?;

    let mut headers = parts.headers.clone();
    strip_proxy_headers(&mut headers);

    let upstream_resp = state
        .client
        .request(parts.method.clone(), &url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| {
            log::warn!("proxy upstream error: {e}");
            StatusCode::BAD_GATEWAY
        })?;

    let status = upstream_resp.status();
    let mut resp_headers = upstream_resp.headers().clone();
    strip_proxy_headers(&mut resp_headers);

    let bytes = upstream_resp.bytes().await.map_err(|e| {
        log::warn!("proxy upstream body read error: {e}");
        StatusCode::BAD_GATEWAY
    })?;

    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    Ok(response)
}

/// Headers we must not forward, per RFC 7230 §6.1, plus `Host`
/// (reqwest sets `Host` from the upstream URL).
const HOP_BY_HOP: &[HeaderName] = &[
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    header::HOST,
];

/// Strip RFC 7230 hop-by-hop headers (including `Host`) and `keep-alive` from `headers` in place.
/// Also parses the `Connection:` value and strips any headers named there (RFC 7230 §6.1).
pub(crate) fn strip_proxy_headers(headers: &mut HeaderMap) {
    // RFC 7230 §6.1: the Connection header lists additional hop-by-hop names
    // for this specific message. Collect them before mutating, since the next
    // loop removes Connection itself.
    let mut connection_listed: Vec<HeaderName> = Vec::new();
    if let Some(conn) = headers.get(header::CONNECTION) {
        if let Ok(val) = conn.to_str() {
            for name in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if let Ok(hn) = HeaderName::from_str(name) {
                    connection_listed.push(hn);
                }
            }
        }
    }
    for h in &connection_listed {
        headers.remove(h);
    }
    for h in HOP_BY_HOP {
        headers.remove(h);
    }
    headers.remove(HeaderName::from_static("keep-alive"));
}

/// Query parameters of the OpenTDF REST `GET /kas/v2/kas_public_key`.
#[derive(Debug, Default, Deserialize)]
pub struct PublicKeyQuery {
    pub algorithm: Option<String>,
    pub fmt: Option<String>,
    pub v: Option<String>,
}

/// Body of ConnectRPC `kas.AccessService/PublicKey`, in its JSON encoding.
#[derive(Debug, Serialize)]
struct ConnectPublicKeyRequest {
    algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fmt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    v: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConnectPublicKeyResponse {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConnectError {
    code: String,
    #[serde(default)]
    message: String,
}

/// REST response shape (same as the local `http_rewrap` handler).
#[derive(Debug, Serialize)]
struct PublicKeyResponse {
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

/// Expand the short algorithm names the local handler accepts. No algorithm
/// means EC, as it always has on this host; the platform's own default is RSA.
fn platform_algorithm(algorithm: Option<&str>) -> String {
    match algorithm {
        None | Some("") | Some("ec") => "ec:secp256r1".to_string(),
        Some("rsa") => "rsa:2048".to_string(),
        Some(other) => other.to_string(),
    }
}

fn error_response(status: StatusCode, error: &str, message: String) -> Response {
    let body = serde_json::json!({ "error": error, "message": message });
    (status, Json(body)).into_response()
}

/// Serve `GET /kas/v2/kas_public_key` from the platform's keyring.
///
/// The platform answers 401 to its REST paths without a token, but its
/// ConnectRPC `PublicKey` is public, so the REST query is sent there and the
/// answer is converted back to the REST shape. Key and `kid` both come from
/// the platform.
pub async fn kas_public_key(
    State(state): State<Arc<PlatformProxyState>>,
    Query(params): Query<PublicKeyQuery>,
) -> Response {
    let url = format!("{}/kas.AccessService/PublicKey", state.upstream_base);
    let body = ConnectPublicKeyRequest {
        algorithm: platform_algorithm(params.algorithm.as_deref()),
        fmt: params.fmt,
        v: params.v,
    };

    let upstream_resp = match state.client.post(&url).json(&body).send().await {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!("kas_public_key upstream error: {e}");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "unavailable",
                "KAS platform unreachable".to_string(),
            );
        }
    };

    let status = upstream_resp.status();
    let bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            log::warn!("kas_public_key upstream body read error: {e}");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "unavailable",
                "KAS platform response unreadable".to_string(),
            );
        }
    };

    if !status.is_success() {
        let (error, message) = match serde_json::from_slice::<ConnectError>(&bytes) {
            Ok(e) => (e.code, e.message),
            Err(_) => (
                "unknown".to_string(),
                String::from_utf8_lossy(&bytes).into(),
            ),
        };
        let status = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        return error_response(status, &error, message);
    }

    match serde_json::from_slice::<ConnectPublicKeyResponse>(&bytes) {
        Ok(r) => Json(PublicKeyResponse {
            public_key: r.public_key,
            kid: r.kid.filter(|k| !k.is_empty()),
        })
        .into_response(),
        Err(e) => {
            log::warn!("kas_public_key upstream response not understood: {e}");
            error_response(
                StatusCode::BAD_GATEWAY,
                "unavailable",
                "unexpected KAS platform response".to_string(),
            )
        }
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;

    #[test]
    fn rejects_invalid_url() {
        let err = PlatformProxyState::new("not a url").unwrap_err();
        assert!(err.to_string().contains("invalid"), "got: {err}");
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err = PlatformProxyState::new("file:///etc/passwd").unwrap_err();
        assert!(err.to_string().contains("scheme"), "got: {err}");
    }

    #[test]
    fn accepts_https_url() {
        let state = PlatformProxyState::new("https://platform.svc:8443").unwrap();
        assert_eq!(state.upstream_base, "https://platform.svc:8443");
    }

    #[test]
    fn strips_trailing_slash_from_upstream() {
        let state = PlatformProxyState::new("https://platform.svc/").unwrap();
        assert_eq!(state.upstream_base, "https://platform.svc");
    }
}

#[cfg(test)]
mod mode_tests {
    use super::*;

    #[test]
    fn parses_known_modes() {
        assert_eq!(ProxyMode::from_str("off").unwrap(), ProxyMode::Off);
        assert_eq!(ProxyMode::from_str("connect").unwrap(), ProxyMode::Connect);
        assert_eq!(ProxyMode::from_str("rest").unwrap(), ProxyMode::Rest);
        assert_eq!(ProxyMode::from_str("both").unwrap(), ProxyMode::Both);
    }

    #[test]
    fn empty_string_defaults_to_off() {
        assert_eq!(ProxyMode::from_str("").unwrap(), ProxyMode::Off);
    }

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(ProxyMode::from_str("CONNECT").unwrap(), ProxyMode::Connect);
        assert_eq!(ProxyMode::from_str("Both").unwrap(), ProxyMode::Both);
    }

    #[test]
    fn rejects_unknown_mode() {
        assert!(ProxyMode::from_str("invalid").is_err());
    }

    #[test]
    fn forwarding_predicates() {
        assert!(!ProxyMode::Off.forwards_connect());
        assert!(!ProxyMode::Off.forwards_rest());
        assert!(!ProxyMode::Off.forwards_discovery());

        assert!(ProxyMode::Connect.forwards_connect());
        assert!(!ProxyMode::Connect.forwards_rest());
        assert!(ProxyMode::Connect.forwards_discovery());

        assert!(!ProxyMode::Rest.forwards_connect());
        assert!(ProxyMode::Rest.forwards_rest());
        assert!(ProxyMode::Rest.forwards_discovery());

        assert!(ProxyMode::Both.forwards_connect());
        assert!(ProxyMode::Both.forwards_rest());
        assert!(ProxyMode::Both.forwards_discovery());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use axum::{routing::any, Router};
    use reqwest::Client;
    use tokio::net::TcpListener;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    /// Build an arks-side server with the proxy mounted at `/kas/v2/rewrap`
    /// pointing at `upstream`. Returns the bound base URL and socket address.
    async fn spawn_proxy(upstream: &str) -> (String, std::net::SocketAddr) {
        let state = PlatformProxyState::new(upstream).expect("valid upstream URL");
        let app = Router::new()
            .route("/kas/v2/rewrap", any(proxy))
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), addr)
    }

    #[tokio::test]
    async fn forwards_attribute_discovery_routes() {
        // Attribute FQN paths must dereference through this host to the
        // upstream platform's policy snapshot (single source of truth).
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/attr/tier/value/supporter"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{"value":"supporter","fqn":"https://patreon.arkavo.com/attr/tier/value/supporter"}"#,
                "application/json",
            ))
            .expect(1)
            .mount(&upstream)
            .await;

        let state = PlatformProxyState::new(&upstream.uri()).expect("valid upstream URL");
        let app = Router::new()
            .route("/attr/*rest", axum::routing::get(proxy))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = Client::new()
            .get(format!("http://{addr}/attr/tier/value/supporter"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp.text().await.unwrap().contains("supporter"));
    }

    #[tokio::test]
    async fn forwards_authorization_v2_wildcard_routes() {
        // The entitled-catalog endpoint (tdf-iroh-s3#5) reaches the platform
        // PDP through this host; every AuthorizationService method must
        // forward under the wildcard.
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/authorization.v2.AuthorizationService/GetDecisionMultiResource",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(r#"{"resourceDecisions":[]}"#, "application/json"),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        let state = PlatformProxyState::new(&upstream.uri()).expect("valid upstream URL");
        let app = Router::new()
            .route(
                // post() mirrors the production binding in main.rs so the
                // test catches accidental method-binding regressions.
                "/authorization.v2.AuthorizationService/*method",
                axum::routing::post(proxy),
            )
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = Client::new()
            .post(format!(
                "http://{addr}/authorization.v2.AuthorizationService/GetDecisionMultiResource"
            ))
            .header("content-type", "application/json")
            .body(r#"{"entityIdentifier":{}}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn forwards_post_with_body_and_returns_upstream_response() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas/v2/rewrap"))
            .and(header("authorization", "Bearer test-jwt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(r#"{"ok":true}"#, "application/json"),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        let (proxy_base, _) = spawn_proxy(&upstream.uri()).await;

        let resp = Client::new()
            .post(format!("{proxy_base}/kas/v2/rewrap"))
            .header("authorization", "Bearer test-jwt")
            .body(r#"{"signed_request_token":"abc"}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(resp.text().await.unwrap(), r#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn does_not_forward_host_or_hop_by_hop_headers() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kas/v2/rewrap"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&upstream)
            .await;

        let (proxy_base, proxy_addr) = spawn_proxy(&upstream.uri()).await;

        Client::new()
            .get(format!("{proxy_base}/kas/v2/rewrap"))
            .header("connection", "close")
            .header("te", "trailers")
            .send()
            .await
            .unwrap();

        let received = upstream.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let req = &received[0];

        // Host should be the upstream host, not the proxy's listening address.
        let host = req.headers.get("host").unwrap().to_str().unwrap();
        assert!(
            host.contains(&upstream.address().to_string()),
            "expected upstream host, got {host}"
        );
        assert!(
            !host.contains(&proxy_addr.to_string()),
            "host header leaked proxy address {proxy_addr}, got {host}"
        );

        // Hop-by-hop headers must not be forwarded.
        assert!(req.headers.get("connection").is_none());
        assert!(req.headers.get("te").is_none());
    }

    #[tokio::test]
    async fn forwards_upstream_status_codes() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas/v2/rewrap"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .expect(1)
            .mount(&upstream)
            .await;

        let (proxy_base, _) = spawn_proxy(&upstream.uri()).await;
        let resp = Client::new()
            .post(format!("{proxy_base}/kas/v2/rewrap"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 403);
        assert_eq!(resp.text().await.unwrap(), "forbidden");
    }

    #[tokio::test]
    async fn returns_502_when_upstream_unreachable() {
        // Point at a port nobody is listening on.
        let (proxy_base, _) = spawn_proxy("http://127.0.0.1:1").await;

        let resp = Client::new()
            .post(format!("{proxy_base}/kas/v2/rewrap"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 502);
    }

    async fn spawn_public_key_proxy(upstream: &str) -> String {
        let state = PlatformProxyState::new(upstream).expect("valid upstream URL");
        let app = Router::new()
            .route("/kas/v2/kas_public_key", axum::routing::get(kas_public_key))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn get_json(url: String) -> (u16, serde_json::Value) {
        let resp = Client::new().get(url).send().await.unwrap();
        (resp.status().as_u16(), resp.json().await.unwrap())
    }

    #[tokio::test]
    async fn public_key_translates_to_connect_and_returns_platform_kid() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas.AccessService/PublicKey"))
            .and(wiremock::matchers::body_json(
                serde_json::json!({"algorithm": "rsa:2048", "v": "2"}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"publicKey": "rsa-pem", "kid": "r1"})),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        let base = spawn_public_key_proxy(&upstream.uri()).await;
        let (status, body) = get_json(format!(
            "{base}/kas/v2/kas_public_key?algorithm=rsa:2048&v=2"
        ))
        .await;

        assert_eq!(status, 200);
        assert_eq!(
            body,
            serde_json::json!({"public_key": "rsa-pem", "kid": "r1"})
        );
    }

    #[tokio::test]
    async fn public_key_defaults_to_ec_and_expands_short_names() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas.AccessService/PublicKey"))
            .and(wiremock::matchers::body_json(
                serde_json::json!({"algorithm": "ec:secp256r1"}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"publicKey": "ec-pem", "kid": "e1"})),
            )
            .expect(2)
            .mount(&upstream)
            .await;
        Mock::given(method("POST"))
            .and(path("/kas.AccessService/PublicKey"))
            .and(wiremock::matchers::body_json(
                serde_json::json!({"algorithm": "rsa:2048"}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"publicKey": "rsa-pem"})),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        let base = spawn_public_key_proxy(&upstream.uri()).await;
        let (_, body) = get_json(format!("{base}/kas/v2/kas_public_key")).await;
        assert_eq!(body["kid"], "e1");
        let (_, body) = get_json(format!("{base}/kas/v2/kas_public_key?algorithm=ec")).await;
        assert_eq!(body["kid"], "e1");
        // A platform response without a kid yields none.
        let (_, body) = get_json(format!("{base}/kas/v2/kas_public_key?algorithm=rsa")).await;
        assert_eq!(body, serde_json::json!({"public_key": "rsa-pem"}));
    }

    #[tokio::test]
    async fn public_key_maps_connect_errors() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/kas.AccessService/PublicKey"))
            .respond_with(ResponseTemplate::new(404).set_body_json(
                serde_json::json!({"code": "not_found", "message": "no default key for algorithm"}),
            ))
            .mount(&upstream)
            .await;

        let base = spawn_public_key_proxy(&upstream.uri()).await;
        let (status, body) =
            get_json(format!("{base}/kas/v2/kas_public_key?algorithm=bogus")).await;

        assert_eq!(status, 404);
        assert_eq!(body["error"], "not_found");
        assert_eq!(body["message"], "no default key for algorithm");
    }

    #[tokio::test]
    async fn public_key_upstream_unreachable_is_502() {
        let base = spawn_public_key_proxy("http://127.0.0.1:1").await;
        let (status, body) = get_json(format!("{base}/kas/v2/kas_public_key")).await;

        assert_eq!(status, 502);
        assert_eq!(body["error"], "unavailable");
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;
    use axum::http::{header, HeaderMap, HeaderName, HeaderValue};

    #[test]
    fn strip_hop_by_hop_removes_rfc7230_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert(header::HOST, HeaderValue::from_static("kas.local"));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );

        strip_proxy_headers(&mut headers);

        assert!(!headers.contains_key(header::CONNECTION));
        assert!(!headers.contains_key(header::TE));
        assert!(!headers.contains_key(header::HOST));
        assert!(!headers.contains_key(HeaderName::from_static("keep-alive")));
        assert_eq!(headers.get(header::AUTHORIZATION).unwrap(), "Bearer x");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn strip_proxy_headers_honors_connection_listed_names() {
        // RFC 7230 §6.1: headers named in the Connection field are hop-by-hop
        // for that specific message and must be removed before forwarding.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, X-Custom-Hop"),
        );
        headers.insert(
            HeaderName::from_static("x-custom-hop"),
            HeaderValue::from_static("session=abc"),
        );
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));

        strip_proxy_headers(&mut headers);

        assert!(!headers.contains_key(HeaderName::from_static("x-custom-hop")));
        assert!(!headers.contains_key(header::CONNECTION));
        assert_eq!(headers.get(header::AUTHORIZATION).unwrap(), "Bearer x");
    }
}
