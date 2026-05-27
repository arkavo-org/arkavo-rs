//! Reverse proxy to upstream opentdf-platform KAS.
//!
//! See `docs/platform-proxy.md` for operator config and design rationale.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, HeaderMap, HeaderName};
use reqwest::Client;
use url::Url;

/// Which arks routes get forwarded to opentdf-platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    /// No forwarding; arks handles everything locally.
    Off,
    /// Forward only ConnectRPC routes (`/kas.AccessService/*`).
    Connect,
    /// Forward only legacy REST routes (`/kas/v2/rewrap`, `/kas/v2/kas_public_key`).
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
pub(crate) fn strip_proxy_headers(headers: &mut HeaderMap) {
    for h in HOP_BY_HOP {
        headers.remove(h);
    }
    // Also strip any header named in a Connection: header list (RFC 7230 §6.1).
    // Not all proxies do this, but it's cheap and correct.
    headers.remove(HeaderName::from_static("keep-alive"));
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

        assert!(ProxyMode::Connect.forwards_connect());
        assert!(!ProxyMode::Connect.forwards_rest());

        assert!(!ProxyMode::Rest.forwards_connect());
        assert!(ProxyMode::Rest.forwards_rest());

        assert!(ProxyMode::Both.forwards_connect());
        assert!(ProxyMode::Both.forwards_rest());
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
}
