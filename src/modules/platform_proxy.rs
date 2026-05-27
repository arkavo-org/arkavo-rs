//! Reverse proxy to upstream opentdf-platform KAS.
//!
//! See `docs/platform-proxy.md` for operator config and design rationale.

use std::str::FromStr;

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
