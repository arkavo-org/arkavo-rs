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
