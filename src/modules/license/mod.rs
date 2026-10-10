//! FairPlay license authorization: who may receive a content key, and for
//! which TDF policy. See docs/superpowers/specs/2026-09-28-fairplay-license-authorization-design.md.

pub mod config;
#[cfg(test)]
pub mod fixtures;
pub mod issuer;
pub mod pdp;
pub mod person_token;
pub mod strict_json;
pub mod tdf_policy;

use axum::http::StatusCode;

/// A refusal, carrying only a sanitized reason (never token or key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseError {
    /// 401: the app deletes its token and prompts sign-in (ARK-110).
    Unauthenticated(&'static str),
    /// 403: valid caller, but not allowed (non-person, deny, bad manifest).
    Forbidden(&'static str),
    /// 503: the platform, identity or service credential is unavailable.
    Unavailable(&'static str),
    /// 400: the request is malformed before any authorization step.
    BadRequest(&'static str),
}

impl LicenseError {
    pub fn status(&self) -> StatusCode {
        match self {
            LicenseError::Unauthenticated(_) => StatusCode::UNAUTHORIZED,
            LicenseError::Forbidden(_) => StatusCode::FORBIDDEN,
            LicenseError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            LicenseError::BadRequest(_) => StatusCode::BAD_REQUEST,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            LicenseError::Unauthenticated(_) => "authentication_failed",
            LicenseError::Forbidden(_) => "forbidden",
            LicenseError::Unavailable(_) => "service_unavailable",
            LicenseError::BadRequest(_) => "invalid_request",
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            LicenseError::Unauthenticated(r)
            | LicenseError::Forbidden(r)
            | LicenseError::Unavailable(r)
            | LicenseError::BadRequest(r) => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_code_mapping() {
        assert_eq!(
            LicenseError::Unauthenticated("x").status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(LicenseError::Forbidden("x").status(), StatusCode::FORBIDDEN);
        assert_eq!(
            LicenseError::Unavailable("x").status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            LicenseError::BadRequest("x").status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(LicenseError::Forbidden("x").error_code(), "forbidden");
        assert_eq!(LicenseError::Unavailable("why").reason(), "why");
    }
}
