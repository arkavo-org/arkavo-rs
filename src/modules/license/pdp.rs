//! OpenTDF `GetDecision` with the viewer's own token as the entity, called
//! as the `arks-media` service client. Only DECISION_PERMIT allows.

use super::LicenseError;
use reqwest::redirect::Policy;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

pub struct PlatformPdp {
    platform_url: String,
    token_url: String,
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
    service_token: Mutex<Option<(String, Instant)>>,
}

pub fn decision_request(user_token: &str, resource_id: &str, fqns: &[String]) -> Value {
    json!({
        "entityIdentifier": {"token": {"ephemeralId": "viewer", "jwt": user_token}},
        "action": {"name": "read"},
        "resource": {"ephemeralId": resource_id, "attributeValues": {"fqns": fqns}},
    })
}

/// Connect error codes: bad input / not found / not allowed → 403; anything
/// that means "could not decide" → 503. Never a 500.
pub fn map_connect_error(http_status: u16, body: &Value) -> LicenseError {
    match body.get("code").and_then(Value::as_str) {
        Some(
            "invalid_argument"
            | "not_found"
            | "permission_denied"
            | "failed_precondition"
            | "out_of_range",
        ) => LicenseError::Forbidden("platform refused the decision request"),
        _ => {
            log::warn!("license pdp: platform HTTP {http_status}");
            LicenseError::Unavailable("platform decision unavailable")
        }
    }
}

impl PlatformPdp {
    pub fn new(
        platform_url: &str,
        token_url: String,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(Policy::none())
            .build()
            .map_err(|e| format!("license pdp http client: {e}"))?;
        Ok(Self {
            platform_url: platform_url.trim_end_matches('/').to_string(),
            token_url,
            client_id,
            client_secret,
            http,
            service_token: Mutex::new(None),
        })
    }

    async fn service_token(&self, force: bool) -> Result<String, LicenseError> {
        let mut guard = self.service_token.lock().await;
        if !force {
            if let Some((t, exp)) = guard.as_ref() {
                if Instant::now() + REFRESH_MARGIN < *exp {
                    return Ok(t.clone());
                }
            }
        }
        let resp = self
            .http
            .post(&self.token_url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("grant_type", "client_credentials")])
            .send()
            .await
            .map_err(|_| LicenseError::Unavailable("identity unreachable"))?;
        if !resp.status().is_success() {
            log::error!("license pdp: service token HTTP {}", resp.status());
            return Err(LicenseError::Unavailable("service credential rejected"));
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|_| LicenseError::Unavailable("bad token response"))?;
        let token = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or(LicenseError::Unavailable("bad token response"))?
            .to_string();
        let ttl = body
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(300);
        *guard = Some((token.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(token)
    }

    pub async fn decide(
        &self,
        user_token: &str,
        resource_id: &str,
        fqns: &[String],
        rid: &str,
    ) -> Result<(), LicenseError> {
        let body = decision_request(user_token, resource_id, fqns);
        let url = format!(
            "{}/authorization.v2.AuthorizationService/GetDecision",
            self.platform_url
        );
        let mut force = false;
        for _ in 0..2 {
            let bearer = self.service_token(force).await?;
            let resp = self
                .http
                .post(&url)
                .header("content-type", "application/json")
                .header("connect-protocol-version", "1")
                .header("x-request-id", rid)
                .bearer_auth(&bearer)
                .json(&body)
                .send()
                .await
                .map_err(|_| LicenseError::Unavailable("platform unreachable"))?;
            let status = resp.status();
            if status.as_u16() == 401 && !force {
                force = true;
                continue;
            }
            if !status.is_success() {
                let json: Value = resp.json().await.unwrap_or(Value::Null);
                return Err(map_connect_error(status.as_u16(), &json));
            }
            let json: Value = resp
                .json()
                .await
                .map_err(|_| LicenseError::Unavailable("platform decision unreadable"))?;
            return match json["decision"]["decision"].as_str() {
                Some("DECISION_PERMIT") => Ok(()),
                Some("DECISION_DENY") => Err(LicenseError::Forbidden("platform denied")),
                _ => Err(LicenseError::Unavailable("platform returned no decision")),
            };
        }
        Err(LicenseError::Unavailable("service credential rejected"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const GD: &str = "/authorization.v2.AuthorizationService/GetDecision";

    const CLIENT_ID: &str = "arks-media";

    /// Random per-run secret; never a committed literal.
    fn test_secret() -> &'static str {
        static S: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        S.get_or_init(|| uuid::Uuid::new_v4().to_string())
    }

    async fn token_mock(server: &MockServer, times: u64) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let expected = format!(
            "Basic {}",
            STANDARD.encode(format!("{CLIENT_ID}:{}", test_secret()))
        );
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(header("authorization", expected.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"access_token":"svc-1","expires_in":3600,"token_type":"Bearer"}),
            ))
            .expect(times)
            .mount(server)
            .await;
    }

    fn pdp(server: &MockServer) -> PlatformPdp {
        PlatformPdp::new(
            &server.uri(),
            format!("{}/oauth/token", server.uri()),
            CLIENT_ID.into(),
            test_secret().into(),
        )
        .unwrap()
    }

    #[test]
    fn request_shape_uses_token_entity() {
        let v = decision_request("user-cwt", "uuid-1", &["https://a/attr/x/value/y".into()]);
        assert_eq!(v["entityIdentifier"]["token"]["jwt"], "user-cwt");
        assert_eq!(v["action"]["name"], "read");
        assert_eq!(v["resource"]["ephemeralId"], "uuid-1");
        assert_eq!(
            v["resource"]["attributeValues"]["fqns"][0],
            "https://a/attr/x/value/y"
        );
    }

    #[tokio::test]
    async fn permit_and_deny() {
        let server = MockServer::start().await;
        token_mock(&server, 1).await; // cached across both calls
        Mock::given(method("POST"))
            .and(path(GD))
            .and(header("authorization", "Bearer svc-1"))
            .and(body_partial_json(
                json!({"resource":{"ephemeralId":"permit-me"}}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"decision":{"decision":"DECISION_PERMIT"}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(GD))
            .and(body_partial_json(
                json!({"resource":{"ephemeralId":"deny-me"}}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"decision":{"decision":"DECISION_DENY"}})),
            )
            .mount(&server)
            .await;
        let p = pdp(&server);
        assert_eq!(p.decide("u", "permit-me", &["f".into()], "r").await, Ok(()));
        assert!(matches!(
            p.decide("u", "deny-me", &["f".into()], "r").await,
            Err(LicenseError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn stale_service_token_is_reminted_once() {
        let server = MockServer::start().await;
        token_mock(&server, 2).await;
        Mock::given(method("POST"))
            .and(path(GD))
            .respond_with(
                ResponseTemplate::new(401).set_body_json(json!({"code":"unauthenticated"})),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(GD))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"decision":{"decision":"DECISION_PERMIT"}})),
            )
            .mount(&server)
            .await;
        assert_eq!(
            pdp(&server).decide("u", "x", &["f".into()], "r").await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn platform_down_is_503() {
        let p = PlatformPdp::new(
            "http://127.0.0.1:9",
            "http://127.0.0.1:9/oauth/token".into(),
            "a".into(),
            "b".into(),
        )
        .unwrap();
        assert!(matches!(
            p.decide("u", "x", &["f".into()], "r").await,
            Err(LicenseError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn unspecified_or_unreadable_decision_is_503() {
        for resp in [
            ResponseTemplate::new(200)
                .set_body_json(json!({"decision":{"decision":"DECISION_UNSPECIFIED"}})),
            ResponseTemplate::new(200).set_body_string("not json"),
        ] {
            let server = MockServer::start().await;
            token_mock(&server, 1).await;
            Mock::given(method("POST"))
                .and(path(GD))
                .respond_with(resp)
                .mount(&server)
                .await;
            assert!(matches!(
                pdp(&server).decide("u", "x", &["f".into()], "r").await,
                Err(LicenseError::Unavailable(_))
            ));
        }
    }

    #[test]
    fn connect_error_mapping() {
        for code in [
            "invalid_argument",
            "not_found",
            "permission_denied",
            "failed_precondition",
        ] {
            assert!(
                matches!(
                    map_connect_error(400, &json!({"code": code})),
                    LicenseError::Forbidden(_)
                ),
                "{code}"
            );
        }
        for code in [
            "unavailable",
            "deadline_exceeded",
            "internal",
            "unknown",
            "unauthenticated",
        ] {
            assert!(
                matches!(
                    map_connect_error(503, &json!({"code": code})),
                    LicenseError::Unavailable(_)
                ),
                "{code}"
            );
        }
        assert!(matches!(
            map_connect_error(502, &json!(null)),
            LicenseError::Unavailable(_)
        ));
    }
}
