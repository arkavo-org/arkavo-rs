//! `/owner-kas/v1/*` (design §4.2). Receiver routes take only the owner-KAS
//! bearer; owner routes take only the owner's passkey session CWT. Bodies are
//! read after the credential verifies, never parsed beyond the Rewrap's
//! top-level `signed_request_token`, and never logged.

use super::apns::{PushOutcome, Pusher};
use super::record::{self, Bundle, Passkeys, RecordError, MAX_BUNDLE_BYTES};
use super::store::{
    Enqueued, Limits, NewRequest, Push, QueueStore, RespondError, RouteError, RouteStore,
    StoredRequest, RETENTION_AFTER_DEADLINE,
};
use super::token::{
    is_bare_subject, is_route_id, new_ulid, verify_signed_request, OwnerKasToken, OwnerKasVerifier,
    TokenError,
};
use crate::modules::license::person_token::PersonTokenVerifier;
use crate::modules::license::LicenseError;
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use nanotdf::warn;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_REWRAP_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_PUSH_BODY_BYTES: usize = 1024;
pub const MAX_PENDING_PER_ROUTE: u64 = 64;
pub const MAX_PENDING_PER_SUBMITTER: u64 = 8;
pub const RETRY_AFTER_SECS: u64 = 5;
/// At most one APNs alert per route in this window.
pub const PUSH_INTERVAL_SECS: u64 = 30;

/// Asks identity whether a passkey credential is still the subject's.
#[async_trait]
pub trait CredentialStatus: Send + Sync {
    async fn check(&self, credential_id: &[u8], sub: &str) -> Result<(), StatusRefusal>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusRefusal {
    /// Revoked, unknown, or another subject's: 403.
    Refused(&'static str),
    /// Identity did not answer: 503.
    Unavailable,
}

/// `GET <url>` with `{credentialId}` filled in: 200 `{sub, revoked}` for the
/// subject and not revoked passes; 404 is unknown (refused); anything else
/// is unavailable.
pub struct IdentityCredentialStatus {
    url_template: String,
    http: reqwest::Client,
}

impl IdentityCredentialStatus {
    pub fn new(url_template: String) -> Self {
        Self {
            url_template,
            http: crate::modules::http_client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }
}

#[async_trait]
impl CredentialStatus for IdentityCredentialStatus {
    async fn check(&self, credential_id: &[u8], sub: &str) -> Result<(), StatusRefusal> {
        #[derive(Deserialize)]
        struct Status {
            sub: String,
            revoked: bool,
        }
        let url = self
            .url_template
            .replace("{credentialId}", &URL_SAFE_NO_PAD.encode(credential_id));
        let resp = self.http.get(&url).send().await.map_err(|e| {
            warn!("Passkey credential status unreachable: {}", e.without_url());
            StatusRefusal::Unavailable
        })?;
        match resp.status() {
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::NOT_FOUND => {
                return Err(StatusRefusal::Refused("passkey credential unknown"))
            }
            other => {
                warn!("Passkey credential status failed: {other}");
                return Err(StatusRefusal::Unavailable);
            }
        }
        let status: Status = resp.json().await.map_err(|_| StatusRefusal::Unavailable)?;
        if status.revoked {
            return Err(StatusRefusal::Refused("passkey credential revoked"));
        }
        if status.sub != sub {
            return Err(StatusRefusal::Refused(
                "passkey credential belongs to another subject",
            ));
        }
        Ok(())
    }
}

/// No status check (`OWNER_KAS_CREDENTIAL_STATUS_URL=off`, development only).
pub struct NoCredentialStatus;

#[async_trait]
impl CredentialStatus for NoCredentialStatus {
    async fn check(&self, _: &[u8], _: &str) -> Result<(), StatusRefusal> {
        Ok(())
    }
}

pub struct OwnerKasState {
    pub receivers: OwnerKasVerifier,
    pub owners: PersonTokenVerifier,
    pub routes: Arc<dyn RouteStore>,
    pub queue: Arc<dyn QueueStore>,
    pub pusher: Option<Arc<dyn Pusher>>,
    pub status: Arc<dyn CredentialStatus>,
    pub passkeys: Passkeys,
}

type S = State<Arc<OwnerKasState>>;

pub fn router(state: Arc<OwnerKasState>) -> Router {
    Router::new()
        .route(
            "/owner-kas/v1/routes/:route_id/kas.AccessService/Rewrap",
            post(rewrap).layer(DefaultBodyLimit::max(MAX_REWRAP_BYTES)),
        )
        .route("/owner-kas/v1/requests/:request_id", get(poll))
        .route(
            "/owner-kas/v1/routes/:route_id",
            get(get_route)
                .put(put_route)
                .layer(DefaultBodyLimit::max(MAX_BUNDLE_BYTES)),
        )
        .route(
            "/owner-kas/v1/routes/:route_id/requests",
            get(list_requests),
        )
        .route(
            "/owner-kas/v1/requests/:request_id/response",
            put(put_response).layer(DefaultBodyLimit::max(MAX_RESPONSE_BYTES)),
        )
        .route(
            "/owner-kas/v1/routes/:route_id/push",
            put(put_push)
                .delete(delete_push)
                .layer(DefaultBodyLimit::max(MAX_PUSH_BODY_BYTES)),
        )
        .layer(axum::middleware::map_response(no_store))
        .with_state(state)
}

/// With the relay off, every `/owner-kas/` route answers 503.
pub fn unconfigured_router() -> Router {
    Router::new().route(
        "/owner-kas/*rest",
        any(|| async { err(StatusCode::SERVICE_UNAVAILABLE, "owner KAS not configured") }),
    )
}

async fn no_store(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn err(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// The receiver's owner-KAS token for `route_id` (when given).
// The refusal is the handler's whole response; it is built once per request.
#[allow(clippy::result_large_err)]
async fn receiver(
    state: &OwnerKasState,
    headers: &HeaderMap,
    route_id: Option<&str>,
    grace_secs: i64,
) -> Result<OwnerKasToken, Response> {
    let token =
        bearer(headers).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "owner-KAS token required"))?;
    let t = match state.receivers.verify(token, now(), grace_secs).await {
        Ok(t) => t,
        Err(TokenError::KeySet) => {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity keys unavailable",
            ))
        }
        Err(TokenError::Invalid) => {
            return Err(err(StatusCode::UNAUTHORIZED, "invalid owner-KAS token"))
        }
    };
    if route_id.is_some_and(|r| r != t.route_id) {
        return Err(err(StatusCode::UNAUTHORIZED, "token is for another route"));
    }
    Ok(t)
}

/// The owner's account: a passkey session CWT with a bare lowercase UUID `sub`.
// The refusal is the handler's whole response; it is built once per request.
#[allow(clippy::result_large_err)]
async fn owner(state: &OwnerKasState, headers: &HeaderMap) -> Result<String, Response> {
    match state.owners.verify(headers, now()).await {
        Ok(p) if is_bare_subject(&p.sub) => Ok(p.sub),
        Ok(_) => Err(err(StatusCode::FORBIDDEN, "not a person's session")),
        Err(e) => Err(match e {
            LicenseError::Unavailable(m) => err(StatusCode::SERVICE_UNAVAILABLE, m),
            LicenseError::Forbidden(m) => err(StatusCode::FORBIDDEN, m),
            LicenseError::Unauthenticated(m) | LicenseError::BadRequest(m) => {
                err(StatusCode::UNAUTHORIZED, m)
            }
        }),
    }
}

fn bad_route(route_id: &str) -> Option<Response> {
    (!is_route_id(route_id)).then(|| err(StatusCode::BAD_REQUEST, "invalid route_id"))
}

fn route_error(e: RouteError) -> Response {
    match e {
        RouteError::NotFound => err(StatusCode::NOT_FOUND, "route not found"),
        RouteError::OtherOwner => err(StatusCode::FORBIDDEN, "route belongs to another owner"),
        RouteError::Stale => err(StatusCode::CONFLICT, "seq is not above the stored record's"),
        RouteError::Unavailable(e) => {
            warn!("Owner-KAS route store unavailable: {e}");
            err(StatusCode::SERVICE_UNAVAILABLE, "route store unavailable")
        }
    }
}

fn queue_unavailable(e: String) -> Response {
    warn!("Owner-KAS queue unavailable: {e}");
    err(StatusCode::SERVICE_UNAVAILABLE, "queue unavailable")
}

fn retry_after(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(RETRY_AFTER_SECS));
    res
}

fn pending(request_id: &str, deadline: i64) -> Response {
    let mut res = (
        StatusCode::ACCEPTED,
        Json(json!({ "request_id": request_id, "status": "pending", "deadline": deadline })),
    )
        .into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("/owner-kas/v1/requests/{request_id}")) {
        res.headers_mut().insert(header::LOCATION, v);
    }
    retry_after(res)
}

/// `POST /owner-kas/v1/routes/{route_id}/kas.AccessService/Rewrap`
async fn rewrap(
    State(state): S,
    Path(route_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = bad_route(&route_id) {
        return r;
    }
    let t = match receiver(&state, &headers, Some(&route_id), 0).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let now = now();
    if !verify_signed_request(&body, &t, now) {
        return err(StatusCode::UNAUTHORIZED, "invalid signed request token");
    }
    let route = match state.routes.get(&route_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return err(StatusCode::NOT_FOUND, "route not found"),
        Err(e) => return route_error(e),
    };
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let hash = hex::encode(Sha256::digest(&body));
    let request_id = new_ulid(chrono::Utc::now().timestamp_millis() as u64);
    let enqueued = state
        .queue
        .enqueue(
            NewRequest {
                route_id: &route_id,
                sub: &t.sub,
                body_sha256_hex: &hash,
                deadline: t.exp,
                received_at: now,
                authorization,
                body: &body,
            },
            &request_id,
            &Limits {
                per_route: MAX_PENDING_PER_ROUTE,
                per_submitter: MAX_PENDING_PER_SUBMITTER,
            },
            now,
        )
        .await;
    match enqueued {
        Ok(Enqueued::Created(id)) => {
            if let (Some(pusher), Some(push)) = (state.pusher.clone(), route.push) {
                tokio::spawn(alert(state.clone(), pusher, route_id.clone(), push, t.exp));
            }
            pending(&id, t.exp)
        }
        Ok(Enqueued::Existing(id)) => pending(&id, t.exp),
        Ok(Enqueued::RouteFull) | Ok(Enqueued::SubmitterFull) => retry_after(err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pending requests",
        )),
        Err(e) => queue_unavailable(e),
    }
}

/// The APNs hint: rate-limited per route; a failure never reaches the
/// receiver; a token APNs reports as unregistered is deleted.
async fn alert(
    state: Arc<OwnerKasState>,
    pusher: Arc<dyn Pusher>,
    route_id: String,
    push: Push,
    deadline: i64,
) {
    match state.queue.push_slot(&route_id, PUSH_INTERVAL_SECS).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            warn!("Owner-KAS push rate limit unavailable: {e}");
            return;
        }
    }
    let outcome = pusher
        .alert(&push.apns_token, &push.environment, &route_id, deadline)
        .await;
    if outcome == PushOutcome::Unregistered {
        if let Err(e) = state
            .routes
            .clear_push_token(&route_id, &push.apns_token)
            .await
        {
            warn!("Owner-KAS unregistered APNs token not removed: {e:?}");
        }
    }
}

/// `GET /owner-kas/v1/requests/{request_id}`: the receiver's bearer is
/// accepted until the request is deleted, so a late poll gets 410, not 401.
async fn poll(State(state): S, Path(request_id): Path<String>, headers: HeaderMap) -> Response {
    let t = match receiver(&state, &headers, None, RETENTION_AFTER_DEADLINE).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let not_found = || err(StatusCode::NOT_FOUND, "request not found");
    if !is_route_id(&request_id) {
        return not_found();
    }
    let r = match state.queue.get(&request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => return queue_unavailable(e),
    };
    if r.route_id != t.route_id || r.sub != t.sub {
        return not_found();
    }
    if let Some(answer) = r.response {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            answer,
        )
            .into_response();
    }
    if now() > r.deadline {
        return (StatusCode::GONE, Json(json!({ "status": "expired" }))).into_response();
    }
    pending(&r.request_id, r.deadline)
}

/// `GET /owner-kas/v1/routes/{route_id}`: the record as stored.
async fn get_route(State(state): S, Path(route_id): Path<String>, headers: HeaderMap) -> Response {
    if let Some(r) = bad_route(&route_id) {
        return r;
    }
    if let Err(r) = receiver(&state, &headers, Some(&route_id), 0).await {
        return r;
    }
    match state.routes.get(&route_id).await {
        Ok(Some(r)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            r.bundle,
        )
            .into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "route not found"),
        Err(e) => route_error(e),
    }
}

/// `PUT /owner-kas/v1/routes/{route_id}`: admit a passkey-signed record.
async fn put_route(
    State(state): S,
    Path(route_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = bad_route(&route_id) {
        return r;
    }
    let sub = match owner(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Ok(text) = std::str::from_utf8(&body) else {
        return err(StatusCode::BAD_REQUEST, "body is not UTF-8");
    };
    let Ok(bundle) = serde_json::from_str::<Bundle>(text) else {
        return err(StatusCode::BAD_REQUEST, "body is not a route record bundle");
    };
    let verified = match record::verify_bundle(
        &bundle,
        &route_id,
        &sub,
        &state.receivers.keys,
        &state.receivers.issuer,
        &state.passkeys,
        now(),
    )
    .await
    {
        Ok(v) => v,
        Err(RecordError::KeySet) => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "identity keys unavailable")
        }
        Err(RecordError::Invalid(why)) => {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("invalid route record: {why}"),
            )
        }
    };
    match state.status.check(&verified.credential_id, &sub).await {
        Ok(()) => {}
        Err(StatusRefusal::Refused(why)) => return err(StatusCode::FORBIDDEN, why),
        Err(StatusRefusal::Unavailable) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "credential status unavailable",
            )
        }
    }
    match state
        .routes
        .put_record(&route_id, &sub, verified.record.seq, text)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "route_id": route_id, "seq": verified.record.seq })),
        )
            .into_response(),
        Err(e) => route_error(e),
    }
}

/// The route, if `sub` owns it.
// The refusal is the handler's whole response; it is built once per request.
#[allow(clippy::result_large_err)]
async fn owned_route(state: &OwnerKasState, route_id: &str, sub: &str) -> Result<(), Response> {
    match state.routes.get(route_id).await {
        Ok(Some(r)) if r.owner_sub == sub => Ok(()),
        Ok(Some(_)) => Err(route_error(RouteError::OtherOwner)),
        Ok(None) => Err(route_error(RouteError::NotFound)),
        Err(e) => Err(route_error(e)),
    }
}

#[derive(Deserialize)]
struct After {
    after: Option<String>,
}

fn listed(r: &StoredRequest) -> serde_json::Value {
    json!({
        "request_id": r.request_id,
        "authorization": r.authorization,
        "body": URL_SAFE_NO_PAD.encode(&r.body),
        "received_at": r.received_at,
    })
}

/// `GET /owner-kas/v1/routes/{route_id}/requests?after={request_id}`
async fn list_requests(
    State(state): S,
    Path(route_id): Path<String>,
    Query(q): Query<After>,
    headers: HeaderMap,
) -> Response {
    if let Some(r) = bad_route(&route_id) {
        return r;
    }
    let sub = match owner(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = owned_route(&state, &route_id, &sub).await {
        return r;
    }
    let after = q.after.filter(|a| is_route_id(a));
    match state
        .queue
        .pending(
            &route_id,
            after.as_deref(),
            MAX_PENDING_PER_ROUTE as usize,
            now(),
        )
        .await
    {
        Ok(rs) => Json(json!({
            "requests": rs.iter().map(listed).collect::<Vec<_>>(),
            "cursor": rs.last().map(|r| r.request_id.clone()),
        }))
        .into_response(),
        Err(e) => queue_unavailable(e),
    }
}

/// `PUT /owner-kas/v1/requests/{request_id}/response`: once.
async fn put_response(
    State(state): S,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let sub = match owner(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let not_found = || err(StatusCode::NOT_FOUND, "request not found");
    if !is_route_id(&request_id) {
        return not_found();
    }
    let r = match state.queue.get(&request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => return queue_unavailable(e),
    };
    // Someone else's request is not revealed.
    match state.routes.get(&r.route_id).await {
        Ok(Some(route)) if route.owner_sub == sub => {}
        Ok(_) => return not_found(),
        Err(e) => return route_error(e),
    }
    if body.is_empty() {
        return err(StatusCode::BAD_REQUEST, "empty response");
    }
    match state.queue.respond(&request_id, &body, now()).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(RespondError::NotFound) => not_found(),
        Err(RespondError::AlreadyAnswered) => err(StatusCode::CONFLICT, "already answered"),
        Err(RespondError::Expired) => {
            (StatusCode::GONE, Json(json!({ "status": "expired" }))).into_response()
        }
        Err(RespondError::Unavailable(e)) => queue_unavailable(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushBody {
    apns_token: String,
    environment: String,
}

fn valid_apns_token(t: &str) -> bool {
    (64..=200).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `PUT /owner-kas/v1/routes/{route_id}/push`
async fn put_push(
    State(state): S,
    Path(route_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = bad_route(&route_id) {
        return r;
    }
    let sub = match owner(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Ok(p) = serde_json::from_slice::<PushBody>(&body) else {
        return err(
            StatusCode::BAD_REQUEST,
            "body is not {apns_token, environment}",
        );
    };
    if !valid_apns_token(&p.apns_token) {
        return err(StatusCode::BAD_REQUEST, "invalid apns_token");
    }
    // The APNs key is production-only (arkavo-ios ADR-0074 decision 7):
    // Xcode development tokens can't be reached.
    if p.environment != "production" {
        return err(StatusCode::BAD_REQUEST, "environment must be production");
    }
    let push = Push {
        apns_token: p.apns_token.to_ascii_lowercase(),
        environment: p.environment,
    };
    match state.routes.set_push(&route_id, &sub, &push).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => route_error(e),
    }
}

/// `DELETE /owner-kas/v1/routes/{route_id}/push`
async fn delete_push(
    State(state): S,
    Path(route_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(r) = bad_route(&route_id) {
        return r;
    }
    let sub = match owner(&state, &headers).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.routes.clear_push(&route_id, &sub).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => route_error(e),
    }
}

#[cfg(test)]
mod tests;
