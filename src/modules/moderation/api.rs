//! HTTP surface: the viewer's report intake and the moderators' queue.
//!
//! - `POST  /moderation/v1/reports`      a signed-in viewer files a report
//! - `GET   /moderation/v1/reports`      moderators list a status queue
//! - `GET   /moderation/v1/reports/:id`  moderators read one report
//! - `PATCH /moderation/v1/reports/:id`  moderators record a response

use super::auth::{AuthError, SessionVerifier};
use super::report::{InvalidReport, ReportRecord, ReportSubmission, Status, StatusUpdate};
use super::store::{Cursor, Inserted, ReportStore, StoreError};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::{error, info, warn};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

/// A report is a few hundred bytes; the note bound keeps it under 8 KiB.
const MAX_BODY_BYTES: usize = 16 * 1024;
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 100;
const NOTIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// A limiter slower than this is treated as unavailable, so the report goes through.
const LIMITER_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Where moderator notifications and action events go (NATS in production).
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn publish(&self, subject: String, payload: Vec<u8>) -> Result<(), String>;
}

/// Counts hits on `key` in a window that starts at the first hit.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn hit(&self, key: &str, window_secs: u64) -> Result<u64, String>;
}

pub struct RedisRateLimiter {
    client: redis::Client,
    /// One multiplexed connection shared by all reports; dropped on error so
    /// the next report reconnects.
    conn: tokio::sync::Mutex<Option<redis::aio::MultiplexedConnection>>,
}

impl RedisRateLimiter {
    pub fn new(client: redis::Client) -> Self {
        Self {
            client,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    async fn connection(&self) -> Result<redis::aio::MultiplexedConnection, String> {
        let mut cached = self.conn.lock().await;
        if let Some(c) = cached.as_ref() {
            return Ok(c.clone());
        }
        let c = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| e.to_string())?;
        *cached = Some(c.clone());
        Ok(c)
    }
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn hit(&self, key: &str, window_secs: u64) -> Result<u64, String> {
        let mut conn = self.connection().await?;
        // SET NX EX then INCR, atomically: the key always carries an expiry.
        let result: redis::RedisResult<(u64,)> = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(key)
            .arg(0)
            .arg("EX")
            .arg(window_secs)
            .arg("NX")
            .ignore()
            .incr(key, 1)
            .query_async(&mut conn)
            .await;
        match result {
            Ok((count,)) => Ok(count),
            Err(e) => {
                *self.conn.lock().await = None;
                Err(e.to_string())
            }
        }
    }
}

pub struct ModerationState {
    pub store: Arc<dyn ReportStore>,
    pub verifier: SessionVerifier,
    pub limiter: Arc<dyn RateLimiter>,
    pub notifier: Arc<dyn Notifier>,
    pub moderators: HashSet<String>,
    pub retention_secs: i64,
    /// Reports per account per hour; 0 disables.
    pub hourly_limit: u64,
    /// Reports per account per day; 0 disables.
    pub daily_limit: u64,
    /// NATS subject prefix, e.g. `moderation`.
    pub subject_prefix: String,
}

pub fn router(state: Arc<ModerationState>) -> Router {
    Router::new()
        .route(
            "/moderation/v1/reports",
            post(submit_report).get(list_reports),
        )
        .route(
            "/moderation/v1/reports/:id",
            get(get_report).patch(update_report),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

fn err_json(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn auth_fail(e: AuthError) -> Response {
    match e {
        AuthError::Unauthenticated => err_json(StatusCode::UNAUTHORIZED, "sign in required"),
        AuthError::Forbidden => err_json(StatusCode::FORBIDDEN, "not a moderator"),
        AuthError::KeySet => err_json(StatusCode::SERVICE_UNAVAILABLE, "key set unavailable"),
    }
}

fn invalid(e: InvalidReport) -> Response {
    err_json(StatusCode::BAD_REQUEST, e.0)
}

fn store_fail(e: StoreError) -> Response {
    match e {
        StoreError::StatusChanged => {
            err_json(StatusCode::CONFLICT, "report changed; read it again")
        }
        StoreError::Unavailable(detail) => {
            error!("moderation store unavailable: {detail}");
            err_json(StatusCode::SERVICE_UNAVAILABLE, "report store unavailable")
        }
    }
}

fn rfc3339(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// What the viewer gets back: enough to show "sent", nothing more.
fn receipt(r: &ReportRecord) -> Value {
    json!({ "id": r.id, "status": r.status, "receivedAt": rfc3339(r.received_at) })
}

impl ModerationState {
    /// `Err(retry_after_secs)` when the reporter is over a limit. A limiter
    /// that cannot be reached lets the report through: losing a report is
    /// worse than accepting one more.
    async fn within_limits(&self, reporter: &str, now: i64) -> Result<(), u64> {
        for (window, limit) in [(3_600u64, self.hourly_limit), (86_400, self.daily_limit)] {
            if limit == 0 {
                continue;
            }
            let bucket = now as u64 / window;
            let key = format!("moderation:rl:{window}:{reporter}:{bucket}");
            match tokio::time::timeout(LIMITER_TIMEOUT, self.limiter.hit(&key, window)).await {
                Ok(Ok(n)) if n > limit => return Err(window - (now as u64 % window)),
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!("moderation rate limiter unavailable, allowing: {e}"),
                Err(_) => warn!("moderation rate limiter timed out, allowing"),
            }
        }
        Ok(())
    }

    async fn publish(&self, suffix: &str, payload: Value) {
        let subject = format!("{}.{}", self.subject_prefix, suffix);
        let publish = self
            .notifier
            .publish(subject.clone(), payload.to_string().into_bytes());
        // The report is already stored; a stalled bus must not hold the reply.
        match tokio::time::timeout(NOTIFY_TIMEOUT, publish).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!("moderation notify to {subject} failed: {e}"),
            Err(_) => error!("moderation notify to {subject} timed out"),
        }
    }

    /// The moderator alert. It names the report and its target but carries
    /// neither the note nor the reporter; moderators read those from the store.
    async fn notify_received(&self, r: &ReportRecord) {
        self.publish(
            "reports.received",
            json!({
                "type": "report.received",
                "id": r.id,
                "reasons": r.reasons,
                "creatorSubject": r.creator_subject,
                "contentId": r.content_id,
                "receivedAt": rfc3339(r.received_at),
            }),
        )
        .await;
    }

    /// One event per action, for the services that enforce it
    /// (tdf-iroh-s3#17 takedown and suspension, authnz-rs#91 entitlement).
    async fn notify_actions(&self, r: &ReportRecord) {
        for action in &r.actions {
            self.publish(
                &format!("actions.{}", action.as_str()),
                json!({
                    "type": "report.action",
                    "action": action,
                    "reportId": r.id,
                    "creatorSubject": r.creator_subject,
                    "contentId": r.content_id,
                    "moderator": r.moderator_subject,
                    "at": r.resolved_at.map(rfc3339),
                }),
            )
            .await;
        }
    }

    async fn moderator(&self, headers: &HeaderMap) -> Result<String, AuthError> {
        let sub = self.verifier.person(headers).await?;
        if self.moderators.contains(&sub) {
            Ok(sub)
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

pub async fn submit_report(
    State(state): State<Arc<ModerationState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let reporter = match state.verifier.person(&headers).await {
        Ok(s) => s,
        Err(e) => return auth_fail(e),
    };
    let submission: ReportSubmission = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid report payload"),
    };
    let report = match submission.validate() {
        Ok(r) => r,
        Err(e) => return invalid(e),
    };
    let now = chrono::Utc::now().timestamp();
    if let Err(retry_after) = state.within_limits(&reporter, now).await {
        let mut res = err_json(StatusCode::TOO_MANY_REQUESTS, "too many reports");
        res.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
        return res;
    }
    let record = ReportRecord::new(report, reporter, now, state.retention_secs);
    match state.store.insert(&record).await {
        Ok(Inserted::Created) => {
            info!("moderation report received: {}", record.id);
            state.notify_received(&record).await;
            (StatusCode::CREATED, Json(receipt(&record))).into_response()
        }
        // A retry of the same report by the same reporter is acknowledged again.
        Ok(Inserted::Existing(existing)) if existing.same_submission(&record) => {
            (StatusCode::OK, Json(receipt(&existing))).into_response()
        }
        Ok(Inserted::Existing(_)) => err_json(StatusCode::CONFLICT, "report id already used"),
        Err(e) => store_fail(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    status: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

fn encode_cursor(c: &Cursor) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(c).unwrap_or_default())
}

fn decode_cursor(s: &str) -> Option<Cursor> {
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub async fn list_reports(
    State(state): State<Arc<ModerationState>>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    if let Err(e) = state.moderator(&headers).await {
        return auth_fail(e);
    }
    let status = match params.status.as_deref() {
        None => Status::Received,
        Some(s) => match Status::parse(s) {
            Some(st) => st,
            None => return err_json(StatusCode::BAD_REQUEST, "unknown status"),
        },
    };
    let limit = params.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let after = match params.cursor.as_deref() {
        None => None,
        Some(c) => match decode_cursor(c) {
            Some(c) => Some(c),
            None => return err_json(StatusCode::BAD_REQUEST, "invalid cursor"),
        },
    };
    match state.store.list(status, limit, after).await {
        Ok((reports, next)) => Json(json!({
            "reports": reports,
            "nextCursor": next.as_ref().map(encode_cursor),
        }))
        .into_response(),
        Err(e) => store_fail(e),
    }
}

/// Report IDs are stored in the UUID's lowercase hyphenated form.
fn report_key(id: &str) -> Option<String> {
    Uuid::parse_str(id).ok().map(|u| u.to_string())
}

pub async fn get_report(
    State(state): State<Arc<ModerationState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = state.moderator(&headers).await {
        return auth_fail(e);
    }
    let Some(key) = report_key(&id) else {
        return err_json(StatusCode::NOT_FOUND, "no such report");
    };
    match state.store.get(&key).await {
        Ok(Some(r)) => Json(r).into_response(),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "no such report"),
        Err(e) => store_fail(e),
    }
}

pub async fn update_report(
    State(state): State<Arc<ModerationState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let moderator = match state.moderator(&headers).await {
        Ok(m) => m,
        Err(e) => return auth_fail(e),
    };
    let Some(key) = report_key(&id) else {
        return err_json(StatusCode::NOT_FOUND, "no such report");
    };
    let update: StatusUpdate = match serde_json::from_slice(&body) {
        Ok(u) => u,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "invalid update"),
    };
    let current = match state.store.get(&key).await {
        Ok(Some(r)) => r,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "no such report"),
        Err(e) => return store_fail(e),
    };
    let next = match update.apply(&current, &moderator, chrono::Utc::now().timestamp()) {
        Ok(n) => n,
        Err(e) if current.status.is_terminal() => return err_json(StatusCode::CONFLICT, e.0),
        Err(e) => return invalid(e),
    };
    if let Err(e) = state.store.update(&next, current.status).await {
        return store_fail(e);
    }
    info!(
        "moderation report {} {} -> {}",
        next.id,
        current.status.as_str(),
        next.status.as_str()
    );
    state.notify_actions(&next).await;
    Json(next).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authzen::cose_keys::CoseKeyCache;
    use crate::modules::authzen::cwt_verify::test_support::{keypair, mint, mint_map};
    use crate::modules::moderation::store::memory::MemoryReportStore;
    use axum::body::Body;
    use axum::http::Request;
    use ciborium::value::Value as Cbor;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tower::ServiceExt;

    const ISS: &str = "https://identity.arkavo.net";
    const KID: &[u8] = b"kid-1";
    const VIEWER: &str = "11111111-1111-1111-1111-111111111111";
    const MODERATOR: &str = "22222222-2222-2222-2222-222222222222";
    const REPORT_ID: &str = "6F9619FF-8B86-D011-B42D-00C04FC964FF";

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, Value)>>);

    #[async_trait]
    impl Notifier for Recorder {
        async fn publish(&self, subject: String, payload: Vec<u8>) -> Result<(), String> {
            let v = serde_json::from_slice(&payload).unwrap();
            self.0.lock().unwrap().push((subject, v));
            Ok(())
        }
    }

    #[derive(Default)]
    struct Counter(Mutex<HashMap<String, u64>>, Mutex<bool>, Mutex<bool>);

    #[async_trait]
    impl RateLimiter for Counter {
        async fn hit(&self, key: &str, _window: u64) -> Result<u64, String> {
            if *self.1.lock().unwrap() {
                return Err("down".into());
            }
            if *self.2.lock().unwrap() {
                std::future::pending::<()>().await;
            }
            let mut m = self.0.lock().unwrap();
            let n = m.entry(key.to_string()).or_default();
            *n += 1;
            Ok(*n)
        }
    }

    struct Harness {
        app: Router,
        store: Arc<MemoryReportStore>,
        notes: Arc<Recorder>,
        limiter: Arc<Counter>,
    }

    fn harness(hourly: u64) -> Harness {
        let (_, vk) = keypair();
        let store = Arc::new(MemoryReportStore::default());
        let notes = Arc::new(Recorder::default());
        let limiter = Arc::new(Counter::default());
        let state = Arc::new(ModerationState {
            store: store.clone(),
            verifier: SessionVerifier {
                issuer: ISS.into(),
                audience: "arkavo".into(),
                keys: CoseKeyCache::with_static_keys(vec![(KID.to_vec(), vk)]),
            },
            limiter: limiter.clone(),
            notifier: notes.clone(),
            moderators: HashSet::from([MODERATOR.to_string()]),
            retention_secs: 365 * 86_400,
            hourly_limit: hourly,
            daily_limit: 100,
            subject_prefix: "moderation".into(),
        });
        Harness {
            app: router(state),
            store,
            notes,
            limiter,
        }
    }

    fn token(sub: &str) -> String {
        let (sk, _) = keypair();
        let now = chrono::Utc::now().timestamp();
        mint(
            &sk,
            KID,
            ISS,
            sub,
            "arkavo",
            now,
            now + 3_600,
            sub.as_bytes(),
        )
    }

    fn payload(id: &str) -> Value {
        json!({
            "blockUser": true,
            "blockedPublicID": "creator-a",
            "contentId": "content-1",
            "id": id,
            "reasons": ["harassment"],
            "timestamp": "2026-10-02T12:00:00Z",
            "appVersion": "App: Arkavo 3.0 (112)",
            "note": "please look"
        })
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(t) = bearer {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let body = body.map_or(Body::empty(), |b| Body::from(b.to_string()));
        let res = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, headers, v)
    }

    async fn submit(h: &Harness, sub: &str, id: &str) -> (StatusCode, HeaderMap, Value) {
        call(
            &h.app,
            "POST",
            "/moderation/v1/reports",
            Some(&token(sub)),
            Some(payload(id)),
        )
        .await
    }

    #[tokio::test]
    async fn a_signed_in_report_is_stored_once_and_moderators_are_told() {
        let h = harness(20);
        let (status, _, body) = submit(&h, VIEWER, REPORT_ID).await;
        assert_eq!(status, StatusCode::CREATED);
        let id = REPORT_ID.to_lowercase();
        assert_eq!(body["id"], id);
        assert_eq!(body["status"], "received");

        let stored = h.store.records.lock().unwrap().get(&id).cloned().unwrap();
        assert_eq!(stored.reporter_subject, VIEWER);
        assert_eq!(stored.note.as_deref(), Some("please look"));
        assert_eq!(stored.app_version.as_deref(), Some("App: Arkavo 3.0 (112)"));

        let notes = h.notes.0.lock().unwrap().clone();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].0, "moderation.reports.received");
        assert_eq!(notes[0].1["id"], id);
        assert_eq!(notes[0].1["contentId"], "content-1");
        // The alert carries neither the note nor the reporter.
        let alert = notes[0].1.to_string();
        assert!(!alert.contains("please look"));
        assert!(!alert.contains(VIEWER));
    }

    #[tokio::test]
    async fn reports_about_the_same_recording_do_not_overwrite() {
        let h = harness(20);
        let a = Uuid::new_v4().to_string();
        let b = Uuid::new_v4().to_string();
        assert_eq!(submit(&h, VIEWER, &a).await.0, StatusCode::CREATED);
        assert_eq!(submit(&h, MODERATOR, &b).await.0, StatusCode::CREATED);
        assert_eq!(h.store.records.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_retry_is_acknowledged_and_a_reused_id_is_refused() {
        let h = harness(20);
        assert_eq!(submit(&h, VIEWER, REPORT_ID).await.0, StatusCode::CREATED);
        assert_eq!(submit(&h, VIEWER, REPORT_ID).await.0, StatusCode::OK);
        assert_eq!(
            submit(&h, MODERATOR, REPORT_ID).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(h.notes.0.lock().unwrap().len(), 1);
        let stored = h
            .store
            .records
            .lock()
            .unwrap()
            .values()
            .next()
            .cloned()
            .unwrap();
        assert_eq!(stored.reporter_subject, VIEWER);
    }

    #[tokio::test]
    async fn signed_out_and_non_person_tokens_are_refused() {
        let h = harness(20);
        let uri = "/moderation/v1/reports";
        let p = Some(payload(REPORT_ID));
        assert_eq!(
            call(&h.app, "POST", uri, None, p.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&h.app, "POST", uri, Some("garbage"), p.clone())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let (sk, _) = keypair();
        let now = chrono::Utc::now().timestamp();
        let expired = mint(
            &sk,
            KID,
            ISS,
            VIEWER,
            "arkavo",
            now - 7_200,
            now - 3_600,
            b"x",
        );
        assert_eq!(
            call(&h.app, "POST", uri, Some(&expired), p.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let wrong_aud = mint(&sk, KID, ISS, VIEWER, "other", now, now + 60, b"y");
        assert_eq!(
            call(&h.app, "POST", uri, Some(&wrong_aud), p.clone())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let service = token("client:catalog-node");
        assert_eq!(
            call(&h.app, "POST", uri, Some(&service), p.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let access = mint_map(
            &sk,
            KID,
            vec![
                (Cbor::Integer(1.into()), Cbor::Text(ISS.into())),
                (Cbor::Integer(2.into()), Cbor::Text(VIEWER.into())),
                (Cbor::Integer(3.into()), Cbor::Text("arkavo".into())),
                (Cbor::Integer(4.into()), Cbor::Integer((now + 60).into())),
                (Cbor::Integer(6.into()), Cbor::Integer(now.into())),
                (Cbor::Integer(7.into()), Cbor::Bytes(vec![9; 16])),
                (Cbor::Text("scope".into()), Cbor::Text("openid".into())),
            ],
        );
        assert_eq!(
            call(&h.app, "POST", uri, Some(&access), p).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert!(h.store.records.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bad_payloads_are_refused() {
        let h = harness(20);
        let mut p = payload(REPORT_ID);
        p["reporter"] = json!(VIEWER);
        let (status, _, _) = call(
            &h.app,
            "POST",
            "/moderation/v1/reports",
            Some(&token(VIEWER)),
            Some(p),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let mut p = payload(REPORT_ID);
        p["reasons"] = json!(["nope"]);
        let (status, _, body) = call(
            &h.app,
            "POST",
            "/moderation/v1/reports",
            Some(&token(VIEWER)),
            Some(p),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "unknown reason");
    }

    #[tokio::test]
    async fn oversized_bodies_are_refused() {
        let h = harness(20);
        let mut p = payload(REPORT_ID);
        p["note"] = json!("a".repeat(MAX_BODY_BYTES));
        let (status, _, _) = call(
            &h.app,
            "POST",
            "/moderation/v1/reports",
            Some(&token(VIEWER)),
            Some(p),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn reporters_are_rate_limited_per_account() {
        let h = harness(2);
        for _ in 0..2 {
            let id = Uuid::new_v4().to_string();
            assert_eq!(submit(&h, VIEWER, &id).await.0, StatusCode::CREATED);
        }
        let (status, headers, _) = submit(&h, VIEWER, &Uuid::new_v4().to_string()).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 = headers[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=3_600).contains(&retry));
        // Another account is unaffected.
        let id = Uuid::new_v4().to_string();
        assert_eq!(submit(&h, MODERATOR, &id).await.0, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn an_unreachable_limiter_lets_reports_through() {
        let h = harness(1);
        *h.limiter.1.lock().unwrap() = true;
        for _ in 0..3 {
            let id = Uuid::new_v4().to_string();
            assert_eq!(submit(&h, VIEWER, &id).await.0, StatusCode::CREATED);
        }
    }

    #[tokio::test]
    async fn a_hung_limiter_lets_reports_through_in_bounded_time() {
        let h = harness(1);
        *h.limiter.2.lock().unwrap() = true;
        let started = std::time::Instant::now();
        assert_eq!(submit(&h, VIEWER, REPORT_ID).await.0, StatusCode::CREATED);
        // Two windows, each bounded by LIMITER_TIMEOUT.
        assert!(started.elapsed() < LIMITER_TIMEOUT * 3);
    }

    #[tokio::test]
    async fn a_store_outage_is_a_failure_not_a_success() {
        let h = harness(20);
        *h.store.fail.lock().unwrap() = true;
        assert_eq!(
            submit(&h, VIEWER, REPORT_ID).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(h.notes.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn only_moderators_read_the_queue() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        let id = REPORT_ID.to_lowercase();
        for uri in [
            "/moderation/v1/reports".to_string(),
            format!("/moderation/v1/reports/{id}"),
        ] {
            assert_eq!(
                call(&h.app, "GET", &uri, None, None).await.0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                call(&h.app, "GET", &uri, Some(&token(VIEWER)), None)
                    .await
                    .0,
                StatusCode::FORBIDDEN
            );
        }
        let (status, _, body) = call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{id}"),
            Some(&token(VIEWER)),
            Some(json!({"status": "dismissed"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "not a moderator");
    }

    #[tokio::test]
    async fn the_queue_pages_oldest_first() {
        let h = harness(20);
        let ids: Vec<String> = (0..3).map(|_| Uuid::new_v4().to_string()).collect();
        for id in &ids {
            submit(&h, VIEWER, id).await;
        }
        // Distinct receive times so the order is defined.
        for (i, id) in ids.iter().enumerate() {
            h.store
                .records
                .lock()
                .unwrap()
                .get_mut(id)
                .unwrap()
                .received_at = 1_000 + i as i64;
        }
        let m = token(MODERATOR);
        let (status, _, page1) = call(
            &h.app,
            "GET",
            "/moderation/v1/reports?limit=2",
            Some(&m),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let got: Vec<_> = page1["reports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(got, ids[..2].to_vec());
        let cursor = page1["nextCursor"].as_str().unwrap();
        let (_, _, page2) = call(
            &h.app,
            "GET",
            &format!("/moderation/v1/reports?limit=2&cursor={cursor}"),
            Some(&m),
            None,
        )
        .await;
        assert_eq!(page2["reports"][0]["id"], ids[2]);
        assert_eq!(page2["nextCursor"], Value::Null);
        let (status, _, _) = call(
            &h.app,
            "GET",
            "/moderation/v1/reports?status=bogus",
            Some(&m),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_moderator_response_is_timed_and_actions_are_published() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        let id = REPORT_ID.to_lowercase();
        let uri = format!("/moderation/v1/reports/{id}");
        let m = token(MODERATOR);

        let (status, _, body) = call(
            &h.app,
            "PATCH",
            &uri,
            Some(&m),
            Some(json!({"status": "reviewing"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "reviewing");
        assert!(body["firstResponseAt"].is_i64());
        assert!(body["responseSeconds"].as_i64().unwrap() >= 0);
        assert_eq!(body["moderatorSubject"], MODERATOR);

        let (status, _, body) = call(
            &h.app,
            "PATCH",
            &uri,
            Some(&m),
            Some(json!({"status": "actioned", "actions": ["takedown", "suspend"], "note": "removed"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "actioned");
        assert!(body["resolvedAt"].is_i64());

        let subjects: Vec<String> = h
            .notes
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|n| n.0.clone())
            .collect();
        assert_eq!(
            subjects,
            vec![
                "moderation.reports.received",
                "moderation.actions.takedown",
                "moderation.actions.suspend"
            ]
        );
        let takedown = h.notes.0.lock().unwrap()[1].1.clone();
        assert_eq!(takedown["reportId"], id);
        assert_eq!(takedown["contentId"], "content-1");
        assert_eq!(takedown["creatorSubject"], "creator-a");

        // A resolved report is final.
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &uri,
            Some(&m),
            Some(json!({"status": "dismissed"})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _, body) = call(&h.app, "GET", &uri, Some(&m), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resolutionNote"], "removed");
        assert_eq!(body["reporterSubject"], VIEWER);
    }

    #[tokio::test]
    async fn unknown_and_malformed_ids_are_not_found() {
        let h = harness(20);
        let m = token(MODERATOR);
        for id in ["not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
            let uri = format!("/moderation/v1/reports/{id}");
            assert_eq!(
                call(&h.app, "GET", &uri, Some(&m), None).await.0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                call(
                    &h.app,
                    "PATCH",
                    &uri,
                    Some(&m),
                    Some(json!({"status": "reviewing"}))
                )
                .await
                .0,
                StatusCode::NOT_FOUND
            );
        }
    }
}
