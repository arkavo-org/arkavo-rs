//! HTTP surface: the viewer's report intake and the moderators' queue.
//!
//! - `POST  /moderation/v1/reports`      a signed-in viewer files a report
//! - `GET   /moderation/v1/reports`      moderators list a status queue
//! - `GET   /moderation/v1/reports/:id`  moderators read one report
//! - `PATCH /moderation/v1/reports/:id`  moderators record a response
//! - `GET    /moderation/v1/suspensions/:subject`  the platform reads an
//!   account's publishing suspension (service CWT, arkavo-rs#93)
//! - `DELETE /moderation/v1/suspensions/:subject`  moderators lift it, with a
//!   reason; the lift is recorded, not deleted

use super::auth::{AuthError, SessionVerifier};
use super::report::{
    identifier, normalised_note, Action, InvalidReport, ReportRecord, ReportSubmission, Status,
    StatusUpdate,
};
use super::store::{Cursor, Inserted, Lift, ReportStore, StoreError, Suspension, SuspensionStore};
use crate::modules::authzen::cwt_subject::subject_id_bind;
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::{error, info, warn};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

/// The note is bounded in grapheme clusters, not bytes: 1,000 ZWJ family
/// emoji are about 25 KB. This leaves room for any note the viewer accepts.
const MAX_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_PAGE: usize = 50;
const MAX_PAGE: usize = 100;
const NOTIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Longest suspension reason: identity's publishing-suspension API refuses a
/// longer `reason`, and #93's identity call sends the stored reason unchanged.
const MAX_SUSPENSION_REASON_LEN: usize = 1_024;
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
    pub suspensions: Arc<dyn SuspensionStore>,
    pub verifier: SessionVerifier,
    /// Service clients that may read suspensions.
    pub suspension_readers: HashSet<String>,
    /// Required in a suspension reader's token `aud` (this server).
    pub suspension_reader_audience: String,
    pub limiter: Arc<dyn RateLimiter>,
    pub notifier: Arc<dyn Notifier>,
    pub moderators: HashSet<String>,
    /// Kept this long after a report is resolved.
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
        .route(
            "/moderation/v1/suspensions/:subject",
            get(get_suspension).delete(lift_suspension),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// With the intake off, the suspension route answers 503 (any method) rather
/// than 404, so a reader can tell "not configured" from "not suspended" (it
/// fails closed on both).
pub fn unconfigured_router() -> Router {
    Router::new().route(
        "/moderation/v1/suspensions/:subject",
        any(|| async { err_json(StatusCode::SERVICE_UNAVAILABLE, "moderation not configured") }),
    )
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
    store_error(
        e,
        "report changed; read it again",
        "report store unavailable",
    )
}

fn store_error(e: StoreError, changed: &str, unavailable: &str) -> Response {
    match e {
        StoreError::StatusChanged => err_json(StatusCode::CONFLICT, changed),
        StoreError::Unavailable(detail) => {
            error!("moderation {unavailable}: {detail}");
            err_json(StatusCode::SERVICE_UNAVAILABLE, unavailable)
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

    /// Publish within `NOTIFY_TIMEOUT`, so a stalled bus cannot hold the reply.
    async fn try_publish(&self, suffix: &str, payload: Value) -> Result<(), String> {
        let subject = format!("{}.{}", self.subject_prefix, suffix);
        let publish = self
            .notifier
            .publish(subject.clone(), payload.to_string().into_bytes());
        match tokio::time::timeout(NOTIFY_TIMEOUT, publish).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("notify to {subject} failed: {e}")),
            Err(_) => Err(format!("notify to {subject} timed out")),
        }
    }

    /// For alerts about a report that is already stored: a failure is logged,
    /// and the report stays in the `received` queue.
    async fn publish(&self, suffix: &str, payload: Value) {
        if let Err(e) = self.try_publish(suffix, payload).await {
            error!("moderation {e}");
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
    /// Sent before the report is stored as actioned: if delivery fails the
    /// report is unchanged and the moderator can retry. A retry after a
    /// partial failure sends an action again, so enforcers must be idempotent.
    async fn deliver_actions(&self, r: &ReportRecord) -> Result<(), String> {
        for action in &r.actions {
            self.try_publish(
                &format!("actions.{}", action.as_str()),
                json!({
                    "type": "report.action",
                    "action": action,
                    "reportId": r.id,
                    "creatorSubject": r.creator_subject,
                    // The account key, as in the lift event and the stored
                    // suspension: enforcers pair a suspend with its lift on it.
                    "account": r.creator_subject.as_deref().and_then(account_id),
                    "contentId": r.content_id,
                    "moderator": r.moderator_subject,
                    // The moderator's note, which is a suspend's reason
                    "reason": r.resolution_note,
                    "at": r.resolved_at.map(rfc3339),
                }),
            )
            .await?;
        }
        Ok(())
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
    let record = ReportRecord::new(report, reporter, now);
    // A retry of a stored report is answered before the rate limit, so it
    // neither uses quota nor gets 429. A store outage fails here, before any
    // quota is used.
    match state.store.get(&record.id).await {
        Ok(Some(existing)) if existing.same_submission(&record) => {
            return (StatusCode::OK, Json(receipt(&existing))).into_response();
        }
        Ok(Some(_)) => return err_json(StatusCode::CONFLICT, "report id already used"),
        Ok(None) => {}
        Err(e) => return store_fail(e),
    }
    if let Err(retry_after) = state.within_limits(&record.reporter_subject, now).await {
        let mut res = err_json(StatusCode::TOO_MANY_REQUESTS, "too many reports");
        res.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
        return res;
    }
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

/// A cursor is only ever one this server issued: a stored report ID (the
/// canonical UUID) and a receive time. Anything else is the client's error,
/// not the store's.
fn decode_cursor(s: &str) -> Option<Cursor> {
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    let c: Cursor = serde_json::from_slice(&bytes).ok()?;
    let canonical = report_key(&c.id)?;
    (canonical == c.id && c.received_at >= 0).then_some(c)
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
    // A moderator never decides a report they filed, or one about their own
    // account, whatever the response.
    let me = account_id(&moderator).unwrap_or_else(|| moderator.clone());
    let reporter = account_id(&current.reporter_subject);
    let creator = current.creator_subject.as_deref().and_then(account_id);
    if reporter.as_deref() == Some(me.as_str()) || creator.as_deref() == Some(me.as_str()) {
        return err_json(
            StatusCode::FORBIDDEN,
            "a moderator can't respond to their own report or one about their own account",
        );
    }
    // A suspend carries its own reason in this request; a note left by an
    // earlier response doesn't count.
    // Only an actioned response takes actions; `apply` reports any other misuse.
    let suspending = update.status == Status::Actioned && update.actions.contains(&Action::Suspend);
    let reason = update
        .note
        .as_deref()
        .map(normalised_note)
        .filter(|n| !n.is_empty());
    if suspending {
        match &reason {
            None => return err_json(StatusCode::BAD_REQUEST, "suspend requires a note"),
            Some(r) if r.chars().count() > MAX_SUSPENSION_REASON_LEN => {
                return err_json(
                    StatusCode::BAD_REQUEST,
                    "a suspend note is at most 1024 characters",
                )
            }
            Some(_) => {}
        }
    }
    let now = chrono::Utc::now().timestamp();
    let mut next = match update.apply(&current, &moderator, now) {
        Ok(n) => n,
        Err(e) if current.status.is_terminal() => return err_json(StatusCode::CONFLICT, e.0),
        Err(e) => return invalid(e),
    };
    if next.status.is_terminal() {
        next.expires_at = Some(now.saturating_add(state.retention_secs));
    }
    // A suspension is stored in the same atomic write as the actioned report,
    // after the action events are delivered: an account is never suspended by
    // a report that wasn't actioned, and a failed or raced PATCH changes nothing.
    let suspension = if suspending {
        // `apply` already requires a creator; a subject that is only the
        // `arkavo:` prefix names no account, and suspending nothing must not pass.
        let Some(subject) = creator else {
            return err_json(
                StatusCode::BAD_REQUEST,
                "suspend requires a usable creator subject",
            );
        };
        Some(Suspension {
            subject,
            since: now,
            report_id: next.id.clone(),
            moderator: moderator.clone(),
            reason: reason.unwrap_or_default(),
            lifted: None,
        })
    } else {
        None
    };
    if let Err(e) = state.deliver_actions(&next).await {
        error!("moderation report {}: {e}; report left unchanged", next.id);
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "action not delivered; the report is unchanged, try again",
        );
    }
    let stored = match &suspension {
        Some(s) => state
            .suspensions
            .suspend_with_report(s, &next, current.status)
            .await
            .map(Some),
        None => state
            .store
            .update(&next, current.status)
            .await
            .map(|_| None),
    };
    match stored {
        Ok(Some(created)) => info!(
            "moderation suspension for {} (report {}): {}",
            suspension.as_ref().map_or("", |s| s.subject.as_str()),
            next.id,
            if created {
                "recorded"
            } else {
                "already suspended"
            }
        ),
        Ok(None) => {}
        Err(e) => return store_fail(e),
    }
    info!(
        "moderation report {} {} -> {}",
        next.id,
        current.status.as_str(),
        next.status.as_str()
    );
    Json(next).into_response()
}

/// The key for an account: its token `sub` without the `arkavo:` prefix, and a
/// UUID in its lowercase hyphenated form, so `arkavo:<UUID>` and `<uuid>` name
/// the same account. `None` when the subject fails the report identifier rules
/// (empty, over 256 bytes, whitespace or control characters) or is only the
/// prefix.
fn account_id(subject: &str) -> Option<String> {
    let subject = identifier(Some(subject.to_string()), "invalid subject")
        .ok()
        .flatten()?;
    let key = subject_id_bind(&subject);
    if key.is_empty() {
        return None;
    }
    // Only the hyphenated form folds case; braced, URN and simple spellings stay
    // as they are, distinct from the account they resemble.
    let hyphenated = key.len() == 36 && Uuid::parse_str(key).is_ok();
    Some(if hyphenated {
        key.to_ascii_lowercase()
    } else {
        key.to_string()
    })
}

fn suspension_fail(e: StoreError) -> Response {
    store_error(
        e,
        "suspension changed; try again",
        "suspension store unavailable",
    )
}

/// `GET /moderation/v1/suspensions/:subject`, for the platform's
/// `constraints.publishing_status` (opentdf-platform#59). Not suspended is a
/// 200 with `suspended: false`, never a 404.
pub async fn get_suspension(
    State(state): State<Arc<ModerationState>>,
    headers: HeaderMap,
    Path(subject): Path<String>,
) -> Response {
    match state
        .verifier
        .service_client(
            &headers,
            &state.suspension_readers,
            &state.suspension_reader_audience,
        )
        .await
    {
        Ok(_) => {}
        Err(AuthError::Unauthenticated) => {
            return err_json(StatusCode::UNAUTHORIZED, "service credential required")
        }
        Err(AuthError::Forbidden) => {
            return err_json(StatusCode::FORBIDDEN, "not a suspension reader")
        }
        Err(e) => return auth_fail(e),
    }
    let Some(key) = account_id(&subject) else {
        return err_json(StatusCode::BAD_REQUEST, "invalid subject");
    };
    match state.suspensions.get(&key).await {
        Ok(Some(s)) if s.is_active() => Json(json!({
            "subject": subject,
            "suspended": true,
            "since": rfc3339(s.since),
            "reportId": s.report_id,
        }))
        .into_response(),
        Ok(_) => Json(json!({ "subject": subject, "suspended": false })).into_response(),
        Err(e) => suspension_fail(e),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiftRequest {
    reason: String,
}

/// `DELETE /moderation/v1/suspensions/:subject` with `{"reason"}`: a moderator
/// lifts an account's suspension. The lift is recorded on the suspension, not
/// deleted. Idempotent; `lifted` says whether there was an active one.
pub async fn lift_suspension(
    State(state): State<Arc<ModerationState>>,
    headers: HeaderMap,
    Path(subject): Path<String>,
    body: Bytes,
) -> Response {
    let moderator = match state.moderator(&headers).await {
        Ok(m) => m,
        Err(e) => return auth_fail(e),
    };
    let Some(account) = account_id(&subject) else {
        return err_json(StatusCode::BAD_REQUEST, "invalid subject");
    };
    if Some(account.as_str()) == account_id(&moderator).as_deref() {
        return err_json(
            StatusCode::FORBIDDEN,
            "a moderator can't lift their own suspension",
        );
    }
    let reason = match serde_json::from_slice::<LiftRequest>(&body) {
        Ok(r) => normalised_note(&r.reason),
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "lift requires a reason"),
    };
    if reason.is_empty() || reason.chars().count() > MAX_SUSPENSION_REASON_LEN {
        return err_json(StatusCode::BAD_REQUEST, "lift requires a reason");
    }
    let lift = Lift {
        at: chrono::Utc::now().timestamp(),
        moderator: moderator.clone(),
        reason,
    };
    // The lift event always goes out first, even with nothing stored to lift, so
    // a suspension an enforcer holds without an arks record (a suspend whose
    // store write failed) can still be undone. The stored lift then applies only
    // to the suspension version read here: if another moderator changed it in
    // between, 409, and a retry announces again.
    let current = match state.suspensions.history(&account).await {
        Ok(h) => h.filter(|(h, _)| h.current.is_active()),
        Err(e) => return suspension_fail(e),
    };
    let event = json!({
        "type": "suspension.lift",
        "action": "lift",
        "creatorSubject": subject,
        "account": account,
        "reportId": current.as_ref().map(|(h, _)| h.current.report_id.clone()),
        "moderator": moderator,
        "reason": lift.reason,
        "at": rfc3339(lift.at),
    });
    if let Err(e) = state.try_publish("actions.lift", event).await {
        error!("moderation lift not delivered: {e}; suspension unchanged");
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "lift not delivered; the suspension is unchanged, try again",
        );
    }
    let Some((history, version)) = current else {
        return Json(json!({ "subject": subject, "suspended": false, "lifted": false }))
            .into_response();
    };
    // The lift itself (who, when, why) is the stored record; the log names the
    // suspension by its report.
    let report_id = history.current.report_id.clone();
    if let Err(e) = state.suspensions.lift(history, version, &lift).await {
        return suspension_fail(e);
    }
    info!("moderation suspension from report {report_id} lifted by {moderator}");
    Json(json!({ "subject": subject, "suspended": false, "lifted": true })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::authzen::cose_keys::CoseKeyCache;
    use crate::modules::authzen::cwt_verify::test_support::{keypair, mint, mint_map};
    use crate::modules::moderation::store::memory::{MemoryReportStore, MemorySuspensionStore};
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

    /// Published events, and whether the bus is down.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, Value)>>, Mutex<bool>);

    #[async_trait]
    impl Notifier for Recorder {
        async fn publish(&self, subject: String, payload: Vec<u8>) -> Result<(), String> {
            if *self.1.lock().unwrap() {
                return Err("bus down".into());
            }
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
        suspensions: Arc<MemorySuspensionStore>,
        notes: Arc<Recorder>,
        limiter: Arc<Counter>,
    }

    const READER: &str = "opentdf-platform";
    const PLATFORM_AUD: &str = "https://platform.arkavo.net";

    fn harness(hourly: u64) -> Harness {
        let (_, vk) = keypair();
        let store = Arc::new(MemoryReportStore::default());
        let notes = Arc::new(Recorder::default());
        let limiter = Arc::new(Counter::default());
        let suspensions = Arc::new(MemorySuspensionStore::with_reports(store.clone()));
        let state = Arc::new(ModerationState {
            store: store.clone(),
            suspensions: suspensions.clone(),
            suspension_readers: HashSet::from([READER.to_string()]),
            suspension_reader_audience: PLATFORM_AUD.into(),
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
            suspensions,
            notes,
            limiter,
        }
    }

    /// A `client_credentials` token for `client_id`, as identity mints it for
    /// this server.
    fn service_token(client_id: &str) -> String {
        service_token_for(client_id, &[client_id, PLATFORM_AUD])
    }

    fn service_token_for(client_id: &str, aud: &[&str]) -> String {
        let (sk, _) = keypair();
        let now = chrono::Utc::now().timestamp();
        mint_map(
            &sk,
            KID,
            vec![
                (Cbor::Integer(1.into()), Cbor::Text(ISS.into())),
                (
                    Cbor::Integer(2.into()),
                    Cbor::Text(format!("client:{client_id}")),
                ),
                (
                    Cbor::Integer(3.into()),
                    Cbor::Array(aud.iter().map(|a| Cbor::Text((*a).into())).collect()),
                ),
                (Cbor::Integer(4.into()), Cbor::Integer((now + 3_600).into())),
                (Cbor::Integer(6.into()), Cbor::Integer(now.into())),
                (Cbor::Integer(7.into()), Cbor::Bytes(vec![9u8; 16])),
                (
                    Cbor::Text("arkavo_roles".into()),
                    Cbor::Array(vec![Cbor::Text("service-account".into())]),
                ),
            ],
        )
    }

    /// Submit the standard report (creator `creator-a`) and action it.
    async fn suspend_creator(h: &Harness, report_id: &str) -> StatusCode {
        submit(h, VIEWER, report_id).await;
        call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{}", report_id.to_lowercase()),
            Some(&token(MODERATOR)),
            Some(json!({"status": "actioned", "actions": ["suspend"], "note": "harassment"})),
        )
        .await
        .0
    }

    async fn read_suspension(h: &Harness, subject: &str) -> (StatusCode, Value) {
        let (status, _, body) = call(
            &h.app,
            "GET",
            &format!("/moderation/v1/suspensions/{subject}"),
            Some(&service_token(READER)),
            None,
        )
        .await;
        (status, body)
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
            call(&h.app, "POST", uri, Some(&access), p.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        // An agent's token, marked by `arkavo_npe` with no `agent` role.
        let agent = mint_map(
            &sk,
            KID,
            vec![
                (Cbor::Integer(1.into()), Cbor::Text(ISS.into())),
                (Cbor::Integer(2.into()), Cbor::Text(VIEWER.into())),
                (Cbor::Integer(3.into()), Cbor::Text("arkavo".into())),
                (Cbor::Integer(4.into()), Cbor::Integer((now + 60).into())),
                (Cbor::Integer(6.into()), Cbor::Integer(now.into())),
                (Cbor::Integer(7.into()), Cbor::Bytes(vec![8; 16])),
                (Cbor::Text("arkavo_npe".into()), Cbor::Bool(true)),
            ],
        );
        assert_eq!(
            call(&h.app, "POST", uri, Some(&agent), p).await.0,
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

    #[tokio::test]
    async fn a_retry_at_the_limit_still_gets_its_receipt() {
        let h = harness(1);
        assert_eq!(submit(&h, VIEWER, REPORT_ID).await.0, StatusCode::CREATED);
        // The first reply was lost; the viewer, now at the limit, retries.
        let (status, _, body) = submit(&h, VIEWER, REPORT_ID).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], REPORT_ID.to_lowercase());
        // Only the first submission was counted.
        assert!(h.limiter.0.lock().unwrap().values().all(|&n| n == 1));
    }

    #[tokio::test]
    async fn a_store_outage_uses_no_quota() {
        let h = harness(1);
        *h.store.fail.lock().unwrap() = true;
        for _ in 0..3 {
            assert_eq!(
                submit(&h, VIEWER, REPORT_ID).await.0,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        *h.store.fail.lock().unwrap() = false;
        assert_eq!(submit(&h, VIEWER, REPORT_ID).await.0, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn a_forged_cursor_is_a_bad_request() {
        let h = harness(20);
        let m = token(MODERATOR);
        for c in [
            json!({"id": "", "received_at": 1}),
            json!({"id": "not-a-uuid", "received_at": 1}),
            json!({"id": REPORT_ID, "received_at": 1}), // not the stored (lowercase) form
            json!({"id": REPORT_ID.to_lowercase(), "received_at": -1}),
        ] {
            let cursor = URL_SAFE_NO_PAD.encode(c.to_string());
            let (status, _, _) = call(
                &h.app,
                "GET",
                &format!("/moderation/v1/reports?cursor={cursor}"),
                Some(&m),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{c}");
        }
    }

    #[tokio::test]
    async fn a_note_of_1000_family_emoji_fits_the_body_limit() {
        let h = harness(20);
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}";
        let mut p = payload(REPORT_ID);
        p["note"] = json!(family.repeat(1_000));
        let (status, _, _) = call(
            &h.app,
            "POST",
            "/moderation/v1/reports",
            Some(&token(VIEWER)),
            Some(p),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn an_undelivered_action_leaves_the_report_open_for_a_retry() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        let id = REPORT_ID.to_lowercase();
        let uri = format!("/moderation/v1/reports/{id}");
        let m = token(MODERATOR);
        let action = json!({"status": "actioned", "actions": ["takedown"]});

        *h.notes.1.lock().unwrap() = true;
        let (status, _, _) = call(&h.app, "PATCH", &uri, Some(&m), Some(action.clone())).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let stored = h.store.records.lock().unwrap()[&id].clone();
        assert_eq!(stored.status, Status::Received);

        *h.notes.1.lock().unwrap() = false;
        let (status, _, body) = call(&h.app, "PATCH", &uri, Some(&m), Some(action)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "actioned");
        assert!(h
            .notes
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.0 == "moderation.actions.takedown"));
    }

    #[tokio::test]
    async fn retention_starts_when_a_report_is_resolved() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        let id = REPORT_ID.to_lowercase();
        assert_eq!(h.store.records.lock().unwrap()[&id].expires_at, None);
        let uri = format!("/moderation/v1/reports/{id}");
        let m = token(MODERATOR);
        call(
            &h.app,
            "PATCH",
            &uri,
            Some(&m),
            Some(json!({"status": "reviewing"})),
        )
        .await;
        assert_eq!(h.store.records.lock().unwrap()[&id].expires_at, None);
        let (status, _, body) = call(
            &h.app,
            "PATCH",
            &uri,
            Some(&m),
            Some(json!({"status": "dismissed"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let resolved = body["resolvedAt"].as_i64().unwrap();
        assert_eq!(body["expiresAt"].as_i64(), Some(resolved + 365 * 86_400));
    }
    #[tokio::test]
    async fn a_suspend_action_records_a_suspension_the_platform_reads() {
        let h = harness(20);
        let (status, body) = read_suspension(&h, "creator-a").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"subject": "creator-a", "suspended": false}));

        assert_eq!(suspend_creator(&h, REPORT_ID).await, StatusCode::OK);
        let id = REPORT_ID.to_lowercase();
        let (status, body) = read_suspension(&h, "creator-a").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["suspended"], true);
        assert_eq!(body["reportId"], id);
        assert!(body["since"].as_str().unwrap().ends_with('Z'));
        // Both subject forms name the same account.
        let (_, prefixed) = read_suspension(&h, "arkavo:creator-a").await;
        assert_eq!(prefixed["suspended"], true);
        assert_eq!(prefixed["subject"], "arkavo:creator-a");
        let (_, other) = read_suspension(&h, "creator-b").await;
        assert_eq!(other["suspended"], false);
    }

    #[tokio::test]
    async fn an_account_keeps_its_first_suspension() {
        let h = harness(20);
        suspend_creator(&h, REPORT_ID).await;
        let second = "7A9619FF-8B86-D011-B42D-00C04FC964FF";
        assert_eq!(suspend_creator(&h, second).await, StatusCode::OK);
        let (_, body) = read_suspension(&h, "creator-a").await;
        assert_eq!(body["reportId"], REPORT_ID.to_lowercase());
    }

    #[tokio::test]
    async fn only_listed_service_clients_read_suspensions() {
        let h = harness(20);
        let uri = "/moderation/v1/suspensions/creator-a";
        let cases = [
            (None, StatusCode::UNAUTHORIZED),
            (Some(token(VIEWER)), StatusCode::UNAUTHORIZED),
            (Some(token(MODERATOR)), StatusCode::UNAUTHORIZED),
            (Some(service_token("catalog-node")), StatusCode::FORBIDDEN),
            (Some(service_token(READER)), StatusCode::OK),
        ];
        for (bearer, want) in cases {
            let (status, _, _) = call(&h.app, "GET", uri, bearer.as_deref(), None).await;
            assert_eq!(status, want, "{bearer:?}");
        }
        let (status, _) = read_suspension(&h, "creator%20a").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = read_suspension(&h, "arkavo:").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_suspension_store_outage_is_503_and_leaves_the_report_open() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        *h.suspensions.fail.lock().unwrap() = true;
        let id = REPORT_ID.to_lowercase();
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{id}"),
            Some(&token(MODERATOR)),
            Some(json!({"status": "actioned", "actions": ["suspend"], "note": "harassment"})),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let stored = h.store.records.lock().unwrap().get(&id).cloned().unwrap();
        assert_eq!(stored.status, Status::Received);
        // The action event went out first; a retry sends it again.
        assert_eq!(h.notes.0.lock().unwrap().len(), 2);
        let (status, _) = read_suspension(&h, "creator-a").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_moderator_lifts_a_suspension_with_a_reason_and_it_stays_on_record() {
        let h = harness(20);
        suspend_creator(&h, REPORT_ID).await;
        let uri = "/moderation/v1/suspensions/arkavo:creator-a";
        let reason = Some(json!({"reason": "appeal upheld"}));
        let (status, _, _) =
            call(&h.app, "DELETE", uri, Some(&token(VIEWER)), reason.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = call(
            &h.app,
            "DELETE",
            uri,
            Some(&service_token(READER)),
            reason.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        for bad in [
            None,
            Some(json!({})),
            Some(json!({"reason": "  \n "})),
            Some(json!({"reason": "x", "extra": 1})),
        ] {
            let (status, _, _) =
                call(&h.app, "DELETE", uri, Some(&token(MODERATOR)), bad.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}");
        }

        let (status, _, body) = call(
            &h.app,
            "DELETE",
            uri,
            Some(&token(MODERATOR)),
            reason.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["lifted"], true);
        assert_eq!(body["suspended"], false);
        let (_, body) = read_suspension(&h, "creator-a").await;
        assert_eq!(body, json!({"subject": "creator-a", "suspended": false}));
        // The lift is recorded on the suspension, which stays on record.
        let stored = h.suspensions.records.lock().unwrap()["creator-a"].clone();
        assert_eq!(stored.current.reason, "harassment");
        let lift = stored.current.lifted.unwrap();
        assert_eq!(
            (lift.moderator.as_str(), lift.reason.as_str()),
            (MODERATOR, "appeal upheld")
        );
        let event = h.notes.0.lock().unwrap().last().cloned().unwrap();
        assert_eq!(event.0, "moderation.actions.lift");
        assert_eq!(event.1["account"], "creator-a");
        assert_eq!(event.1["moderator"], MODERATOR);

        let (status, _, body) = call(&h.app, "DELETE", uri, Some(&token(MODERATOR)), reason).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["lifted"], false);

        // Suspended again by a later report: active, and the lifted one is history.
        let second = "7A9619FF-8B86-D011-B42D-00C04FC964FF";
        assert_eq!(suspend_creator(&h, second).await, StatusCode::OK);
        let (_, body) = read_suspension(&h, "creator-a").await;
        assert_eq!(body["suspended"], true);
        assert_eq!(body["reportId"], second.to_lowercase());
        assert_eq!(
            h.suspensions.records.lock().unwrap()["creator-a"]
                .earlier
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_suspend_note_fits_identitys_reason_limit() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        let uri = format!("/moderation/v1/reports/{}", REPORT_ID.to_lowercase());
        let patch =
            |n: usize| json!({"status": "actioned", "actions": ["suspend"], "note": "é".repeat(n)});
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &uri,
            Some(&token(MODERATOR)),
            Some(patch(1_025)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &uri,
            Some(&token(MODERATOR)),
            Some(patch(1_024)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let lift = "/moderation/v1/suspensions/creator-a";
        let (status, _, _) = call(
            &h.app,
            "DELETE",
            lift,
            Some(&token(MODERATOR)),
            Some(json!({"reason": "x".repeat(1_025)})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_suspend_needs_a_note() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{}", REPORT_ID.to_lowercase()),
            Some(&token(MODERATOR)),
            Some(json!({"status": "actioned", "actions": ["suspend"]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(h.suspensions.records.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_moderator_never_acts_on_their_own_report_or_account() {
        let h = harness(20);
        // Their own report, about anyone.
        submit(&h, MODERATOR, REPORT_ID).await;
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{}", REPORT_ID.to_lowercase()),
            Some(&token(MODERATOR)),
            Some(json!({"status": "reviewing"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // A viewer's report about the moderator.
        let other = "7A9619FF-8B86-D011-B42D-00C04FC964FF";
        let mut p = payload(other);
        p["blockedPublicID"] = json!(format!("arkavo:{MODERATOR}"));
        call(
            &h.app,
            "POST",
            "/moderation/v1/reports",
            Some(&token(VIEWER)),
            Some(p),
        )
        .await;
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{}", other.to_lowercase()),
            Some(&token(MODERATOR)),
            Some(json!({"status": "actioned", "actions": ["suspend"], "note": "self"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(h.suspensions.records.lock().unwrap().is_empty());

        let (status, _, _) = call(
            &h.app,
            "DELETE",
            &format!("/moderation/v1/suspensions/{MODERATOR}"),
            Some(&token(MODERATOR)),
            Some(json!({"reason": "mine"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn without_the_intake_the_suspension_route_is_503_not_404() {
        let (status, _, body) = call(
            &unconfigured_router(),
            "GET",
            "/moderation/v1/suspensions/creator-a",
            Some(&service_token(READER)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "moderation not configured");
    }
    #[tokio::test]
    async fn suspending_a_prefix_only_subject_is_refused() {
        let h = harness(20);
        let mut p = payload(REPORT_ID);
        p["blockedPublicID"] = json!("arkavo:");
        let (status, _, _) = call(
            &h.app,
            "POST",
            "/moderation/v1/reports",
            Some(&token(VIEWER)),
            Some(p),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = REPORT_ID.to_lowercase();
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{id}"),
            Some(&token(MODERATOR)),
            Some(json!({"status": "actioned", "actions": ["suspend"]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let stored = h.store.records.lock().unwrap().get(&id).cloned().unwrap();
        assert_eq!(stored.status, Status::Received);
        assert!(h.suspensions.records.lock().unwrap().is_empty());
        assert_eq!(h.notes.0.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn an_earlier_note_is_not_a_suspend_reason() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        let uri = format!("/moderation/v1/reports/{}", REPORT_ID.to_lowercase());
        let m = token(MODERATOR);
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &uri,
            Some(&m),
            Some(json!({"status": "reviewing", "note": "looking into it"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &uri,
            Some(&m),
            Some(json!({"status": "actioned", "actions": ["suspend"]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(h.suspensions.records.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_moderator_never_dismisses_a_report_about_themselves() {
        let h = harness(20);
        let mut p = payload(REPORT_ID);
        p["blockedPublicID"] = json!(MODERATOR.to_uppercase());
        call(
            &h.app,
            "POST",
            "/moderation/v1/reports",
            Some(&token(VIEWER)),
            Some(p),
        )
        .await;
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{}", REPORT_ID.to_lowercase()),
            Some(&token(MODERATOR)),
            Some(json!({"status": "dismissed"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_uuid_subject_is_one_account_in_any_case() {
        let h = harness(20);
        let creator = "5f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b";
        let mut p = payload(REPORT_ID);
        p["blockedPublicID"] = json!(format!("arkavo:{}", creator.to_uppercase()));
        call(
            &h.app,
            "POST",
            "/moderation/v1/reports",
            Some(&token(VIEWER)),
            Some(p),
        )
        .await;
        let (status, _, _) = call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{}", REPORT_ID.to_lowercase()),
            Some(&token(MODERATOR)),
            Some(json!({"status": "actioned", "actions": ["suspend"], "note": "harassment"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = read_suspension(&h, creator).await;
        assert_eq!(body["suspended"], true);
        assert_eq!(body["subject"], creator);
        // The action event names the same account key the lift will.
        let suspend = h.notes.0.lock().unwrap().last().cloned().unwrap();
        assert_eq!(suspend.0, "moderation.actions.suspend");
        assert_eq!(
            suspend.1["creatorSubject"],
            format!("arkavo:{}", creator.to_uppercase())
        );
        assert_eq!(suspend.1["account"], creator);
    }

    #[tokio::test]
    async fn a_reader_token_must_be_minted_for_this_server() {
        let h = harness(20);
        let (status, _, _) = call(
            &h.app,
            "GET",
            "/moderation/v1/suspensions/creator-a",
            Some(&service_token_for(
                READER,
                &[READER, "https://other.example"],
            )),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_failed_suspend_records_nothing_and_a_retry_succeeds() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        *h.notes.1.lock().unwrap() = true;
        assert_eq!(
            suspend_creator(&h, REPORT_ID).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(h.suspensions.records.lock().unwrap().is_empty());
        assert_eq!(
            h.store.records.lock().unwrap()[&REPORT_ID.to_lowercase()].status,
            Status::Received
        );
        *h.notes.1.lock().unwrap() = false;
        assert_eq!(suspend_creator(&h, REPORT_ID).await, StatusCode::OK);
        let (_, body) = read_suspension(&h, "creator-a").await;
        assert_eq!(body["suspended"], true);
    }

    #[tokio::test]
    async fn a_raced_report_records_no_suspension() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        let id = REPORT_ID.to_lowercase();
        let current = h.store.records.lock().unwrap()[&id].clone();
        // Another moderator dismissed it after this PATCH read it.
        let mut dismissed = current.clone();
        dismissed.status = Status::Dismissed;
        let mut actioned = current.clone();
        actioned.status = Status::Actioned;
        h.store
            .records
            .lock()
            .unwrap()
            .insert(id.clone(), dismissed);
        let suspension = Suspension {
            subject: "creator-a".into(),
            since: 1,
            report_id: id.clone(),
            moderator: MODERATOR.into(),
            reason: "why".into(),
            lifted: None,
        };
        assert_eq!(
            h.suspensions
                .suspend_with_report(&suspension, &actioned, Status::Received)
                .await,
            Err(StoreError::StatusChanged)
        );
        assert!(h.suspensions.records.lock().unwrap().is_empty());
        assert_eq!(
            h.store.records.lock().unwrap()[&id].status,
            Status::Dismissed
        );
    }

    #[tokio::test]
    async fn an_undelivered_lift_changes_nothing() {
        let h = harness(20);
        suspend_creator(&h, REPORT_ID).await;
        *h.notes.1.lock().unwrap() = true;
        let uri = "/moderation/v1/suspensions/creator-a";
        let reason = Some(json!({"reason": "appeal upheld"}));
        let (status, _, _) = call(
            &h.app,
            "DELETE",
            uri,
            Some(&token(MODERATOR)),
            reason.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (_, body) = read_suspension(&h, "creator-a").await;
        assert_eq!(body["suspended"], true);
        *h.notes.1.lock().unwrap() = false;
        let (status, _, body) = call(&h.app, "DELETE", uri, Some(&token(MODERATOR)), reason).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["lifted"], true);
    }

    #[tokio::test]
    async fn without_the_intake_every_suspension_method_is_503() {
        for method in ["GET", "DELETE"] {
            let (status, _, _) = call(
                &unconfigured_router(),
                method,
                "/moderation/v1/suspensions/creator-a",
                None,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{method}");
        }
    }

    #[tokio::test]
    async fn a_failed_suspend_leaves_an_earlier_suspension_alone() {
        let h = harness(20);
        suspend_creator(&h, REPORT_ID).await;
        let second = "7A9619FF-8B86-D011-B42D-00C04FC964FF";
        submit(&h, VIEWER, second).await;
        *h.notes.1.lock().unwrap() = true;
        assert_eq!(
            suspend_creator(&h, second).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let (_, body) = read_suspension(&h, "creator-a").await;
        assert_eq!(body["suspended"], true);
        assert_eq!(body["reportId"], REPORT_ID.to_lowercase());
    }
    #[tokio::test]
    async fn a_lift_with_nothing_stored_still_announces_it() {
        let h = harness(20);
        let (status, _, body) = call(
            &h.app,
            "DELETE",
            "/moderation/v1/suspensions/arkavo:creator-a",
            Some(&token(MODERATOR)),
            Some(json!({"reason": "suspend event without a record"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["lifted"], false);
        let event = h.notes.0.lock().unwrap().last().cloned().unwrap();
        assert_eq!(event.0, "moderation.actions.lift");
        assert_eq!(event.1["creatorSubject"], "arkavo:creator-a");
        assert_eq!(event.1["account"], "creator-a");
        assert_eq!(event.1["reason"], "suspend event without a record");
    }

    #[tokio::test]
    async fn a_lift_applies_only_to_the_version_it_read() {
        let h = harness(20);
        suspend_creator(&h, REPORT_ID).await;
        let (history, version) = h.suspensions.history("creator-a").await.unwrap().unwrap();
        // Another report's suspend lands in between (the account stays suspended).
        let second = "7A9619FF-8B86-D011-B42D-00C04FC964FF";
        assert_eq!(suspend_creator(&h, second).await, StatusCode::OK);
        let lift = Lift {
            at: 1,
            moderator: MODERATOR.into(),
            reason: "late".into(),
        };
        assert_eq!(
            h.suspensions.lift(history, version, &lift).await,
            Err(StoreError::StatusChanged)
        );
        let (_, body) = read_suspension(&h, "creator-a").await;
        assert_eq!(body["suspended"], true);
    }

    #[tokio::test]
    async fn the_suspend_event_carries_its_reason() {
        let h = harness(20);
        suspend_creator(&h, REPORT_ID).await;
        let event = h.notes.0.lock().unwrap().last().cloned().unwrap();
        assert_eq!(event.0, "moderation.actions.suspend");
        assert_eq!(event.1["reason"], "harassment");
    }

    #[test]
    fn only_hyphenated_uuids_fold_case() {
        let id = "5f0c1a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b";
        assert_eq!(
            account_id(&format!("arkavo:{}", id.to_uppercase())).as_deref(),
            Some(id)
        );
        for spelling in [
            format!("urn:uuid:{id}"),
            format!("{{{id}}}"),
            id.replace('-', ""),
        ] {
            assert_ne!(account_id(&spelling).as_deref(), Some(id));
        }
    }

    #[tokio::test]
    async fn a_suspend_outside_actioned_gets_the_status_error() {
        let h = harness(20);
        submit(&h, VIEWER, REPORT_ID).await;
        let (status, _, body) = call(
            &h.app,
            "PATCH",
            &format!("/moderation/v1/reports/{}", REPORT_ID.to_lowercase()),
            Some(&token(MODERATOR)),
            Some(json!({"status": "reviewing", "actions": ["suspend"]})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "actions are only allowed with actioned");
    }
}
