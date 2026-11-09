use super::*;
use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_verify::test_support::mint_map;
use crate::modules::owner_kas::identity::memory::MemoryDirectory;
use crate::modules::owner_kas::identity::RouteInfo;
use crate::modules::owner_kas::store::memory::MemoryQueue;
use crate::modules::owner_kas::token::test_support::{
    identity_key, request_key, Mint, ISS, KID, ROUTE, SUB,
};
use crate::modules::owner_kas::token::LIFETIME_SECONDS as LIFETIME;
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request};
use ciborium::value::Value;
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const OWNER: &str = "0a1b2c3d-0000-4000-8000-0000000000aa";
const PLATFORM: &str = "https://platform.arkavo.net";
const APNS_TOKEN: &str = "a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1";

#[derive(Default)]
struct RecordingPusher {
    sent: Mutex<Vec<(String, String, String, i64)>>,
    outcome: Mutex<Option<PushOutcome>>,
}

#[async_trait]
impl Pusher for RecordingPusher {
    async fn alert(&self, token: &str, env: &str, collapse: &str, exp: i64) -> PushOutcome {
        self.sent
            .lock()
            .unwrap()
            .push((token.into(), env.into(), collapse.into(), exp));
        self.outcome
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(PushOutcome::Sent)
    }
}

struct Harness {
    app: Router,
    directory: Arc<MemoryDirectory>,
    pusher: Arc<RecordingPusher>,
}

fn keys() -> CoseKeyCache {
    CoseKeyCache::with_static_keys(vec![(KID.to_vec(), *identity_key().verifying_key())])
}

fn owner_route(push: Option<Push>) -> RouteInfo {
    RouteInfo {
        owner_sub: OWNER.into(),
        push,
    }
}

fn harness_with(push: Option<Push>) -> Harness {
    let directory = Arc::new(MemoryDirectory::with(ROUTE, owner_route(push)));
    let pusher = Arc::new(RecordingPusher::default());
    let state = Arc::new(OwnerKasState {
        receivers: OwnerKasVerifier {
            issuer: ISS.into(),
            keys: keys(),
        },
        owners: PersonTokenVerifier::new(keys(), ISS.into(), PLATFORM.into()),
        directory: directory.clone(),
        queue: Arc::new(MemoryQueue::default()),
        pusher: Some(pusher.clone()),
    });
    Harness {
        app: router(state),
        directory,
        pusher,
    }
}

fn harness() -> Harness {
    harness_with(None)
}

/// A passkey session CWT as identity mints it.
fn session(sub: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let int = |n: i64| Value::Integer(n.into());
    mint_map(
        &identity_key(),
        KID,
        vec![
            (int(1), Value::Text(ISS.into())),
            (int(2), Value::Text(sub.into())),
            (
                int(3),
                Value::Array(vec![
                    Value::Text("arkavo".into()),
                    Value::Text(PLATFORM.into()),
                ]),
            ),
            (int(4), int(now + 3600)),
            (int(6), int(now)),
            (int(7), Value::Bytes(vec![1; 16])),
        ],
    )
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Res {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

async fn call(app: &Router, method: Method, uri: &str, token: Option<&str>, body: Vec<u8>) -> Res {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    Res {
        status,
        headers,
        body,
    }
}

fn rewrap_uri(route: &str) -> String {
    format!("/owner-kas/v1/routes/{route}/kas.AccessService/Rewrap")
}

fn list_uri() -> String {
    format!("/owner-kas/v1/routes/{ROUTE}/requests")
}

async fn submit(h: &Harness, m: &Mint<'_>, extra: &str) -> Res {
    call(
        &h.app,
        Method::POST,
        &rewrap_uri(ROUTE),
        Some(&m.token()),
        m.rewrap_body(m.exp, extra),
    )
    .await
}

fn id_of(res: &Res) -> String {
    res.json()["request_id"].as_str().unwrap().to_string()
}

fn listed_count(res: &Res) -> usize {
    res.json()["requests"].as_array().unwrap().len()
}

#[tokio::test]
async fn the_whole_exchange() {
    let h = harness();
    let m = Mint::new(ROUTE, now());
    let res = submit(&h, &m, "a").await;
    assert_eq!(res.status, StatusCode::ACCEPTED);
    assert_eq!(res.headers["retry-after"], "5");
    assert_eq!(res.headers["cache-control"], "no-store");
    let j = res.json();
    let id = id_of(&res);
    assert_eq!(j["status"], "pending");
    assert_eq!(j["deadline"], m.exp);
    assert_eq!(
        res.headers["location"],
        format!("/owner-kas/v1/requests/{id}").as_str()
    );

    // The same body again: the same request.
    assert_eq!(id_of(&submit(&h, &m, "a").await), id);

    // The receiver polls: pending.
    let poll_uri = format!("/owner-kas/v1/requests/{id}");
    let p = call(&h.app, Method::GET, &poll_uri, Some(&m.token()), vec![]).await;
    assert_eq!(p.status, StatusCode::ACCEPTED);

    // The owner lists it, exactly as received.
    let list = call(
        &h.app,
        Method::GET,
        &list_uri(),
        Some(&session(OWNER)),
        vec![],
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    let items = list.json()["requests"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["request_id"], id.as_str());
    assert_eq!(
        items[0]["authorization"],
        format!("Bearer {}", m.token()).as_str()
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(items[0]["body"].as_str().unwrap())
            .unwrap(),
        m.rewrap_body(m.exp, "a")
    );
    assert_eq!(list.json()["cursor"], id.as_str());

    // Nothing after the cursor.
    let later = call(
        &h.app,
        Method::GET,
        &format!("{}?after={id}", list_uri()),
        Some(&session(OWNER)),
        vec![],
    )
    .await;
    assert_eq!(listed_count(&later), 0);

    // The owner answers, once.
    let answer = br#"{"responses":[]}"#.to_vec();
    let resp_uri = format!("/owner-kas/v1/requests/{id}/response");
    let put = call(
        &h.app,
        Method::PUT,
        &resp_uri,
        Some(&session(OWNER)),
        answer.clone(),
    )
    .await;
    assert_eq!(put.status, StatusCode::NO_CONTENT);
    let twice = call(
        &h.app,
        Method::PUT,
        &resp_uri,
        Some(&session(OWNER)),
        answer.clone(),
    )
    .await;
    assert_eq!(twice.status, StatusCode::CONFLICT);

    // The receiver collects it.
    let done = call(&h.app, Method::GET, &poll_uri, Some(&m.token()), vec![]).await;
    assert_eq!(done.status, StatusCode::OK);
    assert_eq!(done.body, answer);

    // Answered requests leave the owner's list.
    let list = call(
        &h.app,
        Method::GET,
        &list_uri(),
        Some(&session(OWNER)),
        vec![],
    )
    .await;
    assert_eq!(listed_count(&list), 0);
}

#[tokio::test]
async fn a_rewrap_needs_a_matching_token_and_its_key() {
    let h = harness();
    let m = Mint::new(ROUTE, now());

    // A token for another route.
    let other = Mint::new("01JC0000000000000000000000", now());
    let res = call(
        &h.app,
        Method::POST,
        &rewrap_uri(ROUTE),
        Some(&other.token()),
        other.rewrap_body(other.exp, "a"),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);

    // A signed request from another key.
    let mut thief = Mint::new(ROUTE, now());
    thief.request_key = request_key(8);
    let res = call(
        &h.app,
        Method::POST,
        &rewrap_uri(ROUTE),
        Some(&m.token()),
        thief.rewrap_body(m.exp, "a"),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);

    // A passkey session is not an owner-KAS token.
    let res = call(
        &h.app,
        Method::POST,
        &rewrap_uri(ROUTE),
        Some(&session(SUB)),
        m.rewrap_body(m.exp, "a"),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);

    // A route id that isn't canonical.
    let res = call(
        &h.app,
        Method::POST,
        &rewrap_uri(&ROUTE.to_lowercase()),
        Some(&m.token()),
        m.rewrap_body(m.exp, "a"),
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    // Too large.
    let res = call(
        &h.app,
        Method::POST,
        &rewrap_uri(ROUTE),
        Some(&m.token()),
        vec![b' '; MAX_REWRAP_BYTES + 1],
    )
    .await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn identity_decides_whether_the_route_exists() {
    let h = harness();
    let m = Mint::new(ROUTE, now());
    // Unknown or retired at identity: 404.
    h.directory.routes.lock().unwrap().as_mut().unwrap().clear();
    assert_eq!(submit(&h, &m, "a").await.status, StatusCode::NOT_FOUND);
    // Retired at identity: 404, and what was queued for it is dropped.
    *h.directory.routes.lock().unwrap() = Some([(ROUTE.to_string(), owner_route(None))].into());
    let id = id_of(&submit(&h, &m, "queued").await);
    h.directory.retired.lock().unwrap().push(ROUTE.into());
    assert_eq!(submit(&h, &m, "b").await.status, StatusCode::NOT_FOUND);
    let poll = call(
        &h.app,
        Method::GET,
        &format!("/owner-kas/v1/requests/{id}"),
        Some(&m.token()),
        vec![],
    )
    .await;
    assert_eq!(poll.status, StatusCode::NOT_FOUND);
    h.directory.retired.lock().unwrap().clear();
    // Identity unreachable: 503 with Retry-After, and nothing queued.
    *h.directory.routes.lock().unwrap() = None;
    let res = submit(&h, &m, "a").await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(res.headers["retry-after"], "5");
    *h.directory.routes.lock().unwrap() = Some([(ROUTE.to_string(), owner_route(None))].into());
    let list = call(
        &h.app,
        Method::GET,
        &list_uri(),
        Some(&session(OWNER)),
        vec![],
    )
    .await;
    assert_eq!(listed_count(&list), 0);
}

#[tokio::test]
async fn polls_reveal_nothing_to_others() {
    let h = harness();
    let m = Mint::new(ROUTE, now());
    let id = id_of(&submit(&h, &m, "a").await);
    let uri = format!("/owner-kas/v1/requests/{id}");
    let mut other = Mint::new(ROUTE, now());
    other.sub = "0a1b2c3d-0000-4000-8000-000000000009";
    let res = call(&h.app, Method::GET, &uri, Some(&other.token()), vec![]).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let res = call(&h.app, Method::GET, &uri, None, vec![]).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_late_poll_is_gone_not_unauthorized() {
    let h = harness();
    // A token with 1 s left queues; then its deadline passes.
    let mut m = Mint::new(ROUTE, now() - LIFETIME + 1);
    m.exp = now() + 1;
    let res = submit(&h, &m, "a").await;
    assert_eq!(res.status, StatusCode::ACCEPTED);
    let id = id_of(&res);
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let uri = format!("/owner-kas/v1/requests/{id}");
    let res = call(&h.app, Method::GET, &uri, Some(&m.token()), vec![]).await;
    assert_eq!(res.status, StatusCode::GONE);
    assert_eq!(res.json()["status"], "expired");
    // Past the skew, the same route and submitter still read the 410 within
    // the grace...
    let mut late = Mint::new(ROUTE, now() - LIFETIME - 300);
    late.exp = now() - 300;
    let res = call(&h.app, Method::GET, &uri, Some(&late.token()), vec![]).await;
    assert_eq!(res.status, StatusCode::GONE);
    // The owner's late answer is refused as expired.
    let res = call(
        &h.app,
        Method::PUT,
        &format!("/owner-kas/v1/requests/{id}/response"),
        Some(&session(OWNER)),
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(res.status, StatusCode::GONE);
}

#[tokio::test]
async fn a_token_past_its_exp_queues_nothing() {
    // Inside the 60 s skew the bearer still verifies, but its exp is the
    // deadline: nothing is queued and no alert is spent (Gitar, PR #164).
    let h = harness_with(Some(Push {
        apns_token: APNS_TOKEN.into(),
        environment: "production".into(),
    }));
    let mut m = Mint::new(ROUTE, now() - LIFETIME - 30);
    m.exp = now() - 30;
    let res = submit(&h, &m, "a").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let list = call(
        &h.app,
        Method::GET,
        &list_uri(),
        Some(&session(OWNER)),
        vec![],
    )
    .await;
    assert_eq!(listed_count(&list), 0);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(h.pusher.sent.lock().unwrap().is_empty());
    // Way past the skew: refused as before.
    let mut late = Mint::new(ROUTE, now() - LIFETIME - 300);
    late.exp = now() - 300;
    assert_eq!(
        submit(&h, &late, "b").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn limits_per_submitter() {
    let h = harness();
    let m = Mint::new(ROUTE, now());
    for i in 0..MAX_PENDING_PER_SUBMITTER {
        assert_eq!(
            submit(&h, &m, &i.to_string()).await.status,
            StatusCode::ACCEPTED
        );
    }
    let res = submit(&h, &m, "one more").await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.headers["retry-after"], "5");
}

#[tokio::test]
async fn only_the_owner_sees_and_answers() {
    let h = harness();
    let m = Mint::new(ROUTE, now());
    let id = id_of(&submit(&h, &m, "a").await);

    // Someone else's session: an empty list, and their answer is 404.
    let list = call(
        &h.app,
        Method::GET,
        &list_uri(),
        Some(&session(SUB)),
        vec![],
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(listed_count(&list), 0);
    let res = call(
        &h.app,
        Method::PUT,
        &format!("/owner-kas/v1/requests/{id}/response"),
        Some(&session(SUB)),
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);

    // An owner-KAS token is not a session.
    let res = call(&h.app, Method::GET, &list_uri(), Some(&m.token()), vec![]).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    // A prefixed subject is not the bare form.
    let res = call(
        &h.app,
        Method::GET,
        &list_uri(),
        Some(&session(&format!("arkavo:{OWNER}"))),
        vec![],
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_route_and_push_routes_are_gone() {
    let h = harness();
    for (method, uri) in [
        (Method::GET, format!("/owner-kas/v1/routes/{ROUTE}")),
        (Method::PUT, format!("/owner-kas/v1/routes/{ROUTE}")),
        (Method::PUT, format!("/owner-kas/v1/routes/{ROUTE}/push")),
    ] {
        let res = call(&h.app, method, &uri, Some(&session(OWNER)), vec![]).await;
        assert!(
            res.status == StatusCode::NOT_FOUND || res.status == StatusCode::METHOD_NOT_ALLOWED,
            "{uri}: {}",
            res.status
        );
    }
}

#[tokio::test]
async fn the_apns_hint_is_generic_rate_limited_and_cleans_up() {
    let h = harness_with(Some(Push {
        apns_token: APNS_TOKEN.into(),
        environment: "production".into(),
    }));
    *h.pusher.outcome.lock().unwrap() = Some(PushOutcome::Unregistered);
    let m = Mint::new(ROUTE, now());
    submit(&h, &m, "a").await;
    submit(&h, &m, "b").await;
    // The alert is spawned.
    for _ in 0..50 {
        if !h.directory.deleted.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    let sent = h.pusher.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "one alert per route per window");
    assert_eq!(
        sent[0],
        (APNS_TOKEN.into(), "production".into(), ROUTE.into(), m.exp)
    );
    // Unregistered: identity is asked to delete it.
    assert_eq!(
        *h.directory.deleted.lock().unwrap(),
        vec![(ROUTE.to_string(), APNS_TOKEN.to_string())]
    );
}

#[tokio::test]
async fn an_owner_kas_token_is_refused_elsewhere() {
    // The media and session verifiers require the `arkavo` + platform
    // audiences; the owner-KAS token's single `owner-kas:` audience fails.
    let v = PersonTokenVerifier::new(keys(), ISS.into(), PLATFORM.into());
    let token = Mint::new(ROUTE, now()).token();
    assert!(v.verify_token(&token, now()).await.is_err());
    let moderation = crate::modules::moderation::auth::SessionVerifier {
        issuer: ISS.into(),
        audience: "arkavo".into(),
        keys: keys(),
    };
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    assert!(moderation.person(&headers).await.is_err());
}

#[tokio::test]
async fn off_is_503() {
    let res = call(
        &unconfigured_router(),
        Method::POST,
        &rewrap_uri(ROUTE),
        None,
        vec![],
    )
    .await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
}
