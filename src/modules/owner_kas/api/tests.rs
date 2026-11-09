use super::*;
use crate::modules::authzen::cose_keys::CoseKeyCache;
use crate::modules::authzen::cwt_verify::test_support::mint_map;
use crate::modules::owner_kas::record::test_support::{bundle, CREDENTIAL_ID, RP};
use crate::modules::owner_kas::store::memory::{MemoryQueue, MemoryRoutes};
use crate::modules::owner_kas::token::test_support::{
    identity_key, request_key, Mint, ISS, KID, ROUTE, SUB,
};
use axum::body::Body;
use axum::http::{Method, Request};
use ciborium::value::Value;
use std::sync::Mutex;
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

struct StubStatus(Mutex<Result<(), StatusRefusal>>);

#[async_trait]
impl CredentialStatus for StubStatus {
    async fn check(&self, id: &[u8], _sub: &str) -> Result<(), StatusRefusal> {
        assert_eq!(id, CREDENTIAL_ID);
        self.0.lock().unwrap().clone()
    }
}

struct Harness {
    app: Router,
    routes: Arc<MemoryRoutes>,
    pusher: Arc<RecordingPusher>,
    status: Arc<StubStatus>,
}

fn keys() -> CoseKeyCache {
    CoseKeyCache::with_static_keys(vec![(KID.to_vec(), *identity_key().verifying_key())])
}

fn harness() -> Harness {
    let routes = Arc::new(MemoryRoutes::default());
    let pusher = Arc::new(RecordingPusher::default());
    let status = Arc::new(StubStatus(Mutex::new(Ok(()))));
    let state = Arc::new(OwnerKasState {
        receivers: OwnerKasVerifier {
            issuer: ISS.into(),
            keys: keys(),
        },
        owners: PersonTokenVerifier::new(keys(), ISS.into(), PLATFORM.into()),
        routes: routes.clone(),
        queue: Arc::new(MemoryQueue::default()),
        pusher: Some(pusher.clone()),
        status: status.clone(),
        passkeys: Passkeys::for_rp(RP),
    });
    Harness {
        app: router(state),
        routes,
        pusher,
        status,
    }
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

async fn put_record(h: &Harness, seq: u64) -> Res {
    let body = serde_json::to_vec(&bundle(ROUTE, OWNER, seq)).unwrap();
    call(
        &h.app,
        Method::PUT,
        &format!("/owner-kas/v1/routes/{ROUTE}"),
        Some(&session(OWNER)),
        body,
    )
    .await
}

async fn submit(h: &Harness, m: &Mint<'_>, extra: &str) -> Res {
    let token = m.token();
    call(
        &h.app,
        Method::POST,
        &rewrap_uri(ROUTE),
        Some(&token),
        m.rewrap_body(m.exp, extra),
    )
    .await
}

#[tokio::test]
async fn the_whole_exchange() {
    let h = harness();
    assert_eq!(put_record(&h, 1).await.status, StatusCode::OK);

    let m = Mint::new(ROUTE, now());
    let res = submit(&h, &m, "a").await;
    assert_eq!(res.status, StatusCode::ACCEPTED);
    assert_eq!(res.headers["retry-after"], "5");
    assert_eq!(res.headers["cache-control"], "no-store");
    let j = res.json();
    let id = j["request_id"].as_str().unwrap().to_string();
    assert_eq!(j["status"], "pending");
    assert_eq!(j["deadline"], m.exp);
    assert_eq!(
        res.headers["location"],
        format!("/owner-kas/v1/requests/{id}").as_str()
    );

    // The same body again: the same request.
    let again = submit(&h, &m, "a").await;
    assert_eq!(again.json()["request_id"], id.as_str());

    // The receiver polls: pending.
    let poll_uri = format!("/owner-kas/v1/requests/{id}");
    let p = call(&h.app, Method::GET, &poll_uri, Some(&m.token()), vec![]).await;
    assert_eq!(p.status, StatusCode::ACCEPTED);

    // The owner lists it, exactly as received.
    let list = call(
        &h.app,
        Method::GET,
        &format!("/owner-kas/v1/routes/{ROUTE}/requests"),
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
        &format!("/owner-kas/v1/routes/{ROUTE}/requests?after={id}"),
        Some(&session(OWNER)),
        vec![],
    )
    .await;
    assert_eq!(later.json()["requests"].as_array().unwrap().len(), 0);

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
        &format!("/owner-kas/v1/routes/{ROUTE}/requests"),
        Some(&session(OWNER)),
        vec![],
    )
    .await;
    assert_eq!(list.json()["requests"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn a_rewrap_needs_a_record_a_matching_token_and_its_key() {
    let h = harness();
    let m = Mint::new(ROUTE, now());
    // No record yet.
    assert_eq!(submit(&h, &m, "a").await.status, StatusCode::NOT_FOUND);
    put_record(&h, 1).await;

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
async fn polls_reveal_nothing_to_others() {
    let h = harness();
    put_record(&h, 1).await;
    let m = Mint::new(ROUTE, now());
    let id = submit(&h, &m, "a").await.json()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
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
    put_record(&h, 1).await;
    // A token 30 s past its exp is still inside the skew: it queues a request
    // whose deadline has passed.
    let mut m = Mint::new(ROUTE, now() - LIFETIME - 30);
    m.exp = now() - 30;
    let id = submit(&h, &m, "a").await.json()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let uri = format!("/owner-kas/v1/requests/{id}");
    let res = call(&h.app, Method::GET, &uri, Some(&m.token()), vec![]).await;
    assert_eq!(res.status, StatusCode::GONE);
    assert_eq!(res.json()["status"], "expired");
    // Past the skew, the same bearer still reads the 410 within the grace...
    let mut late = Mint::new(ROUTE, now() - LIFETIME - 300);
    late.exp = now() - 300;
    let res = call(&h.app, Method::GET, &uri, Some(&late.token()), vec![]).await;
    assert_eq!(res.status, StatusCode::GONE);
    // ...but cannot queue anything.
    let res = submit(&h, &late, "b").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

const LIFETIME: i64 = crate::modules::owner_kas::token::LIFETIME_SECONDS;

#[tokio::test]
async fn limits_per_submitter_and_route() {
    let h = harness();
    put_record(&h, 1).await;
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
async fn route_records_are_owned_and_monotonic() {
    let h = harness();
    assert_eq!(put_record(&h, 2).await.status, StatusCode::OK);
    assert_eq!(put_record(&h, 2).await.status, StatusCode::CONFLICT);
    assert_eq!(put_record(&h, 1).await.status, StatusCode::CONFLICT);
    assert_eq!(put_record(&h, 3).await.status, StatusCode::OK);

    // Someone else's session.
    let body = serde_json::to_vec(&bundle(ROUTE, OWNER, 4)).unwrap();
    let res = call(
        &h.app,
        Method::PUT,
        &format!("/owner-kas/v1/routes/{ROUTE}"),
        Some(&session(SUB)),
        body,
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);

    // A revoked passkey.
    *h.status.0.lock().unwrap() = Err(StatusRefusal::Refused("passkey credential revoked"));
    assert_eq!(put_record(&h, 5).await.status, StatusCode::FORBIDDEN);
    *h.status.0.lock().unwrap() = Err(StatusRefusal::Unavailable);
    assert_eq!(
        put_record(&h, 5).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );

    // A prefixed subject is not the bare form.
    let res = call(
        &h.app,
        Method::PUT,
        &format!("/owner-kas/v1/routes/{ROUTE}"),
        Some(&session(&format!("arkavo:{OWNER}"))),
        serde_json::to_vec(&bundle(ROUTE, OWNER, 6)).unwrap(),
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    // The receiver reads the record as stored.
    let m = Mint::new(ROUTE, now());
    let res = call(
        &h.app,
        Method::GET,
        &format!("/owner-kas/v1/routes/{ROUTE}"),
        Some(&m.token()),
        vec![],
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Bundle>(&res.body).unwrap(),
        bundle(ROUTE, OWNER, 3)
    );
    // ...but not with a session token.
    let res = call(
        &h.app,
        Method::GET,
        &format!("/owner-kas/v1/routes/{ROUTE}"),
        Some(&session(OWNER)),
        vec![],
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn owners_only_on_owner_routes() {
    let h = harness();
    put_record(&h, 1).await;
    for (method, uri) in [
        (
            Method::GET,
            format!("/owner-kas/v1/routes/{ROUTE}/requests"),
        ),
        (Method::DELETE, format!("/owner-kas/v1/routes/{ROUTE}/push")),
    ] {
        let res = call(&h.app, method.clone(), &uri, Some(&session(SUB)), vec![]).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{uri}");
        // An owner-KAS token is not a session.
        let m = Mint::new(ROUTE, now());
        let res = call(&h.app, method, &uri, Some(&m.token()), vec![]).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn the_apns_hint_is_generic_rate_limited_and_cleans_up() {
    let h = harness();
    put_record(&h, 1).await;
    let push_uri = format!("/owner-kas/v1/routes/{ROUTE}/push");
    for bad in [
        json!({ "apns_token": "zz", "environment": "production" }),
        json!({ "apns_token": APNS_TOKEN, "environment": "staging" }),
        json!({ "apns_token": APNS_TOKEN, "environment": "development" }),
    ] {
        let res = call(
            &h.app,
            Method::PUT,
            &push_uri,
            Some(&session(OWNER)),
            serde_json::to_vec(&bad).unwrap(),
        )
        .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
    }
    let res = call(
        &h.app,
        Method::PUT,
        &push_uri,
        Some(&session(OWNER)),
        serde_json::to_vec(&json!({ "apns_token": APNS_TOKEN, "environment": "production" }))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);

    *h.pusher.outcome.lock().unwrap() = Some(PushOutcome::Unregistered);
    let m = Mint::new(ROUTE, now());
    submit(&h, &m, "a").await;
    submit(&h, &m, "b").await;
    // The alert is spawned.
    for _ in 0..50 {
        if !h.pusher.sent.lock().unwrap().is_empty() {
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
    // Unregistered: the token is gone.
    assert_eq!(h.routes.0.lock().unwrap()[ROUTE].push, None);
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
