//! The relay's only storage: the queued Rewrap, its bearer, the route's
//! owner and the answer, in Redis until the deadline plus
//! [`RETENTION_AFTER_DEADLINE`]. Route records and APNs tokens live at
//! identity (`super::identity`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A request is deleted this long after its deadline.
pub const RETENTION_AFTER_DEADLINE: i64 = 600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Push {
    pub apns_token: String,
    pub environment: String,
}

pub struct NewRequest<'a> {
    pub route_id: &'a str,
    /// The route's owner at identity when the request arrived.
    pub owner_sub: &'a str,
    pub sub: &'a str,
    pub body_sha256_hex: &'a str,
    pub deadline: i64,
    pub received_at: i64,
    pub authorization: &'a str,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enqueued {
    Created(String),
    /// The same body from the same submitter on the same route.
    Existing(String),
    RouteFull,
    SubmitterFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRequest {
    pub request_id: String,
    pub route_id: String,
    pub owner_sub: String,
    pub sub: String,
    pub deadline: i64,
    pub received_at: i64,
    pub authorization: String,
    pub body: Vec<u8>,
    pub response: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespondError {
    NotFound,
    AlreadyAnswered,
    Expired,
    Unavailable(String),
}

pub struct Limits {
    pub per_route: u64,
    pub per_submitter: u64,
}

#[async_trait]
pub trait QueueStore: Send + Sync {
    /// `request_id` is used only when a new request is created.
    async fn enqueue(
        &self,
        req: NewRequest<'_>,
        request_id: &str,
        limits: &Limits,
        now: i64,
    ) -> Result<Enqueued, String>;
    async fn get(&self, request_id: &str) -> Result<Option<StoredRequest>, String>;
    /// Unanswered requests within their deadline, oldest first, after the
    /// request `after` (from the start when absent or gone).
    async fn pending(
        &self,
        route_id: &str,
        after: Option<&str>,
        limit: usize,
        now: i64,
    ) -> Result<Vec<StoredRequest>, String>;
    /// Store the answer once, before the deadline.
    async fn respond(&self, request_id: &str, body: &[u8], now: i64) -> Result<(), RespondError>;
    /// True at most once per `interval_secs` per route: the APNs rate limit.
    async fn push_slot(&self, route_id: &str, interval_secs: u64) -> Result<bool, String>;
    /// Delete everything queued for a route identity reports as retired.
    async fn drop_route(&self, route_id: &str) -> Result<(), String>;
}

// ==================== Redis ====================

const PREFIX: &str = "owner-kas";

fn req_key(id: &str) -> String {
    format!("{PREFIX}:req:{id}")
}

/// Atomically: return an existing request for the same (route, sub, body);
/// drop expired entries from the route's counters; refuse past either cap;
/// otherwise store the request and index it.
///
/// KEYS: dedup, route deadlines, submitter deadlines, route queue, seq
/// counter, request hash.
/// ARGV: id, now, deadline, expire_at, route cap, submitter cap, route,
/// sub, received_at, authorization, body, owner_sub.
const ENQUEUE_LUA: &str = r#"
local existing = redis.call('GET', KEYS[1])
if existing and redis.call('EXISTS', 'owner-kas:req:' .. existing) == 1 then
  return {0, existing}
end
local now = tonumber(ARGV[2])
local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now)
for _, id in ipairs(expired) do redis.call('ZREM', KEYS[4], id) end
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) then return {2, ''} end
if redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[6]) then return {3, ''} end
local id = ARGV[1]
local expire_at = tonumber(ARGV[4])
local seq = redis.call('INCR', KEYS[5])
redis.call('HSET', KEYS[6], 'route', ARGV[7], 'sub', ARGV[8], 'deadline', ARGV[3],
  'received_at', ARGV[9], 'authorization', ARGV[10], 'body', ARGV[11], 'seq', seq,
  'owner', ARGV[12])
redis.call('EXPIREAT', KEYS[6], expire_at)
redis.call('SET', KEYS[1], id, 'EXAT', expire_at)
redis.call('ZADD', KEYS[2], ARGV[3], id)
redis.call('ZADD', KEYS[3], ARGV[3], id)
redis.call('ZADD', KEYS[4], seq, id)
for i = 2, 5 do
  if redis.call('EXPIRETIME', KEYS[i]) < expire_at then redis.call('EXPIREAT', KEYS[i], expire_at) end
end
return {1, id}
"#;

/// Delete a route's requests and indexes. KEYS: queue, route deadlines,
/// seq counter. Submitter deadline sets expire on their own.
const DROP_LUA: &str = r#"
local ids = redis.call('ZRANGE', KEYS[1], 0, -1)
for _, id in ipairs(ids) do redis.call('DEL', 'owner-kas:req:' .. id) end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
return #ids
"#;

/// KEYS: request hash. ARGV: body, now, id.
const RESPOND_LUA: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('HEXISTS', KEYS[1], 'response') == 1 then return 2 end
if tonumber(redis.call('HGET', KEYS[1], 'deadline')) < tonumber(ARGV[2]) then return 3 end
redis.call('HSET', KEYS[1], 'response', ARGV[1])
local route = redis.call('HGET', KEYS[1], 'route')
local sub = redis.call('HGET', KEYS[1], 'sub')
redis.call('ZREM', 'owner-kas:q:' .. route, ARGV[3])
redis.call('ZREM', 'owner-kas:dl:' .. route, ARGV[3])
redis.call('ZREM', 'owner-kas:dl:' .. route .. ':' .. sub, ARGV[3])
return 1
"#;

pub struct RedisQueueStore {
    client: redis::Client,
    conn: tokio::sync::Mutex<Option<redis::aio::MultiplexedConnection>>,
}

impl RedisQueueStore {
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

    async fn reset(&self) {
        *self.conn.lock().await = None;
    }

    async fn load(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        id: &str,
    ) -> Result<Option<StoredRequest>, String> {
        let map: HashMap<String, Vec<u8>> = redis::cmd("HGETALL")
            .arg(req_key(id))
            .query_async(conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(stored_from_map(id, map))
    }
}

fn stored_from_map(id: &str, mut m: HashMap<String, Vec<u8>>) -> Option<StoredRequest> {
    let text = |m: &mut HashMap<String, Vec<u8>>, k: &str| {
        m.remove(k).and_then(|v| String::from_utf8(v).ok())
    };
    Some(StoredRequest {
        request_id: id.to_string(),
        route_id: text(&mut m, "route")?,
        owner_sub: text(&mut m, "owner")?,
        sub: text(&mut m, "sub")?,
        deadline: text(&mut m, "deadline")?.parse().ok()?,
        received_at: text(&mut m, "received_at")?.parse().ok()?,
        authorization: text(&mut m, "authorization")?,
        body: m.remove("body")?,
        response: m.remove("response"),
    })
}

#[async_trait]
impl QueueStore for RedisQueueStore {
    async fn enqueue(
        &self,
        req: NewRequest<'_>,
        request_id: &str,
        limits: &Limits,
        now: i64,
    ) -> Result<Enqueued, String> {
        let mut conn = self.connection().await?;
        let expire_at = req.deadline + RETENTION_AFTER_DEADLINE;
        let result: redis::RedisResult<(i64, String)> = redis::Script::new(ENQUEUE_LUA)
            .key(format!(
                "{PREFIX}:dedup:{}:{}:{}",
                req.route_id, req.sub, req.body_sha256_hex
            ))
            .key(format!("{PREFIX}:dl:{}", req.route_id))
            .key(format!("{PREFIX}:dl:{}:{}", req.route_id, req.sub))
            .key(format!("{PREFIX}:q:{}", req.route_id))
            .key(format!("{PREFIX}:seq:{}", req.route_id))
            .key(req_key(request_id))
            .arg(request_id)
            .arg(now)
            .arg(req.deadline)
            .arg(expire_at)
            .arg(limits.per_route)
            .arg(limits.per_submitter)
            .arg(req.route_id)
            .arg(req.sub)
            .arg(req.received_at)
            .arg(req.authorization)
            .arg(req.body)
            .arg(req.owner_sub)
            .invoke_async(&mut conn)
            .await;
        match result {
            Ok((0, id)) => Ok(Enqueued::Existing(id)),
            Ok((1, id)) => Ok(Enqueued::Created(id)),
            Ok((2, _)) => Ok(Enqueued::RouteFull),
            Ok((3, _)) => Ok(Enqueued::SubmitterFull),
            Ok((n, _)) => Err(format!("unexpected enqueue result {n}")),
            Err(e) => {
                self.reset().await;
                Err(e.to_string())
            }
        }
    }

    async fn get(&self, request_id: &str) -> Result<Option<StoredRequest>, String> {
        let mut conn = self.connection().await?;
        match self.load(&mut conn, request_id).await {
            Ok(r) => Ok(r),
            Err(e) => {
                self.reset().await;
                Err(e)
            }
        }
    }

    async fn pending(
        &self,
        route_id: &str,
        after: Option<&str>,
        limit: usize,
        now: i64,
    ) -> Result<Vec<StoredRequest>, String> {
        let mut conn = self.connection().await?;
        let queue = format!("{PREFIX}:q:{route_id}");
        let from = match after {
            Some(id) => {
                let score: Option<i64> = redis::cmd("ZSCORE")
                    .arg(&queue)
                    .arg(id)
                    .query_async(&mut conn)
                    .await
                    .map_err(|e| e.to_string())?;
                // An answered or expired cursor has left the queue: its
                // hash still has the seq.
                let score = match score {
                    Some(s) => Some(s),
                    None => redis::cmd("HGET")
                        .arg(req_key(id))
                        .arg("seq")
                        .query_async::<Option<i64>>(&mut conn)
                        .await
                        .map_err(|e| e.to_string())?,
                };
                score.map_or("-inf".to_string(), |s| format!("({s}"))
            }
            None => "-inf".to_string(),
        };
        let ids: Vec<String> = redis::cmd("ZRANGEBYSCORE")
            .arg(&queue)
            .arg(from)
            .arg("+inf")
            .arg("LIMIT")
            .arg(0)
            .arg(limit)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(r) = self.load(&mut conn, &id).await?
                && r.response.is_none()
                && r.deadline >= now
            {
                out.push(r);
            }
        }
        Ok(out)
    }

    async fn respond(&self, request_id: &str, body: &[u8], now: i64) -> Result<(), RespondError> {
        let mut conn = self.connection().await.map_err(RespondError::Unavailable)?;
        let result: redis::RedisResult<i64> = redis::Script::new(RESPOND_LUA)
            .key(req_key(request_id))
            .arg(body)
            .arg(now)
            .arg(request_id)
            .invoke_async(&mut conn)
            .await;
        match result {
            Ok(1) => Ok(()),
            Ok(0) => Err(RespondError::NotFound),
            Ok(2) => Err(RespondError::AlreadyAnswered),
            Ok(3) => Err(RespondError::Expired),
            Ok(n) => Err(RespondError::Unavailable(format!("unexpected {n}"))),
            Err(e) => {
                self.reset().await;
                Err(RespondError::Unavailable(e.to_string()))
            }
        }
    }

    async fn drop_route(&self, route_id: &str) -> Result<(), String> {
        let mut conn = self.connection().await?;
        redis::Script::new(DROP_LUA)
            .key(format!("{PREFIX}:q:{route_id}"))
            .key(format!("{PREFIX}:dl:{route_id}"))
            .key(format!("{PREFIX}:seq:{route_id}"))
            .invoke_async::<i64>(&mut conn)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn push_slot(&self, route_id: &str, interval_secs: u64) -> Result<bool, String> {
        let mut conn = self.connection().await?;
        let set: Option<String> = redis::cmd("SET")
            .arg(format!("{PREFIX}:push:{route_id}"))
            .arg(1)
            .arg("EX")
            .arg(interval_secs.max(1))
            .arg("NX")
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(set.is_some())
    }
}

// ==================== In memory (tests) ====================

#[cfg(test)]
pub(crate) mod memory {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct MemoryQueue {
        reqs: Mutex<Vec<(u64, StoredRequest)>>,
        dedup: Mutex<HashMap<String, String>>,
        seq: Mutex<u64>,
        pushes: Mutex<HashMap<String, u64>>,
    }

    #[async_trait]
    impl QueueStore for MemoryQueue {
        async fn enqueue(
            &self,
            req: NewRequest<'_>,
            request_id: &str,
            limits: &Limits,
            now: i64,
        ) -> Result<Enqueued, String> {
            let key = format!("{}:{}:{}", req.route_id, req.sub, req.body_sha256_hex);
            let mut reqs = self.reqs.lock().unwrap();
            reqs.retain(|(_, r)| r.deadline + RETENTION_AFTER_DEADLINE > now);
            if let Some(id) = self.dedup.lock().unwrap().get(&key) {
                if reqs.iter().any(|(_, r)| &r.request_id == id) {
                    return Ok(Enqueued::Existing(id.clone()));
                }
            }
            let live = |r: &StoredRequest| r.response.is_none() && r.deadline > now;
            let on_route: Vec<_> = reqs
                .iter()
                .filter(|(_, r)| r.route_id == req.route_id && live(r))
                .collect();
            if on_route.len() as u64 >= limits.per_route {
                return Ok(Enqueued::RouteFull);
            }
            if on_route.iter().filter(|(_, r)| r.sub == req.sub).count() as u64
                >= limits.per_submitter
            {
                return Ok(Enqueued::SubmitterFull);
            }
            let mut seq = self.seq.lock().unwrap();
            *seq += 1;
            reqs.push((
                *seq,
                StoredRequest {
                    request_id: request_id.into(),
                    route_id: req.route_id.into(),
                    owner_sub: req.owner_sub.into(),
                    sub: req.sub.into(),
                    deadline: req.deadline,
                    received_at: req.received_at,
                    authorization: req.authorization.into(),
                    body: req.body.to_vec(),
                    response: None,
                },
            ));
            self.dedup.lock().unwrap().insert(key, request_id.into());
            Ok(Enqueued::Created(request_id.into()))
        }

        async fn get(&self, request_id: &str) -> Result<Option<StoredRequest>, String> {
            Ok(self
                .reqs
                .lock()
                .unwrap()
                .iter()
                .find(|(_, r)| r.request_id == request_id)
                .map(|(_, r)| r.clone()))
        }

        async fn pending(
            &self,
            route_id: &str,
            after: Option<&str>,
            limit: usize,
            now: i64,
        ) -> Result<Vec<StoredRequest>, String> {
            let reqs = self.reqs.lock().unwrap();
            let from = after
                .and_then(|a| reqs.iter().find(|(_, r)| r.request_id == a))
                .map_or(0, |(s, _)| *s);
            Ok(reqs
                .iter()
                .filter(|(s, r)| {
                    *s > from && r.route_id == route_id && r.response.is_none() && r.deadline >= now
                })
                .take(limit)
                .map(|(_, r)| r.clone())
                .collect())
        }

        async fn respond(
            &self,
            request_id: &str,
            body: &[u8],
            now: i64,
        ) -> Result<(), RespondError> {
            let mut reqs = self.reqs.lock().unwrap();
            let Some((_, r)) = reqs.iter_mut().find(|(_, r)| r.request_id == request_id) else {
                return Err(RespondError::NotFound);
            };
            if r.response.is_some() {
                return Err(RespondError::AlreadyAnswered);
            }
            if r.deadline < now {
                return Err(RespondError::Expired);
            }
            r.response = Some(body.to_vec());
            Ok(())
        }

        async fn drop_route(&self, route_id: &str) -> Result<(), String> {
            self.reqs
                .lock()
                .unwrap()
                .retain(|(_, r)| r.route_id != route_id);
            Ok(())
        }

        async fn push_slot(&self, route_id: &str, _interval_secs: u64) -> Result<bool, String> {
            let mut p = self.pushes.lock().unwrap();
            let n = p.entry(route_id.into()).or_default();
            *n += 1;
            Ok(*n == 1)
        }
    }
}

/// Against a real Redis: `OWNER_KAS_TEST_REDIS=redis://127.0.0.1:6379/15
/// cargo test --bin arks owner_kas::store`. Skipped when unset.
#[cfg(test)]
mod redis_tests {
    use super::*;

    fn store() -> Option<RedisQueueStore> {
        let url = std::env::var("OWNER_KAS_TEST_REDIS").ok()?;
        Some(RedisQueueStore::new(redis::Client::open(url).unwrap()))
    }

    fn route() -> String {
        crate::modules::owner_kas::token::new_ulid(chrono::Utc::now().timestamp_millis() as u64)
    }

    fn id() -> String {
        route()
    }

    fn req<'a>(route: &'a str, sub: &'a str, hash: &'a str, deadline: i64) -> NewRequest<'a> {
        NewRequest {
            route_id: route,
            owner_sub: "owner",
            sub,
            body_sha256_hex: hash,
            deadline,
            received_at: deadline - 900,
            authorization: "Bearer t",
            body: b"\x00{\"signed_request_token\":\"x\"}\xff",
        }
    }

    #[tokio::test]
    async fn queue_round_trip() {
        let Some(s) = store() else { return };
        let now = chrono::Utc::now().timestamp();
        let limits = Limits {
            per_route: 3,
            per_submitter: 2,
        };
        let r = route();
        let a = id();
        assert_eq!(
            s.enqueue(req(&r, "u1", "h1", now + 900), &a, &limits, now)
                .await
                .unwrap(),
            Enqueued::Created(a.clone())
        );
        assert_eq!(
            s.enqueue(req(&r, "u1", "h1", now + 900), &id(), &limits, now)
                .await
                .unwrap(),
            Enqueued::Existing(a.clone())
        );
        let b = id();
        s.enqueue(req(&r, "u1", "h2", now + 900), &b, &limits, now)
            .await
            .unwrap();
        assert_eq!(
            s.enqueue(req(&r, "u1", "h3", now + 900), &id(), &limits, now)
                .await
                .unwrap(),
            Enqueued::SubmitterFull
        );
        let c = id();
        s.enqueue(req(&r, "u2", "h4", now + 900), &c, &limits, now)
            .await
            .unwrap();
        assert_eq!(
            s.enqueue(req(&r, "u3", "h5", now + 900), &id(), &limits, now)
                .await
                .unwrap(),
            Enqueued::RouteFull
        );

        let got = s.get(&a).await.unwrap().unwrap();
        assert_eq!(got.body, req(&r, "", "", 0).body, "binary-safe");
        assert_eq!(
            (got.route_id.as_str(), got.sub.as_str()),
            (r.as_str(), "u1")
        );

        let all: Vec<_> = s
            .pending(&r, None, 64, now)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.request_id)
            .collect();
        assert_eq!(all, vec![a.clone(), b.clone(), c.clone()]);
        let after_a: Vec<_> = s
            .pending(&r, Some(&a), 64, now)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.request_id)
            .collect();
        assert_eq!(after_a, vec![b.clone(), c.clone()]);

        s.respond(&a, b"answer", now).await.unwrap();
        assert_eq!(
            s.respond(&a, b"again", now).await,
            Err(RespondError::AlreadyAnswered)
        );
        assert_eq!(
            s.get(&a).await.unwrap().unwrap().response.as_deref(),
            Some(&b"answer"[..])
        );
        // Answered: off the list, and its slot is free; the cursor still works.
        let after_a: Vec<_> = s
            .pending(&r, Some(&a), 64, now)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.request_id)
            .collect();
        assert_eq!(after_a, vec![b.clone(), c.clone()]);
        assert!(matches!(
            s.enqueue(req(&r, "u3", "h5", now + 900), &id(), &limits, now)
                .await
                .unwrap(),
            Enqueued::Created(_)
        ));

        assert_eq!(
            s.respond(&id(), b"x", now).await,
            Err(RespondError::NotFound)
        );
        assert_eq!(
            s.respond(&b, b"late", now + 901).await,
            Err(RespondError::Expired)
        );

        assert!(s.push_slot(&r, 30).await.unwrap());
        assert!(!s.push_slot(&r, 30).await.unwrap());

        s.drop_route(&r).await.unwrap();
        assert!(s.get(&b).await.unwrap().is_none());
        assert!(s.pending(&r, None, 64, now).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn expired_requests_free_their_slots() {
        let Some(s) = store() else { return };
        let now = chrono::Utc::now().timestamp();
        let limits = Limits {
            per_route: 1,
            per_submitter: 1,
        };
        let r = route();
        s.enqueue(req(&r, "u1", "h1", now - 1), &id(), &limits, now - 100)
            .await
            .unwrap();
        assert!(s.pending(&r, None, 64, now).await.unwrap().is_empty());
        assert!(matches!(
            s.enqueue(req(&r, "u1", "h2", now + 900), &id(), &limits, now)
                .await
                .unwrap(),
            Enqueued::Created(_)
        ));
    }
}
