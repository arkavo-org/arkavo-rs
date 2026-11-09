# Owner KAS address (`/owner-kas/v1/`)

arkavo-rs#163. The design and contract are arkavo-ios's owner-KAS design,
§4.2 and §4.3 (arkavo-ios ADR-0070, design at 43bbd68), with the APNs hint in
ADR-0074. The owner-KAS token is authnz-rs `docs/owner-kas-token.md`
(authnz-rs#146). Route records and APNs tokens live at identity (authnz-rs
0.31.0).

An owner's iPhone holds a KAS private key and decides every release. It can't
be reached directly, so its KAS URL is an address here:
`https://platform.arkavo.net/owner-kas/v1/routes/<route_id>`. OpenTDFKit posts
a standard Rewrap to that URL plus `/kas.AccessService/Rewrap`. arks queues
the request until the owner's phone fetches it, holds the phone's answer until
the receiver collects it, and sends the owner a generic APNs alert.

**arks decides no access, holds no key it could use, and stores nothing
durable.** It doesn't verify the policy, the KAO or the owner's signed
decision: the devices do. A 202 is never an ALLOW, and an expired request is
"unavailable", never a denial.

Unrelated to the "local KAS" of PR #74 (the platform key served by this
process).

## Who holds what

| Data | Where | Why |
| --- | --- | --- |
| Route record (passkey-signed), owner, APNs token | identity | Identity owns account deletion and retires routes (never reuses a `route_id`). The owner registers both there; receivers read the record there. |
| Queued Rewrap, its bearer, the route's owner, the answer | arks, Redis | Short-lived: deleted at the deadline + 10 minutes. |

## Routes

| Route | Credential | Answers |
| --- | --- | --- |
| `POST /routes/{route_id}/kas.AccessService/Rewrap` | owner-KAS token for the route; body's `signed_request_token` signed by its `cnf` key | `202 {request_id, status:"pending", deadline}`, `Location`, `Retry-After: 5`. 400 bad route id; 401 token or signed request; 404 route unknown or retired at identity; 503 + `Retry-After` identity unreachable with nothing cached (nothing queued); 413 > 64 KiB; 429 + `Retry-After` past 64 pending per route or 8 per submitter |
| `GET /requests/{request_id}` | owner-KAS token whose `aud` names the request's route and whose `sub` submitted it | 202 pending, 200 the stored Rewrap response, 410 `{status:"expired"}`. Any other token: 404 |
| `GET /routes/{route_id}/requests?after={request_id}` | owner's passkey session | `{requests:[{request_id, authorization, body, received_at}], cursor}`: the requests whose recorded owner is the session's `sub`; anyone else gets an empty list |
| `PUT /requests/{request_id}/response` | owner's session | 204; 409 already answered, 410 past the deadline, 404 unknown or not the owner's, 413 > 16 KiB |

The route record and the push token are registered and read at identity, not
here. Every response is `Cache-Control: no-store`. With `OWNER_KAS` off,
every `/owner-kas/` path answers 503.

- `route_id` and `request_id` are canonical ULIDs: 26 uppercase Crockford
  base-32 characters, the first `0`–`7`, never normalized.
- Subjects are bare lowercase UUIDs, compared byte for byte. An owner's
  session `sub` in any other form (`arkavo:…`) gets 403.
- `deadline` is the owner-KAS token's `exp` (unix seconds).
- `authorization` is the receiver's `Authorization` header value as received
  (`Bearer <token>`); `body` is unpadded base64url of the Rewrap body bytes.
- The same body from the same submitter on the same route gets the same
  `request_id` (keyed on route, `sub` and the body's SHA-256), without a
  second alert.

### Credentials

**Receiver routes** take only the owner-KAS token, verified as authnz-rs's
reference `owner_kas_token::verify`: tag 61, COSE_Sign1 ES256 under identity's
COSE key set, protected content type `application/owner-kas+cwt`, exactly the
contract's eight payload keys, `iss`, `aud` `owner-kas:<route_id>`,
`exp - iat ≤ 900`, ±60 s. On a Rewrap, the body's top-level
`signed_request_token` must be an ES256 JWT under the token's `cnf` key with
`exp` no later than the token's. Nothing else in the body is read.

The poll accepts the bearer until the request is deleted (deadline + 10 min),
so a late poll gets 410 rather than a 401 the app would show as "signed out".

**Owner routes** take only the passkey session CWT, verified as `/media/v1`
verifies it (`aud` `arkavo` and `MEDIA_PLATFORM_AUDIENCE`, person-shaped, no
agent marker). Its `sub` must equal the owner recorded with the request.

Neither token works on the other's routes, and the owner-KAS token's single
`owner-kas:` audience fails every other verifier in arks.

### The read at identity

authnz-rs#148 (identity 0.31.0). For each Rewrap, arks asks identity for the
route: `GET {OIDC_ISSUER}/owner-kas/routes/{route_id}/relay` →
`{owner_sub, apns_token?, environment?}`. The credential is a
`client_credentials` access token of the relay's own `owner-kas-relay` client
(on identity's `OWNER_KAS_RELAY_CLIENT_IDS`; not `arks-media`, whose secret
shouldn't read push tokens), from `POST {OIDC_ISSUER}/oauth/token`, sent as
**`X-Auth-Token`**, not `Authorization`. It lasts an hour and is re-minted on
a 401.

- 200: the owner is recorded with the request; a production APNs token, if
  any, gets the alert.
- 404 `unknown_route` or 410 `route_retired` (sharing off, the account
  deleted or no longer live): the Rewrap is 404. On a 410 arks also drops
  everything queued for the route and its cache entry. Identity refuses to
  mint tokens for such routes, so this only follows a retirement within the
  token's 15 minutes.
- 403: this client isn't on identity's list. Treated as unavailable (503).
- Anything else, or no answer within 10 s: the Rewrap is 503 with
  `Retry-After` and nothing is queued, since a request without its owner
  could never be listed. A 401 renews the service token once.

A 200 is reused for 60 s. While identity is unreachable, one up to 15 minutes
old still serves. 404 and 410 are never cached.

Until identity 0.31.0 deploys, the read doesn't exist and every Rewrap is 503.

## The APNs alert

On a new request for a route with a token: `apns-push-type: alert`,
`apns-topic: com.arkavo.Arkavo`, `apns-collapse-id` the route ID,
`apns-expiration` the deadline, payload
`{"aps":{"alert":{"body":"Someone is asking to open a file you protected."}}}`.
No person, file or route goes to Apple. At most one alert per route per 30 s.
The alert is sent after the 202 and never fails it. `410` or `400
BadDeviceToken`/`DeviceTokenNotForTopic` makes arks delete the route's push
token at identity: `DELETE {OIDC_ISSUER}/owner-kas/routes/{route_id}/relay/push`
with `{"apns_token": "<that token>"}`, same client. Identity removes it only
if it still matches, so a token the owner set meanwhile survives.

The key (`AuthKey_W3CY524V6Y.p8`, team `M8GS7ZT95Y`) is **production-only**
(arkavo-ios ADR-0074 decision 7), so alerts go only to `api.push.apple.com`,
and a token identity reports with any other `environment` is ignored. The
provider token is an ES256 JWT (`iss` team, `kid` key ID), reused for 50
minutes and renewed once on `ExpiredProviderToken`/`InvalidProviderToken`.
APNs negotiates TLS 1.3 and h2, so the shared TLS 1.3-only client applies.

To check a key without a device:

```bash
OWNER_KAS_APNS_PROBE=production/AuthKey_W3CY524V6Y.p8 APNS_KEY_ID=W3CY524V6Y \
  APNS_TEAM_ID=M8GS7ZT95Y cargo test --bin arks apns_probe -- --nocapture
# APNs production: 400 BadDeviceToken   ← the key is accepted
```

## Storage

Redis under `owner-kas:`: the request (bearer, body, owner, answer),
deduplication, per-route and per-submitter counters and the alert rate limit,
each expiring at the deadline + 10 minutes. The enqueue and the answer are
Lua scripts, so the limits and the write-once answer hold under concurrency.
Production Redis has no append-only log; losing a restart's worth of requests
means receivers retry, which the design allows.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `OWNER_KAS` | `off` | `on` mounts the routes |
| `OWNER_KAS_RELAY_CLIENT_SECRET` | — | required when on: the `owner-kas-relay` client's secret at identity |
| `OWNER_KAS_RELAY_CLIENT_ID` | `owner-kas-relay` | |
| `OWNER_KAS_RELAY_CLIENT_AUDIENCE` | — | sent as `audience` on the token request; identity 0.31.0 needs none |
| `OWNER_KAS_RELAY_URL` | `{OIDC_ISSUER}/owner-kas/routes/{route_id}/relay` | |
| `OWNER_KAS_PUSH_URL` | `{OIDC_ISSUER}/owner-kas/routes/{route_id}/relay/push` | the service `DELETE` |
| `OIDC_ISSUER` | `https://identity.arkavo.net` | token issuer, COSE keys, token endpoint |
| `MEDIA_PLATFORM_AUDIENCE` | `https://platform.arkavo.net` | required in the owner's session `aud` |
| `APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID` | — | all three or none; none queues without alerts |
| `APNS_TOPIC` | `com.arkavo.Arkavo` | |

## Logging

Paths (route and request IDs) are logged by the request middleware. Tokens,
bodies and APNs device tokens are never logged; transport errors to APNs and
identity are logged without their URL.

## Tests

`cargo test --bin arks owner_kas` runs everything against in-memory stores
and a loopback stand-in for identity. The Redis store has its own tests,
skipped unless `OWNER_KAS_TEST_REDIS=redis://127.0.0.1:6379/15` is set.
