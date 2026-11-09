# Owner KAS address (`/owner-kas/v1/`)

arkavo-rs#163. The design and contract are arkavo-ios's owner-KAS design, §4.2
and §4.3 (arkavo-ios ADR-0070), with the APNs hint in ADR-0074. The owner-KAS
token is authnz-rs `docs/owner-kas-token.md` (authnz-rs#146, PR #147).

An owner's iPhone holds a KAS private key and decides every release. It can't
be reached directly, so its KAS URL is an address here:
`https://platform.arkavo.net/owner-kas/v1/routes/<route_id>`. OpenTDFKit posts
a standard Rewrap to that URL plus `/kas.AccessService/Rewrap`. arks queues
the request until the owner's phone fetches it, holds the phone's answer until
the receiver collects it, and sends the owner a generic APNs alert.

**arks decides no access and holds no key it could use.** It doesn't verify
the policy, the KAO or the owner's signed decision: the devices do. Admitting
a route record at `PUT` isn't an access decision either. A 202 is never an
ALLOW, and an expired request is "unavailable", never a denial.

Unrelated to the "local KAS" of PR #74 (the platform key served by this
process).

## Routes

| Route | Credential | Answers |
| --- | --- | --- |
| `POST /routes/{route_id}/kas.AccessService/Rewrap` | owner-KAS token for the route; body's `signed_request_token` signed by its `cnf` key | `202 {request_id, status:"pending", deadline}`, `Location`, `Retry-After: 5`. 400 bad route id, 401 token or signed request, 404 no route record, 413 > 64 KiB, 429 + `Retry-After` past 64 pending per route or 8 per submitter |
| `GET /requests/{request_id}` | owner-KAS token whose `aud` names the request's route and whose `sub` submitted it | 202 pending, 200 the stored Rewrap response, 410 `{status:"expired"}`. Any other token: 404 |
| `GET /routes/{route_id}` | owner-KAS token for the route | 200 the record bundle as stored, 404 |
| `PUT /routes/{route_id}` | owner's passkey session CWT | 200 `{route_id, seq}`; 400 not a bundle, 403 another owner's route or the passkey revoked/unknown at identity, 409 `seq` not higher, 422 the chain doesn't hold, 503 identity unavailable |
| `GET /routes/{route_id}/requests?after={request_id}` | owner's session | `{requests:[{request_id, authorization, body, received_at}], cursor}`; 403 not the owner, 404 no route |
| `PUT /requests/{request_id}/response` | owner's session | 204; 409 already answered, 410 past the deadline, 404 not the owner's, 413 > 16 KiB |
| `PUT /routes/{route_id}/push` | owner's session | `{apns_token, environment:"production"}` → 204; 400 otherwise |
| `DELETE /routes/{route_id}/push` | owner's session | 204 |

Every response is `Cache-Control: no-store`. With `OWNER_KAS` off, every
`/owner-kas/` path answers 503.

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
agent marker). Its `sub` must equal the route's `owner_sub`.

Neither token works on the other's routes, and the owner-KAS token's single
`owner-kas:` audience fails every other verifier in arks.

### Route record (`PUT /routes/{route_id}`)

Catalog v2's bundle with `record` in place of `pointer`:

```json
{ "record": "<b64url>", "credential": "<b64url>",
  "assertion": { "credentialId": "", "authenticatorData": "", "clientDataJSON": "", "signature": "" } }
```

- `record`: deterministic CBOR, a map with exactly the text keys `v` (1),
  `route_id` (the path's), `owner_sub`, `kas_key` and `service_key` (65-byte
  SEC1 P-256 points), `kas_kid`, `seq` (1..2^53−1) and `issued_at` (unix s).
- `assertion`: WebAuthn over SHA-256 of the record bytes; RP
  `identity.arkavo.net`, origin `https://identity.arkavo.net`, UP and UV.
- `credential`: identity's passkey credential attestation
  (`application/arkavo-passkey-credential+cbor`), whose `sub` must equal
  `owner_sub` and the session's `sub`.
- The credential's status at identity:
  `GET {OIDC_ISSUER}/passkeys/credentials/<b64url id>/status` → `{sub, revoked}`.

A route never changes owner.

## The APNs alert

On a new request for a route with a token: `apns-push-type: alert`,
`apns-topic: com.arkavo.Arkavo`, `apns-collapse-id` the route ID,
`apns-expiration` the deadline, payload
`{"aps":{"alert":{"body":"Someone is asking to open a file you protected."}}}`.
No person, file or route goes to Apple. At most one alert per route per 30 s.
The alert is sent after the 202 and never fails it. `410` or `400
BadDeviceToken`/`DeviceTokenNotForTopic` deletes the route's token.

The key (`AuthKey_W3CY524V6Y.p8`, team `M8GS7ZT95Y`) is **production-only**
(arkavo-ios ADR-0074 decision 7), so alerts go only to `api.push.apple.com`.
The push route refuses `development` tokens, which Xcode builds register;
TestFlight, Ad Hoc and App Store builds register production tokens. The
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

- **Routes** (record, APNs token): DynamoDB table `OWNER_KAS_ROUTES_TABLE`,
  partition key `route_id` (S). They must outlive a restart until the owner
  turns sharing off; production Redis snapshots but keeps no append-only log.
  Writes are conditional (owner and `seq`).
- **Requests** (bearer, body, answer), deduplication, per-route and
  per-submitter counters and the alert rate limit: Redis under `owner-kas:`,
  each expiring at the deadline + 10 minutes. The enqueue and the answer are
  Lua scripts, so the limits and the write-once answer hold under
  concurrency.

Create the table (account 976193232136, as moderation's):

```bash
aws dynamodb create-table --table-name prod-owner-kas-routes \
  --attribute-definitions AttributeName=route_id,AttributeType=S \
  --key-schema AttributeName=route_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

`arks-prod` needs `dynamodb:GetItem` and `dynamodb:UpdateItem` on it.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `OWNER_KAS` | `off` | `on` mounts the routes |
| `OWNER_KAS_ROUTES_TABLE` | — | required when on |
| `OWNER_KAS_DYNAMODB_ENDPOINT` | — | development only: DynamoDB Local |
| `OIDC_ISSUER` | `https://identity.arkavo.net` | token issuer; COSE keys and credential status under it |
| `MEDIA_PLATFORM_AUDIENCE` | `https://platform.arkavo.net` | required in the owner's session `aud` |
| `OWNER_KAS_PASSKEY_RP_ID` | `identity.arkavo.net` | the route record's WebAuthn RP |
| `OWNER_KAS_CREDENTIAL_STATUS_URL` | `{OIDC_ISSUER}/passkeys/credentials/{credentialId}/status` | `off` skips the check (development only) |
| `APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID` | — | all three or none; none queues without alerts |
| `APNS_TOPIC` | `com.arkavo.Arkavo` | |

## Logging

Paths (route and request IDs) are logged by the request middleware. Tokens,
bodies and APNs device tokens are never logged; APNs transport errors are
logged without their URL, which carries the device token.

## Tests

`cargo test --bin arks owner_kas` runs everything against in-memory stores.
The Redis store has its own tests, skipped unless
`OWNER_KAS_TEST_REDIS=redis://127.0.0.1:6379/15` is set.
