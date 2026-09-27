# OpenTDF Platform Reverse Proxy

arks can forward selected HTTP routes to an upstream opentdf-platform instance so
clients can hit a single endpoint for both legacy NanoTDF (handled locally) and
modern ZTDF rewrap (handled by platform).

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENTDF_PLATFORM_URL` | — | Upstream base URL. Required when `KAS_PROXY_MODE` ≠ `off`, `AUTHZ_PROXY=on`, or `AUTHZEN_FACADE=on`. Production co-located sidecar is `http://127.0.0.1:8181` (`:8443` on that box is Docker). Loopback is allowed. |
| `KAS_PROXY_MODE` | `off` | One of `off`, `connect`, `rest`, `both`. |
| `AUTHZ_PROXY` | `off` | `on` forwards `/authorization.v2.AuthorizationService/*` to platform. Independent of `KAS_PROXY_MODE` and of `AUTHZEN_FACADE`; requires `OPENTDF_PLATFORM_URL`. |
| `AUTHZEN_FACADE` | `off` | `off` or `on` only. `on` serves AuthZEN 1.0 `/access/v1/evaluation`, `/access/v1/evaluations`, and `GET /.well-known/authzen-configuration`. Independent of `AUTHZ_PROXY`. Requires `OPENTDF_PLATFORM_URL`. There is no built-in evaluator. |
| `OIDC_ISSUER` | `https://identity.arkavo.net` | Service-CWT `iss` pin when the facade is on. |
| `AUTHZEN_COSE_KEYS_URL` | `{OIDC_ISSUER}/.well-known/cose-keys` | COSE_Key Set for PEP service-CWT verify (60s min refresh, 10s fetch, 5min max cache age, single-flight). |
| `AUTHZEN_PEP_CLIENT_IDS` | unset | Optional comma-separated OAuth client ids. If set, other service CWTs get HTTP 403. If unset, any valid `service-account` CWT is accepted. |
| `AUTHZEN_PUBLIC_URL` | unset | `policy_decision_point` identifier. **Set this in production.** If unset it falls back to the request `Host`; `X-Forwarded-Host`/`-Proto` are deliberately *not* trusted (no trusted-proxy config exists here, so honouring them would let a caller point every PEP that bootstraps from the discovery document at a PDP of their choosing). |
| `AUTHZEN_EXPECTED_AUD` | unset | If set, a PEP service CWT's `aud` must contain this value in addition to its own client id. Without it, a service CWT minted for any other relying party of the same issuer authenticates here. |
| `AUTHZEN_UPSTREAM_BEARER` | unset | Optional static bearer for facade→OpenTDF (tests / JWT exchange). Default: forward the verified PEP **service CWT**. |

## Modes

- **`off`** — proxy disabled, all routes served locally.
- **`connect`** — `/kas.AccessService/Rewrap`, `/kas.AccessService/PublicKey`, `/kas.AccessService/LegacyPublicKey` forward to platform.
- **`rest`** — `/kas/v2/rewrap` and `/kas/v2/kas_public_key` forward to platform (replaces the local `http_rewrap` shim).
- **`both`** — `connect` + `rest`.

Whenever the mode is anything other than `off`, `/.well-known/opentdf-configuration` is also forwarded to the upstream platform so clients see the authoritative discovery document, along with public attribute discovery (`GET /attributes`, `GET /attr/*`) served from the platform's policy snapshot — attribute FQNs dereference through this host when the namespace DNS (e.g. patreon.arkavo.com) points here.

`/ws` (custom NanoTDF binary protocol) always stays local; `/media/v1/*` and `/c2pa/v1/*` are always local.

## Proof of possession and actor headers (agent tokens)

Agent tokens are authnz-rs agent CWTs (`arkavo_npe.type = agent`, contract `docs/agent-credentials-contract.md` v1 in authnz-rs). Each carries a `cnf` key. Two platform-side checks bear on these tokens but are **not deployed yet** — they land with opentdf-platform's own agent-credentials PR:

- **P1 (DPoP, RFC 9449):** the platform will refuse an agent token's rewrap unless it comes with a DPoP proof signed by the token's `cnf` key.
- **P2 (workload status; the KAS rule the authnz-rs contract marks informative):** the platform will call the workload status endpoint (`GET /agents/workloads/{id}/status`, configured by `server.auth.agent_status`) and deny the rewrap when that call fails or is non-200, on quarantine, a stale `generation`, a mismatched `current_did`/`workload`/`swarm`/`owner`, or a token that lacks `arkavo_swarm` (agents onboarded by trust QR before specialization).

P1 and P2 are not enforced yet; this section documents what arks must preserve so agent rewraps work once they are. arks is already in that path on `/kas.AccessService/Rewrap`, forwarding whatever the client sends:

| Header | What arks does | Why it matters |
|--------|----------------|-----------------|
| `Authorization` | forwarded byte-for-byte | carries the agent CWT; once P1 is enforced, the proof's `ath` is a hash of the token in it, so any rewrite breaks verification |
| `DPoP` | forwarded byte-for-byte (it is not hop-by-hop) | carries the proof; any rewrite breaks its signature |
| `X-Actor-Token` | forwarded as sent (see #70 below) | names the forwarder for the platform's `act` rule, once that rule is enforced |

`src/modules/platform_proxy.rs` `pop_header_tests` pins the first two — they must reach the platform unchanged today, independent of whether P1 is enforced yet — and pins today's relay of the third.

**Agents will use the Connect rewrap.** `htu` for agents is the bare Connect procedure `/kas.AccessService/Rewrap` (agents use Connect only), which is identical on both sides of this proxy, so once P1 is enforced a Connect DPoP proof will keep validating through arks. For REST `/kas/v2/rewrap`, the platform will build the expected `htu` from `Origin`, or else from `Host` plus whether its own connection is TLS. Behind arks that is `http://127.0.0.1:8181/kas/v2/rewrap`, never `https://platform.arkavo.net/kas/v2/rewrap`, so once P1 ships, a correct agent proof would fail there. REST DPoP through the proxy needs the platform to honour `X-Forwarded-Proto`/`X-Forwarded-Host` from a trusted proxy, which is tracked as a follow-up. Production runs `KAS_PROXY_MODE=connect`: REST rewrap is served by arks locally (see `docs/hostname-policy.md`), so this gap does not block production agent traffic.

**Before arkavo-rs #70 deploys, set `AGENT_AUTHORIZED_ACTORS`.** #70 would make arks strip any client `X-Actor-Token` and send its own service CWT instead (`ARKS_SERVICE_CWT_PATH`). Once the platform enforces an actor-token rule for agent bearers, it will require the actor token's `sub` to appear in the bearer's `act[].sub`; for agent tokens `act` comes from authnz-rs `AGENT_AUTHORIZED_ACTORS`, so that list must contain arks's service id **exactly as the platform sees it**: the `sub` of arks's service CWT, which is `client:<client_id>` for a `client_credentials` token (authnz-rs `handle_client_credentials_grant`), never a URL. Add it on identity before deploying #70, or every agent rewrap through arks fails with 401 once that rule is live. Agent tokens minted before the change don't carry the new `act` entry, so they keep failing until they are refreshed (≤ 5 min for `short_lived` delegations, ≤ 15 min otherwise).

That said, only agent tokens carry an `act` claim at all — a human app's bearer or a service-to-service catalog call has no `act` to satisfy an actor check. #70 as drafted overwrites `X-Actor-Token` on every proxied rewrap, agent or not, so it would make non-agent relayed tokens fail an actor-token rule they were never shaped to pass. #70 needs a narrower rule before it deploys.

## KAS URL identity caveat

The platform validates that the `kas_url` claim in a rewrap request matches its
`RegisteredKASURI` (see `service/kas/kas.go` in the platform repo). That claim
sits inside the signed rewrap envelope, so arks cannot rewrite it while
proxying — rewriting would require re-signing with a key the platform trusts,
which is not supported.

In production this is already consistent and needs no action: arks serves
`https://platform.arkavo.net`, and the co-located platform registers
`registered_kas_uri: https://platform.arkavo.net`. Clients mint against the
same name they dial.

The caveat matters only if the two ever diverge. If you point arks at an
upstream whose `RegisteredKASURI` is a different name (say `https://platform.svc`),
then TDFs must be minted against **that** name, not against the arks hostname —
otherwise the platform rejects the rewrap. Keep `registered_kas_uri` and the
public arks hostname equal unless you have a specific reason not to.

Note the value is the bare origin — `https://platform.arkavo.net`, with no
`/kas` path. A TDF minted with `.../kas` in `keyAccess[].url` carries a
`kas_url` that is not string-equal to the registered value and is denied.

See `docs/hostname-policy.md` for why `platform.arkavo.net` is the only
published production name.

## Authorization service forwarding

`AUTHZ_PROXY=on` exposes the platform's authorization.v2 decision endpoints
through this host. PDP delegators — the entitled-catalog endpoint on
iroh.arkavo.net (tdf-iroh-s3#5) — call
`POST /authorization.v2.AuthorizationService/GetDecisionMultiResource` here
with their service credentials; arks only relays, the platform's own authn
governs access and all policy evaluation stays in the platform.

## AuthZEN facade (`AUTHZEN_FACADE`)

Independent of `AUTHZ_PROXY`. When `on`, arks serves AuthZEN 1.0 JSON:

- `POST /access/v1/evaluation` → OpenTDF `GetDecision` (claims-mode entity chain)
- `POST /access/v1/evaluations` → `GetDecisionMultiResource` or `GetDecisionBulk`
- `GET /.well-known/authzen-configuration` (no `search_*` endpoints in v1; no `signed_metadata`)

The PEP authenticates with a **service CWT** (`Authorization: Bearer`). SARC
`subject` is PIP data, not the Bearer. Arkavo CWTs are never sent as
`EntityIdentifier.token`. Upstream timeout is 10s; upstream failure is HTTP 500
(not 502). `/ws` NanoTDF rewrap is unchanged.

When both flags are on, PEPs must pin the AuthZEN well-known URLs and must not
POST to `/authorization.v2.AuthorizationService/*`.

### Caller-credential spike (2026-08-26, TLS renewed)

PR 3's entry criterion: confirm production `platform.arkavo.net` accepts a
**service CWT** as the Connect caller, and confirm the deployed identifier
charset.

| Check | Result |
|---|---|
| TLS | Let's Encrypt renewed. `platform.arkavo.net` notAfter 2026-11-24 20:26:29 GMT; `identity.arkavo.net` notAfter 2026-11-24 20:18:30 GMT. `curl` without `-k` returns 200 on well-known. |
| Identifier charset | `GET /attributes` — 16 live values (`public`, `exclusive-content`, `early-access`, …). **0 violations** of `^[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?$`. |
| IdP | `access_token_format: application/cwt`; `cose_keys_uri` present; `client_credentials` advertised. Access tokens are CWT (`authnz-rs` `mint_access_token`). |
| Platform well-known | Mirrors IdP: `idp.access_token_format: application/cwt`, `idp.cose_keys_uri`. |
| Connect caller format | **CWT, not JWT.** Deployed code is [arkavo-org/opentdf-platform](https://github.com/arkavo-org/opentdf-platform) (`feat(auth): cut inbound bearer verification from JWT to CWT`, 2026-05-25). `newTokenVerifier` requires `cose_keys_uri` and builds `CWTVerifier`. Upstream `opentdf/platform` `main` is still JWT/`jwks_uri` — do not use that as the production model. |
| Live GetDecision | No Authorization → 401 `missing authorization header`. Compact JWT, opaque garbage, and a well-formed CWT signed with a **non-IdP** key → 401 `unauthenticated`. A production-signed service CWT was not minted here (no `catalog-node` client secret in this environment). |

**Production path:** the facade **forwards the verified PEP service CWT** as
`Authorization: Bearer` to OpenTDF. Do **not** mint/exchange a JWT for the
Connect caller. `AUTHZEN_UPSTREAM_BEARER` remains a test/lab override only.

Service CWT `aud` must include the platform's configured audience
(`OIDC_PLATFORM_AUDIENCE`, commonly `https://platform.arkavo.net`) — the
fork's `CWTVerifier` checks `aud` against that value.

The identifier charset is enforced on mapped OpenTDF action names and derived
attribute values regardless.

## What is NOT proxied

- WebSocket `/ws` (NanoTDF rewrap, contracts, NATS push) — arks-only.
- `/media/v1/*` (TDF3 media DRM, session manager).
- `/c2pa/v1/*` (C2PA signing).
- `/.well-known/apple-app-site-association` (always local; `/.well-known/opentdf-configuration` is forwarded when the proxy is on).

## What's not done

- No JWT re-signing — clients must present credentials platform accepts.
- No request-body rewriting (e.g. `kas_url` rewrite).
- No request streaming — bodies are buffered up to 16 MiB before forwarding.
- AuthZEN Resource Search (`GetEntitlements`) — phase 6.
- No trusted-proxy forwarding headers to the platform — REST `/kas/v2/rewrap` cannot carry an agent DPoP proof through arks (see [Proof of possession and actor headers](#proof-of-possession-and-actor-headers-agent-tokens)).
