# OpenTDF Platform Reverse Proxy

arks can forward selected HTTP routes to an upstream opentdf-platform instance so
clients can hit a single endpoint for both legacy NanoTDF (handled locally) and
modern ZTDF rewrap (handled by platform).

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENTDF_PLATFORM_URL` | — | Upstream base URL, e.g. `https://platform.svc:8443`. |
| `KAS_PROXY_MODE` | `off` | One of `off`, `connect`, `rest`, `both`. |

## Modes

- **`off`** — proxy disabled, all routes served locally.
- **`connect`** — `/kas.AccessService/Rewrap`, `/kas.AccessService/PublicKey`, `/kas.AccessService/LegacyPublicKey` forward to platform.
- **`rest`** — `/kas/v2/rewrap` and `/kas/v2/kas_public_key` forward to platform (replaces the local `http_rewrap` shim).
- **`both`** — `connect` + `rest`.

Whenever the mode is anything other than `off`, `/.well-known/opentdf-configuration` is also forwarded to the upstream platform so clients see the authoritative discovery document.

`/ws` (custom NanoTDF binary protocol) always stays local; `/media/v1/*` and `/c2pa/v1/*` are always local.

## KAS URL identity caveat

The platform validates that the `kas_url` claim in a rewrap request matches its
`RegisteredKASURI` (see `service/kas/kas.go` in the platform repo). If you run
arks at `https://kas.arkavo.net` but TDFs were minted against
`https://platform.svc`, the URL still points at platform — so direct hits or
proxying both work.

If you want clients to mint TDFs against `kas.arkavo.net` and have arks proxy
them through, you must either:

1. Register `https://kas.arkavo.net` as platform's `RegisteredKASURI`, or
2. Rewrite the `kas_url` field inside the signed rewrap request envelope — not
   currently supported; would require JWT re-signing with a key platform trusts.

## What is NOT proxied

- WebSocket `/ws` (NanoTDF rewrap, contracts, NATS push) — arks-only.
- `/media/v1/*` (TDF3 media DRM, session manager).
- `/c2pa/v1/*` (C2PA signing).
- `/.well-known/apple-app-site-association` (always local; `/.well-known/opentdf-configuration` is forwarded when the proxy is on).

## What's not done

- No JWT re-signing — clients must present credentials platform accepts.
- No request-body rewriting (e.g. `kas_url` rewrite).
- No request streaming — bodies are buffered up to 16 MiB before forwarding.
