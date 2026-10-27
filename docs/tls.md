# TLS versions

Which TLS versions arks accepts on inbound connections and requires on outbound ones.
All TLS in arks is rustls; there is no OpenSSL on these paths.

## Inbound

| Listener | Versions | Where |
|---|---|---|
| TCP (HTTPS, WebSocket), `$PORT` | TLS 1.3 only; with `TLS_ALLOW_TLS12=true`, also 1.2 (1.3 preferred) | `rustls_server_config` in `src/bin/main.rs` |
| HTTP/3 (QUIC), UDP `$PORT` | TLS 1.3 only (QUIC requires it) | `src/modules/h3.rs` |

One listener serves every client (`/ws`, `/media`, KAS, `/c2pa`, `.well-known`), so a
client without TLS 1.3 fails the handshake on all of them. ArkavoKit also requires TLS 1.3
on its side for C2PA and identity calls (ArkavoKit#38).

`TLS_ALLOW_TLS12` (default `false`; `true`/`false`, `1`/`0`, `yes`/`no`, anything else
stops startup) re-admits TLS 1.2 as an ops rollback if a client turns out to need it.
arks logs a warning at startup while it is on. A 1.3-capable client still gets 1.3: TLS
1.3's downgrade protection (RFC 8446 §4.1.3) stops an attacker forcing it down to 1.2.

## Outbound

| Link | Client | Minimum |
|---|---|---|
| Identity: COSE keys (`{OIDC_ISSUER}/.well-known/cose-keys`), service tokens (`{OIDC_ISSUER}/oauth/token`) | `reqwest` | TLS 1.3 |
| opentdf-platform (`OPENTDF_PLATFORM_URL`): `GetDecision`, proxy, AuthZEN facade | `reqwest` | TLS 1.3 when https; plain HTTP on loopback in production |
| AWS KMS (C2PA signing), DynamoDB (moderation) | AWS SDK default HTTPS client | TLS 1.2 |
| C2PA timestamp authority (`C2PA_TSA_URL`) | `ureq`, built by the c2pa crate | TLS 1.2 |
| NATS, Redis | | plain, loopback only |

Every `reqwest` client is built from `modules::http_client::builder()`, which sets the
TLS 1.3 minimum; new outbound clients should start from it too. A server that offers only
TLS 1.2 is refused at the handshake, and the request fails as unreachable (503 on the
licence and token paths, with the cause in the error log).

The AWS SDK and timestamp clients are not pinned. AWS KMS, DynamoDB and the SSL.com C2PA
timestamp authority all offer TLS 1.3, so those links negotiate 1.3, and rustls's
downgrade check applies. Only if one of those services stopped offering 1.3 would the
link fall back to 1.2. Pinning them would need:

- **Timestamp authority:** override `send_timestamp_request` on `RemoteKeySigner`
  (`src/modules/c2pa_kms.rs`) and send the RFC 3161 request with a 1.3-only client.
  The c2pa crate builds its own `ureq` agent.
- **AWS SDK:** a custom HTTP client restricted to TLS 1.3, passed to the SDK config.

## Checking a link

```bash
openssl s_client -connect <host>:443 -servername <host> -tls1_3 </dev/null
openssl s_client -connect <host>:443 -servername <host> -tls1_2 </dev/null
```
