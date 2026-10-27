# TLS versions

Which TLS versions arks accepts on inbound connections and requires on outbound ones.
All TLS in arks is rustls; there is no OpenSSL on these paths.

## Inbound

| Listener | Versions | Where |
|---|---|---|
| TCP (HTTPS, WebSocket), `$PORT` | TLS 1.3 and 1.2, 1.3 preferred; nothing older | `ServerConfig::builder()` in `src/bin/main.rs` |
| HTTP/3 (QUIC), UDP `$PORT` | TLS 1.3 only (QUIC requires it) | `src/modules/h3.rs` |

TLS 1.2 stays enabled for clients that still need it. A client that supports 1.3 always
gets 1.3: TLS 1.3's downgrade protection (RFC 8446 §4.1.3) stops an attacker forcing two
1.3-capable ends down to 1.2. Clients that must never use 1.2 enforce a 1.3 minimum
themselves; ArkavoKit does this for C2PA and identity calls (ArkavoKit#38).

To make the listener 1.3-only, replace `ServerConfig::builder()` with
`ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])`. Clients
without TLS 1.3 then fail the handshake.

## Outbound

| Link | Client | Minimum |
|---|---|---|
| Identity: COSE keys (`{OIDC_ISSUER}/.well-known/cose-keys`) | `reqwest`, `src/modules/authzen/cose_keys.rs` | TLS 1.3 |
| Identity: service tokens (`{OIDC_ISSUER}/oauth/token`), and the platform `GetDecision` | `reqwest`, `src/modules/license/pdp.rs` | TLS 1.3 |
| AWS KMS (C2PA signing), DynamoDB (moderation) | AWS SDK default HTTPS client | TLS 1.2 |
| C2PA timestamp authority (`C2PA_TSA_URL`) | `ureq`, built by the c2pa crate | TLS 1.2 |
| opentdf-platform proxy, AuthZEN facade | `reqwest` | TLS 1.2 (plain HTTP on loopback in production) |
| NATS, Redis | | plain, loopback only |

A 1.3 minimum means a server that offers only TLS 1.2 is refused at the handshake.

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
