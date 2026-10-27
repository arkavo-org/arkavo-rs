# Components the scanner cannot see

`osv-scanner` and `cargo cyclonedx` read `Cargo.lock` and Cargo metadata (see
`.github/workflows/security.yaml`). They do not match the items below against advisories, so
they are listed here by hand. This file is uploaded with each release SBOM. Review it whenever
one of them changes, and on the same schedule as the dependency findings: CRITICAL and HIGH
within 30 days of detection (O.6), no later than 90 days (O.3).

## Vendored code

| Component | Where | What it is | Review |
| --- | --- | --- | --- |
| `fpssdk` 26.0.0 | `vendor/fpssdk/` (workspace member) | Apple FairPlay Streaming Server SDK, proprietary Rust source from the Apple Developer Portal (see `THIRD-PARTY-LICENSES.md`). It is a path crate, so advisory databases do not know it. Its own dependencies (`openssl`, `x509-parser`, `chrono`, `serde_jsonrc` and others) are in `Cargo.lock` and are scanned. | When a new SDK drop is vendored, read the release notes and re-check its dependency list. |
| `openssl` built from source | `vendor/fpssdk` enables the `openssl` crate's `vendored` feature, which compiles the C library from the `openssl-src` crate. | The scanner sees the `openssl-src` crate version, not the OpenSSL release inside it. The leading digits of the crate version give the OpenSSL release (for example 300.x is OpenSSL 3.0.x). | Compare against OpenSSL security advisories when `openssl-src` moves. |

## Native binaries

| Component | Where it comes from | Review |
| --- | --- | --- |
| `libfpscrypto` | Apple FairPlay SDK prebuilt library, linked by `vendor/fpssdk/build.rs` for builds with the `fairplay` feature. Not in the repository (`docs/fairplay.md`). Production builds include it by default. | Track the SDK version Apple ships with it; no public advisory feed exists. |

## First-party git dependencies

These are `git` sources in `Cargo.toml`, pinned by tag. The scanner records them by commit, not
by crates.io version, so it cannot match them against advisories. Their own dependencies resolve
through crates.io and are scanned.

| Crate | Source |
| --- | --- |
| `opentdf`, `opentdf-crypto`, `opentdf-protocol`, `opentdf-kas` | `https://github.com/arkavo-org/opentdf-rs` (tags in `Cargo.toml`) |
| `rml_rtmp`, `rml_amf0` | `https://github.com/arkavo-org/rust-media-libs` (tag in `Cargo.toml`) |

## Outside the workspace

- `etc/contracts/*` are standalone ink! contract crates with their own `Cargo.toml` and no
  lockfile. They are not built into `arks` and are not scanned.
- The operating system and runtime image of the hosting environment are covered by the O.6
  hosting process, not by this repository's CI.
