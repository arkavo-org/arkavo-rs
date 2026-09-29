Test-only fixtures for `license::tdf_policy` and the media license tests.

Nothing here is committed key material. The RSA test key, `manifest_allowed.json`
and the two bad bindings (`binding_hex.txt`, `binding_raw_json.txt`) are generated
at test time by `gen_fixtures.sh <output-dir>`, which uses only the openssl CLI so
arks' verifier is checked against an independent producer. The `#[cfg(test)]`
helper `license::fixtures::fixtures()` runs the script once per test process
(via `OnceLock`) into a fresh temp directory and deletes it after reading.

Requirements: OpenSSL 3 (macOS `/usr/bin/openssl` is LibreSSL and will not work).
Put Homebrew `openssl@3` first on PATH, or set `OPENSSL=/path/to/openssl`.
To inspect output manually: `bash gen_fixtures.sh /some/dir`.
