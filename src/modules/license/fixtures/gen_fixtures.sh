#!/usr/bin/env bash
# Regenerates the FairPlay license fixtures with openssl only, so arks'
# verifier is checked against an independent producer of the binding and
# the RSA-OAEP-SHA1 wrap. TEST KEY ONLY — never a real KAS key.
# Usage: gen_fixtures.sh <output-dir>   (optional: OPENSSL=/path/to/openssl)
# Writes test_kas_rsa_private.pem, manifest_allowed.json, binding_hex.txt and
# binding_raw_json.txt into <output-dir>. Nothing generated is committed.
set -euo pipefail
OUT="${1:?usage: gen_fixtures.sh <output-dir>}"
mkdir -p "$OUT"
OPENSSL="${OPENSSL:-openssl}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# macOS /usr/bin/openssl is LibreSSL, which lacks rsa_oaep_md / -mac HMAC.
"$OPENSSL" version | grep -q "^OpenSSL 3" || { echo "need OpenSSL 3 (brew install openssl@3; put it first on PATH or set OPENSSL=...)"; exit 1; }

DEK_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
UUID=3f1c9e2a-7b4d-4e8f-9a21-5c6d7e8f9a0b
FQN=https://patreon.arkavo.com/attr/campaign-tier/value/11111111_gold
KAS_URL=https://platform.arkavo.net/kas
# Content IV f0f1..ff, base64 as TDF writes it.
IV_B64=8PHy8/T19vf4+fr7/P3+/w==

"$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT/test_kas_rsa_private.pem" 2>/dev/null
"$OPENSSL" pkey -in "$OUT/test_kas_rsa_private.pem" -pubout -out "$WORK/pub.pem"

# hex -> binary with printf \x escapes (no xxd dependency)
ESC=$(printf '%s' "$DEK_HEX" | sed 's/../\\x&/g')
printf "$ESC" > "$WORK/dek.bin"
WRAPPED=$("$OPENSSL" pkeyutl -encrypt -pubin -inkey "$WORK/pub.pem" \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 \
  -in "$WORK/dek.bin" | base64 | tr -d '\n')

POLICY="{\"uuid\":\"$UUID\",\"body\":{\"dataAttributes\":[{\"attribute\":\"$FQN\"}],\"dissem\":[]}}"
POLICY_B64=$(printf '%s' "$POLICY" | base64 | tr -d '\n')

# Correct form: base64(HMAC-SHA256(DEK, base64 policy string)).
BINDING=$(printf '%s' "$POLICY_B64" | "$OPENSSL" dgst -sha256 -mac HMAC -macopt hexkey:$DEK_HEX -binary | base64 | tr -d '\n')
# Legacy hex bug: base64(hex(HMAC(...))).
printf '%s' "$POLICY_B64" | "$OPENSSL" dgst -sha256 -mac HMAC -macopt hexkey:$DEK_HEX -hex | awk '{print $NF}' | tr -d '\n' | base64 | tr -d '\n' > "$OUT/binding_hex.txt"
# Wrong input: HMAC over the raw policy JSON.
printf '%s' "$POLICY" | "$OPENSSL" dgst -sha256 -mac HMAC -macopt hexkey:$DEK_HEX -binary | base64 | tr -d '\n' > "$OUT/binding_raw_json.txt"

cat > "$OUT/manifest_allowed.json" <<EOF
{"payload":{"type":"reference","url":"0.payload","protocol":"zip","isEncrypted":true},
 "encryptionInformation":{"type":"split","policy":"$POLICY_B64",
  "keyAccess":[{"type":"wrapped","url":"$KAS_URL","protocol":"kas","wrappedKey":"$WRAPPED",
   "policyBinding":{"alg":"HS256","hash":"$BINDING"}}],
  "method":{"algorithm":"AES-256-GCM","isStreamable":true,"iv":"$IV_B64"},
  "integrityInformation":{"rootSignature":{"alg":"HS256","sig":""},"segmentHashAlg":"GMAC","segments":[]}}}
EOF
echo "fixtures regenerated"
