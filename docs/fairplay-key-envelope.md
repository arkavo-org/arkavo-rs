# FairPlay key-envelope profile

The profile `urn:arkavo:fairplay:key-envelope:1` separates standard OpenTDF encryption from FairPlay media encryption. The archive carries an AES-256-GCM payload entry (usually `0.payload`) containing the per-track AES-128 keys and IVs; the extra HLS entries remain `cbcs` encrypted. The license endpoint consumes the envelope inside the KSM and returns only a FairPlay CKC.

## Request and authorization

`POST /media/v1/key-request` retains the person token, owned playback session, `assetId` (the policy UUID), `component` (`video` or `audio`), base64 `spcData`, and base64 `tdfManifest`. It additionally requires base64 `tdfPayload`, the exact encrypted bytes of the payload entry; an envelope manifest without it is a 400 `tdfPayload is required`. The request does not carry plaintext track keys. The endpoint allows a bounded 6 MiB JSON body so both base64 fields fit, and reads it only after the person token verifies; decoded manifests are limited to 2 MiB and encrypted payloads to 2,097,180 bytes. Legacy manifests omit `tdfPayload` and continue through their existing v1/v2 validation.

The playback session must be started (`POST /media/v1/session/start`) with `assetId` equal to the policy UUID, which the envelope authenticates as its `contentKeyId`. A key request on a session for any other asset is refused. The envelope's own `assetId` is an authenticated label only; viewers never decrypt the payload, so they cannot send it (arkavo-rs#89).

The KSM verifies the manifest and policy, unwraps a single 32-byte DEK with its dedicated envelope key, verifies its policy HMAC, validates segment and root integrity, decrypts the bounded envelope, and checks its track keys, IVs and inventory against the bound policy. It then obtains the platform decision for the viewer. A permit issues the requested track's key and IV through the existing leased CKC path. The SPC asset identifier must equal `<policy uuid>/<component>`.

Malformed envelopes, unknown components, a request `assetId` other than the policy UUID, a session started for another asset, and a denied policy are all refused before the issuer is called. The SPC's asset identifier is different: the FairPlay SDK reads it in the same call that produces the CKC, so a mismatch is detected only after the issuer has run. That CKC is discarded and never returned, and the request gets the generic 403.

## Wire profile

Only Arkavo producers (the ArkavoMediaKit packager) write this profile. It is a strict subset of OpenTDF 4.3.0, and archives from other OpenTDF SDKs are not expected to pass it.

- `schemaVersion` is `4.3.0`, the root field every OpenTDF SDK writes; the spec's `tdf_spec_version` is not used.
- `payload` is an encrypted ZIP `reference`, MIME `application/json`. `payload.url` names its root-level entry; `0.payload` is the usual name. Any name is accepted that is non-empty, at most 255 bytes, not `.` or `..`, has no `/` or `\`, and is neither `manifest.json` nor an HLS media name. arks never opens the archive; it receives the entry's bytes as `tdfPayload`.
- `encryptionInformation.type` is `split`, with exactly one RSA-OAEP wrapped 32-byte key and a raw HS256 policy binding: `hash` is base64 of the raw HMAC-SHA256, as the OpenTDF spec defines it. The reference Go SDK's base64-of-hex form is refused. The KAO uses protocol `kas`; no `encryptedMetadata` is emitted or accepted by this profile. The KAO `kid` names the envelope key the DEK is wrapped to (see [Key rotation](#key-rotation)); it should always be written.
- `method` is AES-256-GCM, streamable, with empty `iv`; the nonce is the first 12 payload bytes.
- Exactly one segment is accepted, with plaintext no larger than 2,097,152 bytes and ciphertext size plaintext + 28. Default segment sizes are 2,097,152 and 2,097,180. The GMAC segment hash is base64 of its trailing 16-byte GCM tag. The HS256 root signature is base64 of raw HMAC-SHA256(DEK, decoded tag).
- Bound policy `arkavo:fpsProfile` contains the profile URI. Existing `arkavo:components` retains each component's ID, kind and keyBinding. `arkavo:mediaIVs` maps the component IDs to base64 16-byte IVs. `arkavo:media` lists `{name,sha256}` for the encrypted HLS files with canonical base64 SHA-256 digests.
- Decrypted JSON is `{profile,assetId,contentKeyId,tracks:[{id,key,iv}],files:[{name,sha256}]}`. `contentKeyId` equals the policy UUID, which must be in canonical lowercase hyphenated form. `assetId` is a nonempty recording identifier of at most 1,024 bytes. The track order is video then optional audio, with distinct 16-byte keys. Track IVs and the exact ordered file list must match the bound policy.
- Inventories have at most 8,191 unique entries, include `master.m3u8`, and use only the agreed root-level HLS filenames: `video/audio.m3u8`, `video/audio-init.mp4`, `video/audio-segmentN.m4s` (canonical decimal N from 0 through 4092). The viewer verifies every actual HLS entry against this inventory before serving it. The server receives no HLS media bytes and cannot itself perform that file hashing.

Duplicate JSON members, unsupported profiles, mixed legacy/payload requests, malformed encodings, mismatched tags, sizes, keys, IVs or inventories fail closed. Public inventory fields become authenticated only after the policy binding succeeds at the KSM; the viewer's local consistency check alone is not authentication.

## Deployment boundary

A DEK that the platform KAS can unwrap is one any entitled viewer can obtain through generic OpenTDF rewrap, and with it the raw track keys, outside FairPlay. The profile therefore uses a dedicated KSM wrapping key that the platform KAS never holds:

- `MEDIA_ENVELOPE_RSA_KEY_PATH` names a PKCS#8 RSA private key held only by arks. The producer wraps the envelope DEK (RSA-OAEP SHA-1) to its public key.
- Unset, the profile is off: every envelope manifest is refused with the generic 403 `manifest refused`. Legacy v1/v2 manifests are unaffected.
- Startup fails if this key, or any retired envelope key, is the same as `KAS_RSA_KEY_PATH`.
- Never import this key into the platform keyring. The KAO `url` still has to be in `MEDIA_KAS_URLS`, but it only routes; the key is the boundary.

The existing `check_rewrap_exposure` startup guard separately keeps the local `/kas/v2/rewrap` shim from releasing KAS-key DEKs.

## Getting the wrapping key

Producers fetch the current envelope key from arks:

```http
GET /media/v1/envelope-key

{"kid":"<32 hex>","alg":"RSA-OAEP","publicKey":"-----BEGIN PUBLIC KEY-----\n..."}
```

The route is unauthenticated, like `/media/v1/certificate`: the key only lets a producer wrap a DEK that arks alone can unwrap. Wrap the 32-byte DEK with RSA-OAEP (SHA-1, as OpenTDF wraps keys) and write `kid` into the KAO. It returns 503 when the profile is not configured, and it is cacheable for 5 minutes, so producers pick up a rotation quickly.

## Key rotation

The envelope key works like a KAS key that only ever answers with a CKC, so it must exist as long as packages wrapped to it must play. Rotation is by `kid`:

- A key's `kid` is the first 32 lowercase hex characters (128 bits) of the SHA-256 of its public key's SubjectPublicKeyInfo DER. That fits the platform KAS registry's 36-character `key_id`, should the key ever be registered there as public-key-only. The packager can compute it from the public PEM alone:

  ```sh
  openssl pkey -pubin -in ksm_envelope_public.pem -outform DER | openssl dgst -sha256 -r | cut -c1-32
  ```

  arks logs the current `kid` at startup and publishes it at `GET /media/v1/envelope-key`.
- `MEDIA_ENVELOPE_RSA_KEY_PATH` is the current key. `MEDIA_ENVELOPE_RSA_RETIRED_KEY_PATHS` (comma list) holds older keys that still unwrap existing packages. A key may appear only once across both.
- A KAO with a `kid` unwraps only with the key it names; an unknown or non-string `kid` is refused with the generic 403. A KAO without a `kid` (packages made before `kid` support) unwraps with the current key only, so it stops playing once its key is retired. Re-wrapping such a package adds its `kid`.

To rotate:

1. Generate a new PKCS#8 RSA key next to the current one and compute its `kid`.
2. Set `MEDIA_ENVELOPE_RSA_KEY_PATH` to the new key and move the old path to `MEDIA_ENVELOPE_RSA_RETIRED_KEY_PATHS`. Restart arks.
3. Producers pick up the new public key and `kid` from `GET /media/v1/envelope-key` (cached up to 5 minutes).
4. To drop a retired key, first re-wrap every package that names it: unwrap the DEK with the old key, wrap it to the new public key (RSA-OAEP SHA-1), and replace the KAO `wrappedKey` and `kid` in `manifest.json`. The policy binding, segment tags and payload entry depend on the DEK, not the wrapping key, so nothing else changes. Then remove the key from `MEDIA_ENVELOPE_RSA_RETIRED_KEY_PATHS` and restart. A re-wrap tool is not yet provided; until one exists, keep retired keys loaded.

No production deployment or Apple device playback is implied by parser and fake-issuer tests. Release acceptance additionally requires a producer-generated archive, strict OpenTDF SDK validation/decryption under an authorized test identity, denied consumer rewrap, and real video/audio CKCs on a supported Apple device.

## Producer interoperability test

The ignored Rust interoperability test consumes the ArkavoMediaKit fixture exporter directory (including its generated test-only RSA key). The fixture policy needs at least one valid data attribute, as required by the license PDP path. Run it explicitly:

```sh
ARKAVO_ENVELOPE_FIXTURE_DIR=/path/to/export cargo test --bin arks --no-default-features producer_generated_archive -- --ignored
```

This verifies the Swift writer's actual manifest, ciphertext, RSA wrapping, policy binding, integrity data, track key and IV against the Rust reader. The separate normal unit and API tests exercise corruption, binding mismatches, policy denials, and track selection without the Apple SDK.
