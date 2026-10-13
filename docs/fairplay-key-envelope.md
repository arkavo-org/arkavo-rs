# FairPlay key-envelope profile

The profile `urn:arkavo:fairplay:key-envelope:1` separates standard OpenTDF encryption from FairPlay media encryption. The archive carries an AES-256-GCM `0.payload` containing the per-track AES-128 keys and IVs; the extra HLS entries remain `cbcs` encrypted. The license endpoint consumes the envelope inside the KSM and returns only a FairPlay CKC.

## Request and authorization

`POST /media/v1/key-request` retains the person token, owned playback session, `assetId` (the policy UUID), `component` (`video` or `audio`), base64 `spcData`, and base64 `tdfManifest`. It additionally requires base64 `tdfPayload`, the exact encrypted bytes of `0.payload`. The request does not carry plaintext track keys. The endpoint allows a bounded 6 MiB JSON body so both base64 fields fit; decoded manifests are limited to 2 MiB and encrypted payloads to 2,097,180 bytes. Legacy manifests omit `tdfPayload` and continue through their existing v1/v2 validation.

The KSM verifies the manifest and policy, unwraps a single 32-byte DEK, verifies its policy HMAC, validates segment and root integrity, decrypts the bounded envelope, and checks its track keys, IVs and inventory against the bound policy. It then obtains the platform decision for the viewer. A permit issues the requested track's key and IV through the existing leased CKC path. The SPC asset identifier must equal `<policy uuid>/<component>`. Refusal occurs before the issuer for malformed envelopes, unknown components, asset mismatches, or denied policy. A mismatched SPC causes the generated CKC to be discarded.

## Wire profile

- `schemaVersion` is `4.3.0`.
- `payload` is a ZIP reference to `0.payload`, encrypted, MIME `application/json`.
- `encryptionInformation.type` is `split`, with exactly one RSA-OAEP wrapped 32-byte key and a raw HS256 policy binding. The KAO uses protocol `kas`; no `encryptedMetadata` is emitted or accepted by this profile.
- `method` is AES-256-GCM, streamable, with empty `iv`; the nonce is the first 12 payload bytes.
- Exactly one segment is accepted, with plaintext no larger than 2,097,152 bytes and ciphertext size plaintext + 28. Default segment sizes are 2,097,152 and 2,097,180. The GMAC segment hash is base64 of its trailing 16-byte GCM tag. The HS256 root signature is base64 of raw HMAC-SHA256(DEK, decoded tag).
- Bound policy `arkavo:fpsProfile` contains the profile URI. Existing `arkavo:components` retains each component's ID, kind and keyBinding. `arkavo:mediaIVs` maps the component IDs to base64 16-byte IVs. `arkavo:media` lists `{name,sha256}` for the encrypted HLS files with canonical base64 SHA-256 digests.
- Decrypted JSON is `{profile,assetId,contentKeyId,tracks:[{id,key,iv}],files:[{name,sha256}]}`. `contentKeyId` equals the policy UUID. `assetId` is a nonempty recording identifier of at most 1,024 bytes. The track order is video then optional audio, with distinct 16-byte keys. Track IVs and the exact ordered file list must match the bound policy.
- Inventories have at most 8,191 unique entries, include `master.m3u8`, and use only the agreed root-level HLS filenames: `video/audio.m3u8`, `video/audio-init.mp4`, `video/audio-segmentN.m4s` (canonical decimal N from 0 through 4092). The viewer verifies every actual HLS entry against this inventory before serving it. The server receives no HLS media bytes and cannot itself perform that file hashing.

Duplicate JSON members, unsupported profiles, mixed legacy/payload requests, malformed encodings, mismatched tags, sizes, keys, IVs or inventories fail closed. Public inventory fields become authenticated only after the policy binding succeeds at the KSM; the viewer's local consistency check alone is not authentication.

## Deployment boundary

This change does not change platform rewrap grants. A consumer permitted to perform generic OpenTDF rewrap for the same RSA key and policy could obtain the DEK and decrypt the envelope outside FairPlay. Before enabling this profile, configure a dedicated KSM wrapping key or a platform authorization boundary that reserves raw DEK release for the KSM identity while allowing viewers to obtain CKCs. Verify a viewer's raw rewrap is denied. The existing `check_rewrap_exposure` startup guard disables the unprotected local shim by forwarding to the platform; it is not proof of that upstream restriction.

No production deployment or Apple device playback is implied by parser and fake-issuer tests. Release acceptance additionally requires a producer-generated archive, strict OpenTDF SDK validation/decryption under an authorized test identity, denied consumer rewrap, and real video/audio CKCs on a supported Apple device.

## Producer interoperability test

The ignored Rust interoperability test consumes the ArkavoMediaKit fixture exporter directory (including its generated test-only RSA key). The fixture policy needs at least one valid data attribute, as required by the license PDP path. Run it explicitly:

```sh
ARKAVO_ENVELOPE_FIXTURE_DIR=/path/to/export cargo test --bin arks --no-default-features producer_generated_archive -- --ignored
```

This verifies the Swift writer's actual manifest, ciphertext, RSA wrapping, policy binding, integrity data, track key and IV against the Rust reader. The separate normal unit and API tests exercise corruption, binding mismatches, policy denials, and track selection without the Apple SDK.
