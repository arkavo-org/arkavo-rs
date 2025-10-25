# Third-Party Licenses

This document acknowledges third-party software components used in this project.

## Apple FairPlay Streaming Server SDK

**Version:** 26
**Location:** `vendor/fpssdk/`
**Usage:** Optional feature (enabled with `--features fairplay`)

### Description

This project optionally integrates Apple's FairPlay Streaming Server SDK 26 for providing DRM protection to Apple devices (iOS, tvOS, macOS, Safari). The SDK is used only when explicitly compiled with the `fairplay` feature flag.

### License & Terms

The FairPlay Streaming Server SDK is proprietary software owned by Apple Inc. Usage is subject to Apple's licensing terms:

- **Copyright:** © 2023-2024 Apple Inc. All rights reserved.
- **Source:** Downloaded from Apple Developer Portal
- **Documentation:** [Apple FairPlay Streaming](https://developer.apple.com/streaming/fps/)

### Usage Terms

1. **Deployment Packages:**
   - May be deployed as part of a FairPlay Streaming solution
   - Subject to Apple's FairPlay Streaming Deployment Package terms

2. **Development Only:**
   - Development credentials in `vendor/FairPlay_Streaming_Server_SDK_26/Development/` are for testing only
   - Production deployment requires Apple-issued production credentials

3. **Compliance:**
   - Organizations deploying this software with FairPlay enabled must have a valid Apple FairPlay Streaming agreement
   - Test certificates must not be used in production environments

### Files Included

```
vendor/fpssdk/
├── Cargo.toml
├── build.rs
├── src/
│   ├── lib.rs (Rust FFI bindings)
│   └── ... (66+ SDK source files)
└── prebuilt/
    └── macos/
        └── libfpscrypto.dylib (Apple's cryptographic library)
```

### Integration Notes

- The SDK code resides in `vendor/fpssdk/` and is committed to the repository
- Full SDK with credentials is in gitignored `vendor/FairPlay_Streaming_Server_SDK_26/`
- Safe Rust wrapper provided in `crates/fairplay-wrapper/`
- No modifications made to Apple's SDK source code
- FFI calls isolated to wrapper crate for safety

### Disabling FairPlay

To build without FairPlay support:

```bash
cargo build  # Default: fairplay feature is disabled
```

To build with FairPlay support:

```bash
cargo build --features fairplay
```

---

## Open Source Dependencies

All other third-party dependencies are open source and listed in `Cargo.toml`. Their licenses can be inspected using:

```bash
cargo license
```

### Key Dependencies

- **axum** (MIT) - Web framework
- **tokio** (MIT) - Async runtime
- **serde** (MIT/Apache-2.0) - Serialization
- **p256** (Apache-2.0/MIT) - Elliptic curve cryptography
- **aes-gcm** (Apache-2.0/MIT) - AES encryption
- **redis** (BSD-3-Clause) - Redis client
- **nats** (Apache-2.0) - NATS messaging client

For a complete list with license details:

```bash
cargo install cargo-license
cargo license --json
```

---

## Attribution

This software uses the following Apple technologies:

- **FairPlay Streaming** - Content protection and key delivery for Apple devices
- **FPS SDK** - Server-side key module for CKC generation

Apple, FairPlay, iOS, tvOS, macOS, and Safari are trademarks of Apple Inc., registered in the U.S. and other countries.

---

## Compliance Statement

Users of this software are responsible for:

1. Obtaining necessary licenses from Apple for FairPlay Streaming deployment
2. Ensuring compliance with all Apple terms and conditions
3. Using appropriate credentials (development vs. production)
4. Following Apple's security and key management requirements
5. Maintaining confidentiality of FairPlay credentials and keys

For more information, visit [Apple Developer - FairPlay Streaming](https://developer.apple.com/streaming/fps/).
