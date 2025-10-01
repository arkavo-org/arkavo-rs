# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust implementation of a Key Access Service (KAS) from the [OpenTDF specification](https://github.com/opentdf/spec). It provides secure key management, NanoTDF rewrap operations, and policy enforcement over WebSocket connections with NATS messaging and Redis caching.

**Binary name**: `arkavo`
**Library name**: `nanotdf`

## Development Commands

### Build
```bash
# Debug build
cargo build

# Release build (optimized for native CPU)
export RUSTFLAGS="-C target-cpu=native"
cargo build --release
```

### Testing
```bash
# Run all tests
cargo test --verbose

# Run a specific test
cargo test [test_name]
```

### Linting and Formatting
```bash
# Lint with clippy (same as CI)
cargo clippy --lib --bin arkavo --all-features -- -D warnings

# Check formatting
cargo fmt --all --check

# Apply formatting
cargo fmt --all
```

### Benchmarking
```bash
# Run benchmarks
cargo bench --bench benchmarks
```

### Running the Server
```bash
# Start dependencies
nats-server
redis-server

# Run the server
cargo run
```

## Prerequisites

Install required dependencies:
```bash
brew install nats-server redis flatbuffers
```

### Key Generation (First Time Setup)

Generate KAS EC private key:
```bash
openssl ecparam -genkey -name prime256v1 -noout -out recipient_private_key.pem
```

Validate the key:
```bash
openssl ec -in recipient_private_key.pem -text -noout
```

Generate self-signed TLS certificates (for development):
```bash
openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out fullchain.pem -days 365 -nodes -subj "/CN=localhost"
```

## Architecture

### Core Components

**Binary** (`src/bin/main.rs`):
- Multi-threaded WebSocket server with optional TLS
- NATS integration for pub/sub messaging
- Redis integration for caching encrypted content
- Policy enforcement through pluggable contracts
- Handles ECDH key agreement, NanoTDF rewrap operations, and event routing

**Library** (`src/lib.rs`):
- NanoTDF binary parser implementing OpenTDF specification
- Supports Remote and Embedded policy types
- ECDSA signature verification with multiple curves (secp256r1, secp384r1, secp521r1, secp256k1)
- AES-GCM symmetric encryption modes

### Message Protocol

Binary messages use a type-byte prefix:
- `0x01`: PublicKey - ECDH key exchange
- `0x02`: KasPublicKey - KAS public key response
- `0x03`: Rewrap - NanoTDF rewrap request
- `0x04`: RewrappedKey - Rewrapped key response
- `0x05`: Nats - NATS message passthrough
- `0x06`: Event - FlatBuffers event handling

### Policy Contracts

Pluggable access control contracts in `src/bin/contracts/`:
- **Simple ABAC** (`contract_simple_abac.rs`): Attribute-based access control
- **Geofence** (`geo_fence_contract.rs`): 3D location-based access (lat/lon/altitude)
- **Content Rating** (`content_rating.rs`): Age-gated content filtering with rating categories (violent, sexual, profane, substance, hate, harm, mature, bully)

Contracts are identified by unique SharedResource identifiers and enforce policy during rewrap operations.

### Event System

FlatBuffers-based event handling (schemas in `src/bin/schemas/`):
- **UserEvent**: Source-to-target user interactions with Redis retrieval
- **CacheEvent**: Store encrypted content in Redis with optional TTL and one-time access
- **RouteEvent**: Route events to specific user profiles via NATS subject `profile.<publicID>`

### Connection State

Each WebSocket connection maintains:
- Ephemeral ECDH shared secret with random salt
- JWT claims (subject/publicID and age verification)
- Bidirectional message channel for NATS subscription forwarding

### Cryptography

- **Key Agreement**: ECDH using P-256 (secp256r1) with custom x-coordinate extraction
- **Session Keys**: HKDF-SHA256 key derivation from shared secret
- **Symmetric Encryption**: AES-256-GCM for rewrapping data encryption keys (DEK)
- **TLS**: Minimum TLS 1.2, configurable certificate paths

## Configuration

Environment variables:
```bash
export PORT=8443
export TLS_CERT_PATH=/path/to/fullchain.pem        # Optional, disables TLS if not set
export TLS_KEY_PATH=/path/to/privkey.pem
export KAS_KEY_PATH=/path/to/recipient_private_key.pem
export NATS_URL=nats://localhost:4222
export NATS_SUBJECT=nanotdf.messages
export REDIS_URL=redis://localhost:6379
export ENABLE_TIMING_LOGS=true                     # Performance logging
export RUST_LOG=info                               # Logging level
```

## FlatBuffers Schema Compilation

If modifying schemas (typically not needed):
```bash
flatc --binary --rust idl/event.fbs
flatc --binary --rust idl/entity.fbs
flatc --binary --rust idl/metadata.fbs
```

Generated files are in `src/bin/schemas/`.

## Code Organization

- `src/lib.rs` - NanoTDF parser library
- `src/bin/main.rs` - WebSocket server binary
- `src/bin/contracts/` - Policy enforcement modules
- `src/bin/schemas/` - FlatBuffers generated code
- `benches/` - Performance benchmarks

## Security Notes

- Private keys (KAS, TLS) must never be committed to version control
- JWT signature validation is currently disabled for development - enable in production
- Self-signed certificates are for development only
- Apple App Site Association file (`apple-app-site-association.json`) is served at `/.well-known/apple-app-site-association`
