//! NTDF-RTMP Protocol Implementation
//!
//! Embeds NanoTDF encryption into RTMP streams per the NTDF-RTMP specification.
//! This module provides secure real-time streaming with end-to-end encryption
//! where intermediate relay servers cannot access plaintext media.
//!
//! ## Architecture
//!
//! - `server.rs` - TCP listener and connection handling
//! - `session.rs` - Per-connection NTDF-RTMP state machine
//! - `manifest.rs` - onTDFManifest AMF parsing and Redis caching
//! - `encryption.rs` - FLV payload encryption/decryption using AES-256-GCM

// Allow unused code during POC development phase
#![allow(dead_code)]

pub mod encryption;
pub mod manifest;
pub mod registry;
pub mod server;
pub mod session;
pub mod stream_events;

pub use server::RtmpServer;
pub use stream_events::StreamEventBroadcaster;

/// RTMP default port
pub const DEFAULT_RTMP_PORT: u16 = 1935;

/// Redis key prefix for RTMP manifests
pub const REDIS_MANIFEST_PREFIX: &str = "rtmp:manifest:";

/// Manifest TTL in seconds (1 hour)
pub const MANIFEST_TTL_SECONDS: u64 = 3600;
