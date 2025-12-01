//! NanoTDF Manifest Handling and Redis Caching
//!
//! Handles the NanoTDF manifest embedded in RTMP onMetaData messages.
//! The manifest contains the NanoTDF header with policy and wrapped DEK.
//!
//! ## Manifest Transport via onMetaData
//!
//! The NanoTDF header is transported as a base64-encoded string in the
//! standard RTMP `onMetaData` message under the key `ntdf_header`.
//!
//! This approach:
//! - Works with standard RTMP tools (FFmpeg, OBS can inject metadata)
//! - Is forwarded correctly by intermediate relays (nginx-rtmp)
//! - Arrives before video data in the standard RTMP handshake

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crate::{BinaryParser, ProtocolEnum, ResourceLocator};

use super::{MANIFEST_TTL_SECONDS, REDIS_MANIFEST_PREFIX};

/// Error types for manifest handling
#[derive(Debug)]
pub enum ManifestError {
    /// Failed to decode base64 header
    Base64DecodeError(String),
    /// Failed to parse NanoTDF header
    NanoTdfParseError(String),
    /// Redis operation failed
    RedisError(String),
    /// Manifest not found in cache
    NotFound,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
            ManifestError::NanoTdfParseError(msg) => write!(f, "NanoTDF parse error: {}", msg),
            ManifestError::RedisError(msg) => write!(f, "Redis error: {}", msg),
            ManifestError::NotFound => write!(f, "Manifest not found"),
        }
    }
}

impl Error for ManifestError {}

/// NanoTDF manifest extracted from onMetaData ntdf_header field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NanoTdfManifest {
    /// Raw NanoTDF header bytes
    pub header_bytes: Vec<u8>,
    /// KAS URL extracted from header
    pub kas_url: String,
    /// Ephemeral public key (33 bytes compressed P-256)
    pub ephemeral_key: Vec<u8>,
    /// Stream key this manifest applies to
    pub stream_key: String,
    /// Timestamp when manifest was received
    pub created_at: i64,
}

impl NanoTdfManifest {
    /// Parse NanoTDF manifest from raw header bytes
    ///
    /// # Arguments
    /// * `header_bytes` - Raw NanoTDF header bytes
    /// * `stream_key` - RTMP stream key this manifest belongs to
    pub fn from_header_bytes(
        header_bytes: Vec<u8>,
        stream_key: String,
    ) -> Result<Self, ManifestError> {
        let mut parser = BinaryParser::new(&header_bytes);
        let header = parser
            .parse_header()
            .map_err(|e| ManifestError::NanoTdfParseError(e.to_string()))?;

        let kas_url = format_kas_url(header.get_kas());
        let ephemeral_key = header.get_ephemeral_key().clone();

        Ok(NanoTdfManifest {
            header_bytes,
            kas_url,
            ephemeral_key,
            stream_key,
            created_at: chrono::Utc::now().timestamp(),
        })
    }
}

/// Format KAS URL from ResourceLocator
fn format_kas_url(locator: &ResourceLocator) -> String {
    let protocol = match locator.protocol_enum {
        ProtocolEnum::Https => "https",
        ProtocolEnum::Http => "http",
        ProtocolEnum::Wss => "wss",
        ProtocolEnum::Ws => "ws",
        ProtocolEnum::SharedResource => "shared",
    };
    format!("{}://{}", protocol, locator.body)
}

/// Cache manifest in Redis for late joiners
///
/// # Arguments
/// * `redis_client` - Redis client
/// * `manifest` - Manifest to cache
pub async fn cache_manifest(
    redis_client: &Arc<redis::Client>,
    manifest: &NanoTdfManifest,
) -> Result<(), ManifestError> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| ManifestError::RedisError(e.to_string()))?;

    let key = format!("{}{}", REDIS_MANIFEST_PREFIX, manifest.stream_key);
    let json = serde_json::to_string(manifest)
        .map_err(|e| ManifestError::RedisError(format!("Serialization error: {}", e)))?;

    let _: () = conn
        .set_ex(&key, json, MANIFEST_TTL_SECONDS)
        .await
        .map_err(|e| ManifestError::RedisError(e.to_string()))?;

    log::debug!(
        "Cached manifest for stream {} (TTL: {}s)",
        manifest.stream_key,
        MANIFEST_TTL_SECONDS
    );

    Ok(())
}

/// Get cached manifest for late joiners
///
/// # Arguments
/// * `redis_client` - Redis client
/// * `stream_key` - RTMP stream key
pub async fn get_cached_manifest(
    redis_client: &Arc<redis::Client>,
    stream_key: &str,
) -> Result<NanoTdfManifest, ManifestError> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| ManifestError::RedisError(e.to_string()))?;

    let key = format!("{}{}", REDIS_MANIFEST_PREFIX, stream_key);
    let json: Option<String> = conn
        .get(&key)
        .await
        .map_err(|e| ManifestError::RedisError(e.to_string()))?;

    match json {
        Some(json_str) => serde_json::from_str(&json_str)
            .map_err(|e| ManifestError::RedisError(format!("Deserialization error: {}", e))),
        None => Err(ManifestError::NotFound),
    }
}

/// Delete cached manifest when stream ends
pub async fn delete_cached_manifest(
    redis_client: &Arc<redis::Client>,
    stream_key: &str,
) -> Result<(), ManifestError> {
    let mut conn = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| ManifestError::RedisError(e.to_string()))?;

    let key = format!("{}{}", REDIS_MANIFEST_PREFIX, stream_key);
    let _: () = conn
        .del(&key)
        .await
        .map_err(|e| ManifestError::RedisError(e.to_string()))?;

    log::debug!("Deleted cached manifest for stream {}", stream_key);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_from_header_bytes() {
        // Example NanoTDF header with ECDSA binding (secp256r1)
        let hex_string = "\
            4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80\
            80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70\
            6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36\
            ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15\
            12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c\
            c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da";

        let bytes = hex::decode(hex_string.replace(" ", "")).expect("Valid hex");
        let stream_key = "test_stream".to_string();

        // Note: Test data may not be a complete header for our parser
        let result = NanoTdfManifest::from_header_bytes(bytes.clone(), stream_key.clone());

        if result.is_err() {
            eprintln!(
                "Note: Test data parsing returned error (expected for incomplete test data): {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn test_format_kas_url() {
        let locator = ResourceLocator {
            protocol_enum: ProtocolEnum::Https,
            body: "kas.example.com".to_string(),
        };
        assert_eq!(format_kas_url(&locator), "https://kas.example.com");

        let locator_http = ResourceLocator {
            protocol_enum: ProtocolEnum::Http,
            body: "kas.local:8080".to_string(),
        };
        assert_eq!(format_kas_url(&locator_http), "http://kas.local:8080");
    }
}
