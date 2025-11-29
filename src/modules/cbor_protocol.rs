//! CBOR-based WebSocket protocol messages.
//!
//! This module defines the CBOR message types for the Arkavo WebSocket protocol.
//! All messages use type prefix `0x08` followed by CBOR-encoded payload.

use serde::{Deserialize, Serialize};

/// Message type prefix for CBOR-encoded messages.
pub const CBOR_MESSAGE_TYPE: u8 = 0x08;

/// Chain validation data included in rewrap requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainValidation {
    /// 32-byte chain session ID (hex-encoded in JSON, raw bytes in CBOR).
    #[serde(with = "hex_bytes")]
    pub session_id: Vec<u8>,

    /// Client-computed SHA256 of header bytes (DPoP binding).
    /// This binds the signature to the actual header content.
    #[serde(with = "serde_bytes")]
    pub header_hash: Vec<u8>,

    /// ECDSA signature over the signing message.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,

    /// Monotonically increasing nonce for replay prevention.
    pub nonce: u64,

    /// Signing algorithm: "ES256" (default), "ES384".
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_algorithm() -> String {
    "ES256".to_string()
}

/// Incoming CBOR messages from client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CborRequest {
    /// Key exchange request (client sends ephemeral public key).
    KeyExchange {
        /// SEC1-encoded P-256 public key (33 or 65 bytes).
        #[serde(with = "serde_bytes")]
        public_key: Vec<u8>,
    },

    /// Chain-validated rewrap request.
    ChainRewrap {
        /// NanoTDF header bytes.
        #[serde(with = "serde_bytes")]
        header: Vec<u8>,

        /// Chain validation data.
        chain: ChainValidation,
    },

    /// Media key request (for streaming).
    MediaKeyRequest {
        /// Playback session ID.
        session_id: String,

        /// User identifier.
        user_id: String,

        /// Asset identifier.
        asset_id: String,

        /// Optional segment number.
        #[serde(skip_serializing_if = "Option::is_none")]
        segment_index: Option<u32>,

        /// PEM-encoded client public key (for TDF3).
        #[serde(skip_serializing_if = "Option::is_none")]
        client_public_key: Option<String>,

        /// NanoTDF header bytes (for TDF3).
        #[serde(skip_serializing_if = "Option::is_none", with = "option_bytes")]
        nanotdf_header: Option<Vec<u8>>,

        /// Server Playback Context (for FairPlay).
        #[serde(skip_serializing_if = "Option::is_none", with = "option_bytes")]
        spc_data: Option<Vec<u8>>,

        /// Chain validation data.
        chain: ChainValidation,
    },

    /// User event.
    UserEvent {
        source_type: EntityType,
        target_type: EntityType,
        #[serde(with = "serde_bytes")]
        source_id: Vec<u8>,
        #[serde(with = "serde_bytes")]
        target_id: Vec<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attribute_types: Option<Vec<AttributeType>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        entity_type: Option<EntityType>,
    },

    /// Cache event (store TDF on server).
    CacheEvent {
        #[serde(with = "serde_bytes")]
        target_id: Vec<u8>,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        one_time_access: Option<bool>,
    },

    /// Route event (forward to specific profile).
    RouteEvent {
        target_type: EntityType,
        #[serde(with = "serde_bytes")]
        target_id: Vec<u8>,
        source_type: EntityType,
        #[serde(with = "serde_bytes")]
        source_id: Vec<u8>,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attribute_type: Option<AttributeType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        entity_type: Option<EntityType>,
    },
}

/// Outgoing CBOR messages to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CborResponse {
    /// Key exchange response.
    KeyExchangeResponse {
        /// SEC1-encoded KAS public key.
        #[serde(with = "serde_bytes")]
        kas_public_key: Vec<u8>,

        /// Random salt for session key derivation.
        #[serde(with = "serde_bytes")]
        session_salt: Vec<u8>,
    },

    /// Rewrapped key response.
    RewrappedKey {
        /// TDF ephemeral public key (33 bytes, compressed).
        #[serde(with = "serde_bytes")]
        ephemeral_key: Vec<u8>,

        /// AES-GCM nonce (12 bytes).
        #[serde(with = "serde_bytes")]
        nonce: Vec<u8>,

        /// Encrypted DEK (32 bytes + 16 byte auth tag).
        #[serde(with = "serde_bytes")]
        wrapped_dek: Vec<u8>,
    },

    /// Media key response.
    MediaKeyResponse {
        /// PEM-encoded session public key.
        session_public_key: String,

        /// Nonce + encrypted DEK (base64 for compatibility).
        wrapped_key: String,

        /// "success" or "denied".
        status: String,

        /// Optional metadata.
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata: Option<serde_json::Value>,
    },

    /// Error response.
    Error {
        /// Error code (e.g., "policy_denied", "authentication_failed").
        code: String,

        /// Human-readable error message.
        message: String,

        /// Optional structured details.
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<serde_json::Value>,
    },
}

/// Entity types (matches FlatBuffer schema).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Unused,
    StreamProfile,
    AccountProfile,
    Server,
}

/// Attribute types (matches FlatBuffer schema).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttributeType {
    Unused,
    Time,
    Location,
}

impl CborRequest {
    /// Decode a CBOR request from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, CborError> {
        ciborium::de::from_reader(data).map_err(|e| CborError::DecodeError(e.to_string()))
    }
}

impl CborResponse {
    /// Encode a CBOR response to bytes.
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|e| CborError::EncodeError(e.to_string()))?;
        Ok(bytes)
    }

    /// Create an error response.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        CborResponse::Error {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    /// Create an error response with details.
    #[allow(dead_code)]
    pub fn error_with_details(
        code: impl Into<String>,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        CborResponse::Error {
            code: code.into(),
            message: message.into(),
            details: Some(details),
        }
    }
}

/// CBOR protocol errors.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum CborError {
    #[error("Failed to decode CBOR: {0}")]
    DecodeError(String),

    #[error("Failed to encode CBOR: {0}")]
    EncodeError(String),

    #[error("Invalid message type")]
    InvalidMessageType,

    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Helper module for hex-encoded bytes in serde.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // In CBOR, serialize as raw bytes; in JSON would be hex string
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Accept either raw bytes (CBOR) or hex string (JSON)
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BytesOrHex {
            Bytes(#[serde(with = "serde_bytes")] Vec<u8>),
            Hex(String),
        }

        match BytesOrHex::deserialize(deserializer)? {
            BytesOrHex::Bytes(b) => Ok(b),
            BytesOrHex::Hex(s) => {
                hex::decode(&s).map_err(|e| serde::de::Error::custom(format!("invalid hex: {}", e)))
            }
        }
    }
}

/// Helper module for optional bytes fields.
mod option_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_bytes(bytes),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<serde_bytes::ByteBuf>::deserialize(deserializer)
            .map(|opt| opt.map(|bb| bb.into_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_rewrap_roundtrip() {
        let header = vec![0x18, 0x01, 0x00, 0x01];
        // Compute header_hash as SHA256 of header
        let header_hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&header).to_vec()
        };

        let request = CborRequest::ChainRewrap {
            header: header.clone(),
            chain: ChainValidation {
                session_id: vec![0xAB; 32],
                header_hash: header_hash.clone(),
                signature: vec![0xCD; 64],
                nonce: 12345,
                algorithm: "ES256".to_string(),
            },
        };

        // Encode
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&request, &mut encoded).unwrap();

        // Decode
        let decoded: CborRequest = ciborium::de::from_reader(&encoded[..]).unwrap();

        match decoded {
            CborRequest::ChainRewrap { header: h, chain } => {
                assert_eq!(h, header);
                assert_eq!(chain.session_id.len(), 32);
                assert_eq!(chain.header_hash.len(), 32);
                assert_eq!(chain.header_hash, header_hash);
                assert_eq!(chain.nonce, 12345);
                assert_eq!(chain.algorithm, "ES256");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_error_response() {
        let response = CborResponse::error("policy_denied", "Session expired");
        let encoded = response.encode().unwrap();

        let decoded: CborResponse = ciborium::de::from_reader(&encoded[..]).unwrap();
        match decoded {
            CborResponse::Error { code, message, .. } => {
                assert_eq!(code, "policy_denied");
                assert_eq!(message, "Session expired");
            }
            _ => panic!("Wrong response type"),
        }
    }

    #[test]
    fn test_rewrapped_key_response() {
        let response = CborResponse::RewrappedKey {
            ephemeral_key: vec![0x02; 33],
            nonce: vec![0x00; 12],
            wrapped_dek: vec![0xFF; 48],
        };

        let encoded = response.encode().unwrap();
        let decoded: CborResponse = ciborium::de::from_reader(&encoded[..]).unwrap();

        match decoded {
            CborResponse::RewrappedKey {
                ephemeral_key,
                nonce,
                wrapped_dek,
            } => {
                assert_eq!(ephemeral_key.len(), 33);
                assert_eq!(nonce.len(), 12);
                assert_eq!(wrapped_dek.len(), 48);
            }
            _ => panic!("Wrong response type"),
        }
    }
}
