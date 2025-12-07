//! Stream Event Broadcasting
//!
//! Handles creating and publishing CBOR-encoded stream lifecycle events.
//! Events are broadcast via NATS to connected WebSocket clients.

use async_nats::Client as NatsClient;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// CBOR message type prefix
pub const CBOR_MESSAGE_TYPE: u8 = 0x08;

/// Stream event - server-to-client notification of stream lifecycle changes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    /// A new stream has started
    StreamStarted {
        /// Stream key (e.g., "live/abc123")
        stream_key: String,
        /// Full RTMP URL for playback
        rtmp_url: String,
        /// Base64-encoded NanoTDF manifest header (for NTDF streams)
        #[serde(skip_serializing_if = "Option::is_none")]
        manifest_header: Option<String>,
        /// Optional stream title
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        /// Timestamp in milliseconds since Unix epoch
        timestamp: u64,
    },
    /// An existing stream has stopped
    StreamStopped {
        /// Stream key that stopped
        stream_key: String,
        /// Timestamp in milliseconds since Unix epoch
        timestamp: u64,
    },
}

impl StreamEvent {
    /// Create a stream started event
    pub fn started(
        stream_key: impl Into<String>,
        rtmp_url: impl Into<String>,
        manifest_header: Option<String>,
        title: Option<String>,
    ) -> Self {
        StreamEvent::StreamStarted {
            stream_key: stream_key.into(),
            rtmp_url: rtmp_url.into(),
            manifest_header,
            title,
            timestamp: current_timestamp(),
        }
    }

    /// Create a stream stopped event
    pub fn stopped(stream_key: impl Into<String>) -> Self {
        StreamEvent::StreamStopped {
            stream_key: stream_key.into(),
            timestamp: current_timestamp(),
        }
    }

    /// Encode the event as a CBOR message with type prefix
    pub fn encode(&self) -> Result<Vec<u8>, StreamEventError> {
        let mut bytes = Vec::new();
        bytes.push(CBOR_MESSAGE_TYPE);
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|e| StreamEventError::EncodeError(e.to_string()))?;
        Ok(bytes)
    }

    /// Decode a stream event from CBOR bytes (without type prefix)
    #[allow(dead_code)]
    pub fn decode(data: &[u8]) -> Result<Self, StreamEventError> {
        ciborium::de::from_reader(data).map_err(|e| StreamEventError::DecodeError(e.to_string()))
    }
}

/// Get current timestamp in milliseconds since Unix epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Stream event errors
#[derive(Debug, thiserror::Error)]
pub enum StreamEventError {
    #[error("Failed to encode stream event: {0}")]
    EncodeError(String),

    #[error("Failed to decode stream event: {0}")]
    DecodeError(String),

    #[error("Failed to publish stream event: {0}")]
    PublishError(String),
}

/// Stream event broadcaster
///
/// Handles publishing stream lifecycle events to NATS for distribution
/// to connected WebSocket clients.
#[derive(Clone)]
pub struct StreamEventBroadcaster {
    nats_client: Option<NatsClient>,
    subject: String,
    rtmp_base_url: String,
}

impl StreamEventBroadcaster {
    /// Create a new broadcaster
    pub fn new(nats_client: Option<NatsClient>, subject: String, rtmp_base_url: String) -> Self {
        Self {
            nats_client,
            subject,
            rtmp_base_url,
        }
    }

    /// Broadcast stream started event
    pub async fn stream_started(
        &self,
        stream_key: &str,
        manifest_header: Option<&str>,
        title: Option<&str>,
    ) {
        let rtmp_url = format!("{}/{}", self.rtmp_base_url, stream_key);
        let event = StreamEvent::started(
            stream_key,
            rtmp_url,
            manifest_header.map(|s| s.to_string()),
            title.map(|s| s.to_string()),
        );

        self.publish_event(&event, "stream_started", stream_key)
            .await;
    }

    /// Broadcast stream stopped event
    pub async fn stream_stopped(&self, stream_key: &str) {
        let event = StreamEvent::stopped(stream_key);
        self.publish_event(&event, "stream_stopped", stream_key)
            .await;
    }

    /// Publish an event to NATS
    async fn publish_event(&self, event: &StreamEvent, event_type: &str, stream_key: &str) {
        if let Some(ref client) = self.nats_client {
            match event.encode() {
                Ok(message) => {
                    if let Err(e) = client.publish(self.subject.clone(), message.into()).await {
                        log::error!(
                            "Failed to publish {} event for {}: {}",
                            event_type,
                            stream_key,
                            e
                        );
                    } else {
                        log::info!("Published {} event for {}", event_type, stream_key);
                    }
                }
                Err(e) => {
                    log::error!(
                        "Failed to encode {} event for {}: {}",
                        event_type,
                        stream_key,
                        e
                    );
                }
            }
        } else {
            log::debug!(
                "NATS not available, skipping {} event for {}",
                event_type,
                stream_key
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_started_encode() {
        let event = StreamEvent::started(
            "live/test123",
            "rtmp://100.arkavo.net/live/test123",
            Some("base64header==".to_string()),
            Some("My Stream".to_string()),
        );

        let encoded = event.encode().unwrap();
        assert_eq!(encoded[0], CBOR_MESSAGE_TYPE);
        assert!(encoded.len() > 1);

        // Decode and verify
        let decoded = StreamEvent::decode(&encoded[1..]).unwrap();
        match decoded {
            StreamEvent::StreamStarted {
                stream_key,
                rtmp_url,
                manifest_header,
                title,
                ..
            } => {
                assert_eq!(stream_key, "live/test123");
                assert_eq!(rtmp_url, "rtmp://100.arkavo.net/live/test123");
                assert_eq!(manifest_header, Some("base64header==".to_string()));
                assert_eq!(title, Some("My Stream".to_string()));
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_stream_stopped_encode() {
        let event = StreamEvent::stopped("live/test123");

        let encoded = event.encode().unwrap();
        assert_eq!(encoded[0], CBOR_MESSAGE_TYPE);

        let decoded = StreamEvent::decode(&encoded[1..]).unwrap();
        match decoded {
            StreamEvent::StreamStopped { stream_key, .. } => {
                assert_eq!(stream_key, "live/test123");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_stream_started_without_optional_fields() {
        let event = StreamEvent::started(
            "live/test123",
            "rtmp://100.arkavo.net/live/test123",
            None,
            None,
        );

        let encoded = event.encode().unwrap();
        let decoded = StreamEvent::decode(&encoded[1..]).unwrap();

        match decoded {
            StreamEvent::StreamStarted {
                manifest_header,
                title,
                ..
            } => {
                assert_eq!(manifest_header, None);
                assert_eq!(title, None);
            }
            _ => panic!("Wrong event type"),
        }
    }
}
