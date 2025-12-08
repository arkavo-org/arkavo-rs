//! Stream Registry for Publisher-Subscriber Linking
//!
//! Provides a shared registry that allows subscribers to connect to active
//! publisher streams and receive relayed frames.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use super::session::RelayFrame;

/// Broadcast channel capacity for frame relay
const RELAY_CHANNEL_CAPACITY: usize = 256;

/// Active stream information
pub struct ActiveStream {
    /// Stream key (e.g., "live/creator")
    pub stream_key: String,
    /// Broadcast sender for relaying frames to subscribers
    pub frame_sender: broadcast::Sender<RelayFrame>,
    /// Cached metadata for late joiners (video sequence header, audio sequence header)
    pub video_sequence_header: Option<Vec<u8>>,
    pub audio_sequence_header: Option<Vec<u8>>,
}

impl ActiveStream {
    pub fn new(stream_key: String) -> Self {
        let (frame_sender, _) = broadcast::channel(RELAY_CHANNEL_CAPACITY);
        ActiveStream {
            stream_key,
            frame_sender,
            video_sequence_header: None,
            audio_sequence_header: None,
        }
    }
}

/// Shared registry of active streams
///
/// Thread-safe registry that maps stream keys to active publisher streams.
/// Subscribers use this to find and connect to publishers.
#[derive(Clone)]
pub struct StreamRegistry {
    streams: Arc<RwLock<HashMap<String, Arc<RwLock<ActiveStream>>>>>,
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamRegistry {
    pub fn new() -> Self {
        StreamRegistry {
            streams: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new publisher stream
    ///
    /// Returns the broadcast sender for the publisher to send frames through.
    pub async fn register_publisher(&self, stream_key: &str) -> broadcast::Sender<RelayFrame> {
        let mut streams = self.streams.write().await;

        // Remove any existing stream with the same key (publisher reconnect)
        streams.remove(stream_key);

        let active_stream = ActiveStream::new(stream_key.to_string());
        let sender = active_stream.frame_sender.clone();

        streams.insert(stream_key.to_string(), Arc::new(RwLock::new(active_stream)));

        log::info!("Publisher registered: {}", stream_key);
        sender
    }

    /// Unregister a publisher stream
    pub async fn unregister_publisher(&self, stream_key: &str) {
        let mut streams = self.streams.write().await;
        if streams.remove(stream_key).is_some() {
            log::info!("Publisher unregistered: {}", stream_key);
        }
    }

    /// Subscribe to a stream
    ///
    /// Returns a receiver for frames if the stream exists, None otherwise.
    pub async fn subscribe(&self, stream_key: &str) -> Option<(broadcast::Receiver<RelayFrame>, Option<Vec<u8>>, Option<Vec<u8>>)> {
        let streams = self.streams.read().await;

        if let Some(stream) = streams.get(stream_key) {
            let stream = stream.read().await;
            let receiver = stream.frame_sender.subscribe();
            let video_header = stream.video_sequence_header.clone();
            let audio_header = stream.audio_sequence_header.clone();

            log::info!("Subscriber connected to: {}", stream_key);
            Some((receiver, video_header, audio_header))
        } else {
            log::debug!("Stream not found for subscription: {}", stream_key);
            None
        }
    }

    /// Update video sequence header for late joiners
    pub async fn set_video_sequence_header(&self, stream_key: &str, header: Vec<u8>) {
        let streams = self.streams.read().await;
        if let Some(stream) = streams.get(stream_key) {
            let mut stream = stream.write().await;
            stream.video_sequence_header = Some(header);
        }
    }

    /// Update audio sequence header for late joiners
    pub async fn set_audio_sequence_header(&self, stream_key: &str, header: Vec<u8>) {
        let streams = self.streams.read().await;
        if let Some(stream) = streams.get(stream_key) {
            let mut stream = stream.write().await;
            stream.audio_sequence_header = Some(header);
        }
    }

    /// Check if a stream is currently active
    pub async fn is_stream_active(&self, stream_key: &str) -> bool {
        let streams = self.streams.read().await;
        streams.contains_key(stream_key)
    }

    /// Get count of active streams
    pub async fn active_stream_count(&self) -> usize {
        let streams = self.streams.read().await;
        streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::rtmp::session::FrameType;

    #[tokio::test]
    async fn test_registry_publisher_subscriber() {
        let registry = StreamRegistry::new();

        // Register publisher
        let sender = registry.register_publisher("live/test").await;

        // Subscribe
        let result = registry.subscribe("live/test").await;
        assert!(result.is_some());

        let (mut receiver, _, _) = result.unwrap();

        // Send a frame
        let frame = RelayFrame {
            frame_type: FrameType::Video,
            timestamp: 1000,
            data: vec![1, 2, 3, 4],
        };

        sender.send(frame.clone()).unwrap();

        // Receive the frame
        let received = receiver.recv().await.unwrap();
        assert_eq!(received.timestamp, 1000);
        assert_eq!(received.data, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_registry_stream_not_found() {
        let registry = StreamRegistry::new();

        let result = registry.subscribe("nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_registry_unregister() {
        let registry = StreamRegistry::new();

        registry.register_publisher("live/test").await;
        assert!(registry.is_stream_active("live/test").await);

        registry.unregister_publisher("live/test").await;
        assert!(!registry.is_stream_active("live/test").await);
    }
}
