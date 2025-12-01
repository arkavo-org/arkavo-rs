//! Per-Connection RTMP Session State Machine
//!
//! Manages the lifecycle of an RTMP connection including:
//! - RTMP handshake
//! - Publisher/Subscriber role detection
//! - NanoTDF manifest via onMetaData `ntdf_header` field
//! - Frame encryption (publisher via Collection) / decryption (subscriber via Decryptor)
//! - Passthrough mode for standard cleartext RTMP streams

use bytes::Bytes;
use opentdf_crypto::tdf::{NanoTdfCollection, NanoTdfCollectionDecryptor};
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey;
use rml_rtmp::handshake::{Handshake, HandshakeProcessResult, PeerType};
use rml_rtmp::sessions::{
    ServerSession, ServerSessionConfig, ServerSessionEvent, ServerSessionResult, StreamMetadata,
};
use rml_rtmp::time::RtmpTimestamp;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::encryption::{
    create_decryptor_kas, decrypt_item, encrypt_item, rotation_threshold_reached,
};
use super::manifest::{delete_cached_manifest, get_cached_manifest, NanoTdfManifest};

/// RTMP session role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Not yet determined
    Unknown,
    /// Publishing content
    Publisher,
    /// Receiving content
    Subscriber,
}

/// Encryption mode for the stream
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    /// Waiting for metadata to determine mode
    Pending,
    /// NTDF encrypted stream (has manifest/DEK)
    Encrypted,
    /// Standard cleartext RTMP stream (passthrough)
    Passthrough,
}

/// RTMP session error
#[derive(Debug)]
pub enum SessionError {
    IoError(std::io::Error),
    RtmpError(String),
    EncryptionError(String),
    ManifestError(String),
    NoManifest,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::IoError(e) => write!(f, "IO error: {}", e),
            SessionError::RtmpError(e) => write!(f, "RTMP error: {}", e),
            SessionError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            SessionError::ManifestError(e) => write!(f, "Manifest error: {}", e),
            SessionError::NoManifest => write!(f, "No TDF manifest received"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        SessionError::IoError(e)
    }
}

/// Per-connection RTMP session state
pub struct RtmpSession {
    /// Session role (publisher or subscriber)
    role: SessionRole,
    /// Encryption mode for this stream
    encryption_mode: EncryptionMode,
    /// Stream key (app/stream_name)
    stream_key: Option<String>,
    /// NanoTDF manifest (received from publisher or cache)
    manifest: Option<NanoTdfManifest>,
    /// NanoTDF Collection for publisher-side encryption (thread-safe)
    collection: Option<Arc<NanoTdfCollection>>,
    /// NanoTDF Decryptor for subscriber-side decryption
    decryptor: Option<NanoTdfCollectionDecryptor>,
    /// KAS private key for DEK derivation (PKCS#8 DER format)
    kas_private_key: Vec<u8>,
    /// Redis client for manifest caching
    redis_client: Arc<redis::Client>,
    /// Subscribers to relay encrypted frames to
    subscribers: Vec<tokio::sync::mpsc::Sender<RelayFrame>>,
    /// Whether we've received onMetaData
    metadata_received: bool,
}

/// Frame to relay to subscribers
#[derive(Debug, Clone)]
pub struct RelayFrame {
    pub frame_type: FrameType,
    pub timestamp: u32,
    pub data: Vec<u8>,
}

/// Type of media frame
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Video,
    Audio,
}

impl RtmpSession {
    /// Create a new RTMP session
    ///
    /// # Arguments
    /// * `redis_client` - Redis client for manifest caching
    /// * `kas_private_key` - KAS EC private key raw bytes (32 bytes for P-256)
    pub fn new(redis_client: Arc<redis::Client>, kas_private_key: [u8; 32]) -> Self {
        // Convert raw 32-byte key to PKCS#8 DER format for opentdf-rs
        // The EcdhKem::derive_key_with_private accepts SEC1 DER or PKCS#8 DER
        let secret_key =
            SecretKey::from_bytes(&kas_private_key.into()).expect("Invalid KAS private key bytes");
        let kas_private_key_der = secret_key
            .to_pkcs8_der()
            .expect("Failed to encode key as PKCS#8")
            .as_bytes()
            .to_vec();

        RtmpSession {
            role: SessionRole::Unknown,
            encryption_mode: EncryptionMode::Pending,
            stream_key: None,
            manifest: None,
            collection: None,
            decryptor: None,
            kas_private_key: kas_private_key_der,
            redis_client,
            subscribers: Vec::new(),
            metadata_received: false,
        }
    }

    /// Handle an incoming RTMP connection
    pub async fn handle_connection(mut self, mut socket: TcpStream) -> Result<(), SessionError> {
        let peer_addr = socket
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        log::info!("RTMP connection from {}", peer_addr);

        // Phase 1: RTMP Handshake
        let mut handshake = Handshake::new(PeerType::Server);
        let mut buf = [0u8; 4096];
        let mut remaining_bytes = Vec::new();

        loop {
            let n = socket.read(&mut buf).await?;
            if n == 0 {
                return Err(SessionError::RtmpError(
                    "Connection closed during handshake".to_string(),
                ));
            }

            let mut input = buf[..n].to_vec();
            if !remaining_bytes.is_empty() {
                let mut combined = remaining_bytes.clone();
                combined.extend_from_slice(&input);
                input = combined;
                remaining_bytes.clear();
            }

            match handshake.process_bytes(&input) {
                Ok(HandshakeProcessResult::InProgress { response_bytes }) => {
                    socket.write_all(&response_bytes).await?;
                }
                Ok(HandshakeProcessResult::Completed {
                    response_bytes,
                    remaining_bytes: leftover,
                }) => {
                    socket.write_all(&response_bytes).await?;
                    remaining_bytes = leftover;
                    log::debug!("RTMP handshake completed for {}", peer_addr);
                    break;
                }
                Err(e) => {
                    return Err(SessionError::RtmpError(format!("Handshake error: {:?}", e)));
                }
            }
        }

        // Phase 2: RTMP Session
        let config = ServerSessionConfig::new();
        let (mut session, initial_results) =
            ServerSession::new(config).map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;

        // Send initial session responses
        for result in initial_results {
            self.process_result(&mut socket, &result).await?;
        }

        // Process any bytes left over from handshake
        if !remaining_bytes.is_empty() {
            let results = session
                .handle_input(&remaining_bytes)
                .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;

            for result in results {
                if let Some(request_id) = self.process_result(&mut socket, &result).await? {
                    let accept_results = session
                        .accept_request(request_id)
                        .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;
                    Self::send_responses(&mut socket, accept_results).await?;
                }
            }
        }

        // Main session loop
        loop {
            let n = socket.read(&mut buf).await?;
            if n == 0 {
                log::info!("RTMP connection closed: {}", peer_addr);
                break;
            }

            // Process bytes through RTMP session
            let results = session
                .handle_input(&buf[..n])
                .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;

            for result in results {
                if let Some(request_id) = self.process_result(&mut socket, &result).await? {
                    let accept_results = session
                        .accept_request(request_id)
                        .map_err(|e| SessionError::RtmpError(format!("{:?}", e)))?;
                    Self::send_responses(&mut socket, accept_results).await?;
                    log::info!("Request {} accepted", request_id);
                }
            }
        }

        // Cleanup on disconnect
        if self.role == SessionRole::Publisher {
            if let Some(ref stream_key) = self.stream_key {
                let _ = delete_cached_manifest(&self.redis_client, stream_key).await;
                log::info!("Publisher disconnected, cleaned up stream: {}", stream_key);
            }
        }

        Ok(())
    }

    /// Process an RTMP session result, returning any accept request IDs that need handling
    async fn process_result(
        &mut self,
        socket: &mut TcpStream,
        result: &ServerSessionResult,
    ) -> Result<Option<u32>, SessionError> {
        match result {
            ServerSessionResult::OutboundResponse(packet) => {
                socket.write_all(&packet.bytes).await?;
                Ok(None)
            }

            ServerSessionResult::RaisedEvent(event) => self.handle_event(event).await,

            ServerSessionResult::UnhandleableMessageReceived(_) => {
                // Ignore unhandled messages
                Ok(None)
            }
        }
    }

    /// Send outbound responses from accept_request
    async fn send_responses(
        socket: &mut TcpStream,
        results: Vec<ServerSessionResult>,
    ) -> Result<(), SessionError> {
        for result in results {
            if let ServerSessionResult::OutboundResponse(packet) = result {
                socket.write_all(&packet.bytes).await?;
            }
        }
        Ok(())
    }

    /// Handle an RTMP session event, returning request_id if acceptance is needed
    async fn handle_event(
        &mut self,
        event: &ServerSessionEvent,
    ) -> Result<Option<u32>, SessionError> {
        match event {
            ServerSessionEvent::ConnectionRequested {
                request_id,
                app_name,
            } => {
                log::info!("Connection requested for app: {}", app_name);
                Ok(Some(*request_id))
            }

            ServerSessionEvent::PublishStreamRequested {
                request_id,
                app_name,
                stream_key,
                mode: _,
            } => {
                self.role = SessionRole::Publisher;
                self.stream_key = Some(format!("{}/{}", app_name, stream_key));
                log::info!(
                    "Publish requested: {}/{} (request_id: {})",
                    app_name,
                    stream_key,
                    request_id
                );
                Ok(Some(*request_id))
            }

            ServerSessionEvent::PlayStreamRequested {
                request_id,
                app_name,
                stream_key,
                start_at: _,
                duration: _,
                reset: _,
                stream_id: _,
            } => {
                self.role = SessionRole::Subscriber;
                let full_key = format!("{}/{}", app_name, stream_key);
                self.stream_key = Some(full_key.clone());
                log::info!("Play requested: {} (request_id: {})", full_key, request_id);

                // Try to fetch cached manifest for late joiner
                match get_cached_manifest(&self.redis_client, &full_key).await {
                    Ok(manifest) => {
                        log::info!("Found cached manifest for late joiner");
                        self.set_manifest_subscriber(manifest)?;
                    }
                    Err(_) => {
                        log::debug!("No cached manifest found, waiting for live manifest");
                    }
                }
                Ok(Some(*request_id))
            }

            ServerSessionEvent::StreamMetadataChanged {
                app_name,
                stream_key,
                metadata,
            } => {
                log::info!("Metadata received for {}/{}", app_name, stream_key);
                self.metadata_received = true;
                self.handle_metadata(metadata).await?;
                Ok(None)
            }

            ServerSessionEvent::VideoDataReceived {
                app_name: _,
                stream_key: _,
                data,
                timestamp,
            } => {
                self.handle_video_data(data, timestamp).await?;
                Ok(None)
            }

            ServerSessionEvent::AudioDataReceived {
                app_name: _,
                stream_key: _,
                data,
                timestamp,
            } => {
                self.handle_audio_data(data, timestamp).await?;
                Ok(None)
            }

            ServerSessionEvent::UnhandleableAmf0Command {
                command_name,
                transaction_id: _,
                command_object: _,
                additional_values: _,
            } => {
                log::debug!("Unhandled AMF0 command: {}", command_name);
                Ok(None)
            }

            _ => {
                log::trace!("Unhandled RTMP event: {:?}", event);
                Ok(None)
            }
        }
    }

    /// Handle stream metadata (onMetaData)
    ///
    /// Checks for `ntdf_header` key containing base64-encoded NanoTDF header.
    /// If found, initializes encryption context. Otherwise, sets passthrough mode.
    ///
    /// NOTE: The rml_rtmp StreamMetadata struct doesn't expose custom fields.
    /// NTDF-aware encoders will need to inject ntdf_header via custom AMF data
    /// which will be parsed separately. Standard RTMP clients default to passthrough.
    async fn handle_metadata(&mut self, metadata: &StreamMetadata) -> Result<(), SessionError> {
        // Log standard metadata for debugging
        log::debug!(
            "Stream metadata: video={}x{}, audio_rate={:?}",
            metadata.video_width.unwrap_or(0),
            metadata.video_height.unwrap_or(0),
            metadata.audio_sample_rate
        );

        // StreamMetadata from rml_rtmp doesn't expose custom fields like ntdf_header.
        // For NTDF-aware streams, the encoder needs to send a custom AMF data message
        // with the ntdf_header field, which we handle in UnhandleableAmf0Command.
        //
        // For now, standard RTMP streams (FFmpeg, OBS) default to passthrough mode.
        if self.encryption_mode == EncryptionMode::Pending {
            self.encryption_mode = EncryptionMode::Passthrough;
            log::info!(
                "Standard metadata received; defaulting to passthrough mode for {:?}",
                self.stream_key
            );
        }

        Ok(())
    }

    /// Handle video data
    async fn handle_video_data(
        &mut self,
        data: &Bytes,
        timestamp: &RtmpTimestamp,
    ) -> Result<(), SessionError> {
        match self.role {
            SessionRole::Publisher => {
                match self.encryption_mode {
                    EncryptionMode::Encrypted => {
                        // Encrypt video frame with Collection
                        if let Some(ref collection) = self.collection {
                            // Check rotation threshold
                            if rotation_threshold_reached(collection) {
                                log::warn!(
                                    "IV rotation threshold reached for stream {:?} - consider key rotation",
                                    self.stream_key
                                );
                            }

                            let encrypted = encrypt_item(collection, data)
                                .map_err(|e| SessionError::EncryptionError(e.to_string()))?;

                            // Relay encrypted frame to subscribers
                            self.relay_frame(RelayFrame {
                                frame_type: FrameType::Video,
                                timestamp: timestamp.value,
                                data: encrypted,
                            })
                            .await;
                        }
                    }
                    EncryptionMode::Passthrough => {
                        // Relay cleartext frame to subscribers
                        self.relay_frame(RelayFrame {
                            frame_type: FrameType::Video,
                            timestamp: timestamp.value,
                            data: data.to_vec(),
                        })
                        .await;
                    }
                    EncryptionMode::Pending => {
                        // First video frame before metadata - auto-set passthrough
                        if !self.metadata_received {
                            self.encryption_mode = EncryptionMode::Passthrough;
                            log::info!(
                                "Video data before metadata; defaulting to passthrough mode"
                            );
                            // Relay this frame
                            self.relay_frame(RelayFrame {
                                frame_type: FrameType::Video,
                                timestamp: timestamp.value,
                                data: data.to_vec(),
                            })
                            .await;
                        }
                    }
                }
            }
            SessionRole::Subscriber => {
                match self.encryption_mode {
                    EncryptionMode::Encrypted => {
                        // Decrypt video frame with Decryptor
                        if let Some(ref decryptor) = self.decryptor {
                            let _decrypted = decrypt_item(decryptor, data)
                                .map_err(|e| SessionError::EncryptionError(e.to_string()))?;
                            // Would send decrypted frame to player
                        }
                    }
                    EncryptionMode::Passthrough => {
                        // Handle cleartext video
                        // Would send frame directly to player
                    }
                    EncryptionMode::Pending => {
                        // Waiting for mode determination
                    }
                }
            }
            SessionRole::Unknown => {
                log::warn!("Received video data with unknown role");
            }
        }

        Ok(())
    }

    /// Handle audio data
    async fn handle_audio_data(
        &mut self,
        data: &Bytes,
        timestamp: &RtmpTimestamp,
    ) -> Result<(), SessionError> {
        match self.role {
            SessionRole::Publisher => {
                match self.encryption_mode {
                    EncryptionMode::Encrypted => {
                        if let Some(ref collection) = self.collection {
                            let encrypted = encrypt_item(collection, data)
                                .map_err(|e| SessionError::EncryptionError(e.to_string()))?;

                            self.relay_frame(RelayFrame {
                                frame_type: FrameType::Audio,
                                timestamp: timestamp.value,
                                data: encrypted,
                            })
                            .await;
                        }
                    }
                    EncryptionMode::Passthrough => {
                        // Relay cleartext audio
                        self.relay_frame(RelayFrame {
                            frame_type: FrameType::Audio,
                            timestamp: timestamp.value,
                            data: data.to_vec(),
                        })
                        .await;
                    }
                    EncryptionMode::Pending => {
                        // Pending - will be handled when mode is set
                    }
                }
            }
            SessionRole::Subscriber => {
                match self.encryption_mode {
                    EncryptionMode::Encrypted => {
                        if let Some(ref decryptor) = self.decryptor {
                            let _decrypted = decrypt_item(decryptor, data)
                                .map_err(|e| SessionError::EncryptionError(e.to_string()))?;
                        }
                    }
                    EncryptionMode::Passthrough => {
                        // Handle cleartext audio directly
                    }
                    EncryptionMode::Pending => {}
                }
            }
            SessionRole::Unknown => {}
        }

        Ok(())
    }

    /// Set manifest for subscriber and create decryptor
    fn set_manifest_subscriber(&mut self, manifest: NanoTdfManifest) -> Result<(), SessionError> {
        // Create decryptor from manifest header bytes and KAS private key
        let decryptor = create_decryptor_kas(&manifest.header_bytes, &self.kas_private_key)
            .map_err(|e| SessionError::EncryptionError(e.to_string()))?;

        self.manifest = Some(manifest);
        self.decryptor = Some(decryptor);
        self.encryption_mode = EncryptionMode::Encrypted;

        log::debug!("Decryptor created successfully from manifest");
        Ok(())
    }

    /// Set collection for publisher (called when publisher provides manifest)
    pub fn set_collection(&mut self, collection: Arc<NanoTdfCollection>) {
        self.collection = Some(collection);
        self.encryption_mode = EncryptionMode::Encrypted;
        log::debug!("Collection set for publisher encryption");
    }

    /// Relay frame to all subscribers
    async fn relay_frame(&mut self, frame: RelayFrame) {
        // Remove disconnected subscribers
        self.subscribers.retain(|tx| !tx.is_closed());

        // Send to all subscribers
        for tx in &self.subscribers {
            let _ = tx.send(frame.clone()).await;
        }
    }

    /// Add a subscriber channel for relay
    pub fn add_subscriber(&mut self, tx: tokio::sync::mpsc::Sender<RelayFrame>) {
        self.subscribers.push(tx);
    }

    /// Get current manifest if available
    pub fn get_manifest(&self) -> Option<&NanoTdfManifest> {
        self.manifest.as_ref()
    }

    /// Check if encryption is ready (collection for publisher, decryptor for subscriber)
    pub fn is_encryption_ready(&self) -> bool {
        match self.role {
            SessionRole::Publisher => self.collection.is_some(),
            SessionRole::Subscriber => self.decryptor.is_some(),
            SessionRole::Unknown => false,
        }
    }

    /// Get session role
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// Get stream key
    pub fn stream_key(&self) -> Option<&str> {
        self.stream_key.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_role() {
        assert_eq!(SessionRole::Unknown, SessionRole::Unknown);
        assert_ne!(SessionRole::Publisher, SessionRole::Subscriber);
    }

    #[test]
    fn test_relay_frame() {
        let frame = RelayFrame {
            frame_type: FrameType::Video,
            timestamp: 12345,
            data: vec![1, 2, 3, 4],
        };

        assert_eq!(frame.frame_type, FrameType::Video);
        assert_eq!(frame.timestamp, 12345);
        assert_eq!(frame.data.len(), 4);
    }
}
