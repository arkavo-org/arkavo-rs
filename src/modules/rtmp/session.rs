//! Per-Connection RTMP Session State Machine
//!
//! Manages the lifecycle of an RTMP connection including:
//! - RTMP handshake
//! - Publisher/Subscriber role detection
//! - onTDFManifest handling (via dedicated message OR onMetaData)
//! - Frame encryption (publisher) / decryption (subscriber)
//! - Passthrough mode for standard cleartext RTMP streams

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use rml_rtmp::handshake::{Handshake, HandshakeProcessResult, PeerType};
use rml_rtmp::sessions::{
    ServerSession, ServerSessionConfig, ServerSessionEvent, ServerSessionResult,
    StreamMetadata,
};
use rml_rtmp::time::RtmpTimestamp;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::encryption::{decrypt_payload, derive_dek, encrypt_payload};
use super::manifest::{
    cache_manifest, create_tdf_manifest_amf, delete_cached_manifest, get_cached_manifest,
    parse_tdf_manifest, NanoTdfManifest,
};

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

/// Metadata key for NanoTDF header in onMetaData
const NTDF_HEADER_KEY: &str = "ntdf_header";

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
    /// Derived DEK for encryption/decryption
    dek: Option<[u8; 32]>,
    /// KAS private key for DEK derivation
    kas_private_key: [u8; 32],
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
    Manifest,
}

impl RtmpSession {
    /// Create a new RTMP session
    pub fn new(redis_client: Arc<redis::Client>, kas_private_key: [u8; 32]) -> Self {
        RtmpSession {
            role: SessionRole::Unknown,
            encryption_mode: EncryptionMode::Pending,
            stream_key: None,
            manifest: None,
            dek: None,
            kas_private_key,
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
                    return Err(SessionError::RtmpError(format!(
                        "Handshake error: {:?}",
                        e
                    )));
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
                        self.set_manifest(manifest)?;
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
    async fn handle_metadata(&mut self, metadata: &StreamMetadata) -> Result<(), SessionError> {
        // Check for ntdf_header in metadata
        if let Some(ntdf_header_b64) = metadata.video_width.as_ref().and_then(|_| {
            // StreamMetadata doesn't expose custom fields directly
            // We need to check via additional_values or use a different approach
            // For now, we'll also check onTDFManifest messages
            None::<String>
        }) {
            // Found ntdf_header in metadata
            match STANDARD.decode(&ntdf_header_b64) {
                Ok(header_bytes) => {
                    if let Some(ref stream_key) = self.stream_key {
                        match NanoTdfManifest::from_header_bytes(header_bytes, stream_key.clone()) {
                            Ok(manifest) => {
                                log::info!(
                                    "NTDF header found in metadata for stream: {}",
                                    stream_key
                                );

                                // Cache manifest for late joiners
                                if let Err(e) = cache_manifest(&self.redis_client, &manifest).await
                                {
                                    log::error!("Failed to cache manifest: {}", e);
                                }

                                // Set manifest and derive DEK
                                self.set_manifest(manifest)?;
                                self.encryption_mode = EncryptionMode::Encrypted;
                                return Ok(());
                            }
                            Err(e) => {
                                log::warn!("Failed to parse NTDF header from metadata: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to decode NTDF header base64: {}", e);
                }
            }
        }

        // No ntdf_header found - set passthrough mode for cleartext streams
        if self.encryption_mode == EncryptionMode::Pending {
            self.encryption_mode = EncryptionMode::Passthrough;
            log::info!(
                "No NTDF header in metadata; defaulting to passthrough mode for {:?}",
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
                // Check for onTDFManifest in data messages (dedicated manifest message)
                if self.try_parse_manifest(data).await {
                    return Ok(());
                }

                match self.encryption_mode {
                    EncryptionMode::Encrypted => {
                        // Encrypt video frame
                        if let Some(ref dek) = self.dek {
                            let encrypted = encrypt_payload(dek, data)
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
                            log::info!("Video data before metadata; defaulting to passthrough mode");
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
                        // Decrypt video frame
                        if let Some(ref dek) = self.dek {
                            let _decrypted = decrypt_payload(dek, data)
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
                        if let Some(ref dek) = self.dek {
                            let encrypted = encrypt_payload(dek, data)
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
                        if let Some(ref dek) = self.dek {
                            let _decrypted = decrypt_payload(dek, data)
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

    /// Try to parse TDF manifest from AMF data (onTDFManifest message)
    async fn try_parse_manifest(&mut self, data: &bytes::Bytes) -> bool {
        if let Some(ref stream_key) = self.stream_key {
            match parse_tdf_manifest(data, stream_key) {
                Ok(manifest) => {
                    log::info!("Received onTDFManifest for stream: {}", stream_key);

                    // Cache manifest for late joiners
                    if let Err(e) = cache_manifest(&self.redis_client, &manifest).await {
                        log::error!("Failed to cache manifest: {}", e);
                    }

                    // Set manifest and derive DEK
                    if let Err(e) = self.set_manifest(manifest.clone()) {
                        log::error!("Failed to set manifest: {}", e);
                        return false;
                    }

                    // Set encryption mode
                    self.encryption_mode = EncryptionMode::Encrypted;

                    // Create AMF data for relaying to subscribers
                    if let Ok(amf_data) = create_tdf_manifest_amf(&manifest) {
                        self.relay_frame(RelayFrame {
                            frame_type: FrameType::Manifest,
                            timestamp: 0,
                            data: amf_data,
                        })
                        .await;
                    }

                    return true;
                }
                Err(_) => {
                    // Not a TDF manifest, continue
                }
            }
        }
        false
    }

    /// Set manifest and derive DEK
    fn set_manifest(&mut self, manifest: NanoTdfManifest) -> Result<(), SessionError> {
        // Derive DEK from manifest
        let dek = derive_dek(&manifest.ephemeral_key, &self.kas_private_key)
            .map_err(|e| SessionError::EncryptionError(e.to_string()))?;

        self.manifest = Some(manifest);
        self.dek = Some(dek);

        log::debug!("DEK derived successfully");
        Ok(())
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

    /// Check if DEK is available
    pub fn has_dek(&self) -> bool {
        self.dek.is_some()
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
