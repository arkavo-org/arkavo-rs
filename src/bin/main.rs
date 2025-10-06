mod contracts;
mod schemas;

// Import modules from library
use nanotdf::{media_metrics, session_manager};

// Include modules from parent src/modules directory
#[path = "../modules/mod.rs"]
mod modules;

use modules::{crypto, http_rewrap, media_api};

use crate::contracts::content_rating::content_rating::{
    AgeLevel, ContentRating, Rating, RatingLevel,
};
use crate::contracts::geo_fence_contract::geo_fence_contract::Geofence3D;
use crate::contracts::{contract_simple_abac, geo_fence_contract};
use crate::schemas::event_generated::arkavo::{Action, Event, EventData};
use crate::schemas::metadata_generated::arkavo;
use crate::schemas::metadata_generated::arkavo::{root_as_metadata, Metadata};
use async_nats::Message as NatsMessage;
use async_nats::{Client as NatsClient, PublishError};
use aws_sdk_s3 as s3;
use flatbuffers::root;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{decode, DecodingKey, Validation};
use log::{error, info};
use nanotdf::{BinaryParser, PolicyType, ProtocolEnum, ResourceLocator};
use native_tls::{Identity, Protocol, TlsAcceptor as NativeTlsAcceptor};
use once_cell::sync::OnceCell;
use p256::ecdh::EphemeralSecret;
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use redis::AsyncCommands;
use redis::Client as RedisClient;
use serde::{Deserialize, Serialize};
use std::env;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::RwLock;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_native_tls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
struct PublicKeyMessage {
    salt: Vec<u8>,
    public_key: Vec<u8>,
}

const MAX_NANOTDF_SIZE: usize = 16 * 1024 * 1024; // 16 MB
const NATS_RETRY_INTERVAL: Duration = Duration::from_secs(5);

struct NatsConnection {
    client: Mutex<Option<async_nats::Client>>,
    url: String,
}

impl NatsConnection {
    fn new(url: String) -> Self {
        Self {
            client: Mutex::new(None),
            url,
        }
    }
    async fn connect(&self) -> Result<(), async_nats::Error> {
        let mut client = self.client.lock().await;
        match async_nats::connect(&self.url).await {
            Ok(new_client) => {
                *client = Some(new_client);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
    async fn get_client(&self) -> Option<async_nats::Client> {
        self.client.lock().await.clone()
    }
}

struct NATSMessage {
    data: Vec<u8>,
}

impl NATSMessage {
    fn new(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() > MAX_NANOTDF_SIZE {
            return Err("NanoTDF message exceeds maximum size");
        }
        Ok(Self {
            data: data.to_vec(),
        })
    }

    async fn send_to_nats(
        &self,
        nats_client: &NatsClient,
        subject: String,
    ) -> Result<(), PublishError> {
        nats_client.publish(subject, self.data.clone().into()).await
    }
}

struct ConnectionState {
    salt_lock: RwLock<Option<Vec<u8>>>,
    shared_secret_lock: RwLock<Option<Vec<u8>>>,
    claims_lock: RwLock<Option<Claims>>,
    outgoing_tx: mpsc::UnboundedSender<Message>,
}

impl ConnectionState {
    fn new(outgoing_tx: mpsc::UnboundedSender<Message>) -> Self {
        ConnectionState {
            salt_lock: RwLock::new(None),
            shared_secret_lock: RwLock::new(None),
            claims_lock: RwLock::new(None),
            outgoing_tx,
        }
    }
}

#[derive(Debug)]
enum MessageType {
    PublicKey = 0x01,
    KasPublicKey = 0x02,
    Rewrap = 0x03,
    RewrappedKey = 0x04,
    Nats = 0x05,
    Event = 0x06,
    Error = 0xFF,
}

impl MessageType {
    fn from_u8(value: u8) -> Option<MessageType> {
        match value {
            0x01 => Some(MessageType::PublicKey),
            0x02 => Some(MessageType::KasPublicKey),
            0x03 => Some(MessageType::Rewrap),
            0x04 => Some(MessageType::RewrappedKey),
            0x05 => Some(MessageType::Nats),
            0x06 => Some(MessageType::Event),
            0xFF => Some(MessageType::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error_type: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl ErrorResponse {
    fn invalid_format(message: impl Into<String>) -> Self {
        Self {
            error_type: "invalid_format".to_string(),
            message: message.into(),
            details: None,
        }
    }

    fn policy_denied(message: impl Into<String>) -> Self {
        Self {
            error_type: "policy_denied".to_string(),
            message: message.into(),
            details: None,
        }
    }

    fn crypto_error(message: impl Into<String>) -> Self {
        Self {
            error_type: "crypto_error".to_string(),
            message: message.into(),
            details: None,
        }
    }

    #[allow(dead_code)]
    fn server_error(message: impl Into<String>) -> Self {
        Self {
            error_type: "server_error".to_string(),
            message: message.into(),
            details: None,
        }
    }

    fn to_message(&self) -> Message {
        let json_payload = serde_json::to_vec(self).unwrap_or_else(|_| {
            br#"{"error_type":"server_error","message":"Failed to serialize error"}"#.to_vec()
        });
        let mut response_data = Vec::with_capacity(1 + json_payload.len());
        response_data.push(MessageType::Error as u8);
        response_data.extend_from_slice(&json_payload);
        Message::Binary(response_data)
    }
}

struct KasKeys {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

static KAS_KEYS: OnceCell<Arc<KasKeys>> = OnceCell::new();
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Middleware for logging HTTP requests
async fn log_request_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = Instant::now();

    let response = next.run(req).await;

    let latency = start.elapsed();
    let status = response.status();

    info!("{} {} - {} ({:?})", method, uri, status.as_u16(), latency);

    response
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    // Load configuration
    let settings = load_config()?;

    // Validate configuration
    validate_config(&settings)?;

    let server_state = Arc::new(ServerState::new(settings.clone()).await?);
    // Load and cache the apple-app-site-association.json file
    let apple_app_site_association = load_apple_app_site_association().await;
    // Initialize KAS keys
    init_kas_keys(&settings.kas_key_path)?;

    // Get KAS keys for HTTP rewrap endpoint
    let kas_private_key_bytes = get_kas_private_key_bytes().expect("KAS keys not initialized");
    let kas_private_key_array: [u8; 32] = kas_private_key_bytes
        .try_into()
        .expect("Invalid KAS private key size");
    let kas_private_key =
        SecretKey::from_bytes(&kas_private_key_array.into()).expect("Invalid KAS private key");
    let kas_public_key = kas_private_key.public_key();
    let kas_public_key_pem = {
        let encoded = kas_public_key.to_encoded_point(false);
        let pem_data = pem::Pem::new("PUBLIC KEY", encoded.as_bytes().to_vec());
        pem::encode(&pem_data)
    };

    // Set up TLS if not disabled
    let tls_acceptor = if settings.tls_enabled {
        Some(load_tls_config(
            &settings.tls_cert_path,
            &settings.tls_key_path,
        )?)
    } else {
        None
    };

    // Initialize NATS connection
    let nats_connection = Arc::new(NatsConnection::new(settings.nats_url.clone()));
    // Spawn a task to handle NATS connection and reconnection
    let nats_connection_clone = nats_connection.clone();
    tokio::spawn(async move {
        loop {
            let client = nats_connection_clone.get_client().await;
            if client.is_none() {
                info!("NATS client not connected. Attempting to connect...");
                match nats_connection_clone.connect().await {
                    Ok(_) => info!("Successfully connected to NATS server"),
                    Err(e) => {
                        error!(
                            "Failed to connect to NATS server: {}. Retrying in {:?}...",
                            e, NATS_RETRY_INTERVAL
                        );
                        tokio::time::sleep(NATS_RETRY_INTERVAL).await;
                        continue;
                    }
                }
            }
            tokio::time::sleep(NATS_RETRY_INTERVAL).await;
        }
    });

    // Set up HTTP REST API server
    let http_port = env::var("HTTP_PORT").unwrap_or_else(|_| settings.port.to_string());

    // Load OAuth public key from environment if provided
    let oauth_public_key_pem = env::var("OAUTH_PUBLIC_KEY_PATH")
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok());

    if oauth_public_key_pem.is_some() {
        info!("OAuth JWT signature validation enabled");
    } else {
        info!("OAuth JWT signature validation disabled (development mode)");
    }

    let rewrap_state = Arc::new(http_rewrap::RewrapState {
        kas_private_key,
        kas_public_key_pem,
        oauth_public_key_pem,
    });

    // Initialize media DRM components
    let max_concurrent_streams = env::var("MAX_CONCURRENT_STREAMS")
        .ok()
        .and_then(|s| s.parse().ok());

    let session_manager = Arc::new(session_manager::SessionManager::new(
        Arc::new(server_state.redis_client.clone()),
        max_concurrent_streams,
    ));

    let enable_media_analytics = env::var("ENABLE_MEDIA_ANALYTICS")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .unwrap_or(true);

    let media_metrics_subject =
        env::var("MEDIA_METRICS_SUBJECT").unwrap_or_else(|_| "media.metrics".to_string());

    // Validate media DRM configuration
    validate_media_config(
        max_concurrent_streams.unwrap_or(5),
        &media_metrics_subject,
        enable_media_analytics,
    )?;

    let nats_client_for_metrics = nats_connection.get_client().await.map(Arc::new);
    let media_metrics = Arc::new(media_metrics::MediaMetrics::new(
        nats_client_for_metrics,
        media_metrics_subject,
        enable_media_analytics,
    ));

    let media_api_state = Arc::new(media_api::MediaApiState {
        rewrap_state: rewrap_state.clone(),
        session_manager: session_manager.clone(),
        media_metrics: media_metrics.clone(),
    });

    use axum::{
        routing::{delete, get, post},
        Router,
    };

    // OpenTDF compatibility router
    let opentdf_router = Router::new()
        .route("/kas/v2/rewrap", post(http_rewrap::rewrap_handler))
        .route(
            "/kas/v2/kas_public_key",
            get(http_rewrap::kas_public_key_handler),
        )
        .with_state(rewrap_state);

    // Media DRM router
    let media_router = Router::new()
        .route("/media/v1/key-request", post(media_api::media_key_request))
        .route("/media/v1/session/start", post(media_api::session_start))
        .route(
            "/media/v1/session/:session_id/heartbeat",
            post(media_api::session_heartbeat),
        )
        .route(
            "/media/v1/session/:session_id",
            delete(media_api::session_terminate),
        )
        .with_state(media_api_state);

    // Combine routers
    let app = Router::new()
        .merge(opentdf_router)
        .merge(media_router)
        .layer(
            tower::ServiceBuilder::new().layer(axum::middleware::from_fn(log_request_middleware)),
        );

    let http_addr = format!("0.0.0.0:{}", http_port);
    info!("Starting HTTP server on {}", http_addr);

    let http_server = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(&http_addr)
            .await
            .expect("Failed to bind HTTP server");
        axum::serve(listener, app)
            .await
            .expect("HTTP server failed");
    });

    // Set up WebSocket server (existing)
    let ws_port = env::var("WS_PORT").unwrap_or_else(|_| settings.port.to_string());
    let ws_addr = format!("0.0.0.0:{}", ws_port);
    info!("Starting WebSocket server on {}", ws_addr);

    let ws_server = tokio::spawn(async move {
        let listener = TcpListener::bind(&ws_addr)
            .await
            .expect("Failed to bind WebSocket server");

        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let tls_acceptor_clone = tls_acceptor.clone();
                let server_state_clone = server_state.clone();
                let nats_connection_clone = nats_connection.clone();
                let apple_app_site_association_clone = apple_app_site_association.clone();

                tokio::spawn(async move {
                    // Use a trait object to hold either TcpStream or TlsStream<TcpStream>
                    let stream: Box<dyn AsyncStream> =
                        if let Some(tls_acceptor) = tls_acceptor_clone {
                            match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => Box::new(tls_stream),
                                Err(e) => {
                                    eprintln!("Failed to accept TLS connection: {}", e);
                                    return;
                                }
                            }
                        } else {
                            Box::new(stream)
                        };

                    handle_connection(
                        stream,
                        server_state_clone,
                        nats_connection_clone,
                        apple_app_site_association_clone,
                    )
                    .await;
                });
            }
        }
    });

    // Run both servers concurrently
    tokio::try_join!(http_server, ws_server)?;

    Ok(())
}

fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let cert = std::fs::read(cert_path)?;
    let key = std::fs::read(key_path)?;

    let identity = Identity::from_pkcs8(&cert, &key)?;
    // Create native_tls TlsAcceptor with custom options
    let mut builder = NativeTlsAcceptor::builder(identity);
    // Set minimum TLS version to TLS 1.2
    builder.min_protocol_version(Some(Protocol::Tlsv12));
    // Build the native_tls acceptor
    let native_acceptor = builder
        .build()
        .map_err(|e| format!("Failed to build TLS acceptor: {}", e))?;
    // Convert to tokio_native_tls acceptor
    let acceptor = TlsAcceptor::from(native_acceptor);
    Ok(acceptor)
}

async fn handle_websocket(
    mut ws_stream: tokio_tungstenite::WebSocketStream<impl AsyncRead + AsyncWrite + Unpin>,
    server_state: Arc<ServerState>,
    nats_connection: Arc<NatsConnection>,
) {
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
    // Create ConnectionState with the outgoing channel
    let connection_state = Arc::new(ConnectionState::new(outgoing_tx));
    // Set up NATS subscription for this connection
    let nats_task = tokio::spawn(handle_nats_subscription(
        nats_connection.clone(),
        server_state.settings.nats_subject.clone(),
        connection_state.clone(),
    ));
    let mut public_id_nats_task: Option<tokio::task::JoinHandle<()>> = None;
    // Handle incoming WebSocket messages
    loop {
        tokio::select! {
            incoming = ws_stream.next() => {
                match incoming {
                    Some(Ok(msg)) => {
                        if msg.is_close() {
                            println!("Received a close message.");
                            break;
                        }
                        if msg.is_text() {
                            // Handle JWT token
                            let token = msg.into_text().unwrap();
                            println!("token: {}", token);
                            match verify_token(&token, &server_state.settings) {
                                Ok(claims) => {
                                    println!("Valid JWT received. Claims: {:?}", claims);
                                    // store the claims
                                    {
                                        let mut claims_lock = connection_state.claims_lock.write().unwrap();
                                        *claims_lock = Some(claims.clone());
                                    }
                                    // Extract publicID from claims and subscribe to `profile.<publicID>`
                                    let public_id = claims.sub;
                                    let subject = format!("profile.{}", public_id);
                                    // Cancel any existing `publicID`-specific NATS task
                                    if let Some(task) = public_id_nats_task.take() {
                                        task.abort();
                                    }
                                    // Set up new NATS subscription for `profile.<publicID>`
                                    public_id_nats_task = Some(tokio::spawn(handle_nats_subscription(
                                        nats_connection.clone(),
                                        subject,
                                        connection_state.clone(),
                                    )));
                                }
                                Err(e) => {
                                    error!("Invalid JWT: {}", e);
                                }
                            }
                        } else if let Some(response) = handle_binary_message(&connection_state, &server_state, msg.into_data(), nats_connection.clone()).await {
                            if ws_stream.send(response).await.is_err() {
                                eprintln!("Failed to send response through WebSocket");
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("Error reading message: {}", e);
                        break;
                    }
                    None => break,
                }
            }
            outgoing = outgoing_rx.recv() => {
                match outgoing {
                    Some(message) => {
                        if ws_stream.send(message).await.is_err() {
                            eprintln!("Failed to send outgoing message through WebSocket");
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    // Cancel the NATS subscription when the WebSocket connection closes
    nats_task.abort();
    if let Some(task) = public_id_nats_task {
        task.abort();
    }
}

async fn handle_connection(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    server_state: Arc<ServerState>,
    nats_connection: Arc<NatsConnection>,
    apple_app_site_association: Arc<RwLock<String>>,
) {
    let mut rewindable_stream = RewindableStream::new(stream);

    // Read the first line of the request
    let request_line = match rewindable_stream.read_until(b'\n').await {
        Ok(line) => line,
        Err(e) => {
            eprintln!("Failed to read from stream: {}", e);
            return;
        }
    };

    let request_line_str = String::from_utf8_lossy(&request_line);
    let mut parts = request_line_str.split_whitespace();
    let method = parts.next();
    let path = parts.next();

    if method == Some("GET") && path == Some("/.well-known/apple-app-site-association") {
        // Handle the apple-app-site-association request
        let apple_app_site_association_content = {
            let read_guard = apple_app_site_association.read().unwrap();
            read_guard.clone()
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            apple_app_site_association_content.len(),
            apple_app_site_association_content
        );
        if let Err(e) = rewindable_stream.write_all(response.as_bytes()).await {
            eprintln!("Failed to write response: {}", e);
        }
    } else {
        // Assume it's a WebSocket request and proceed with the upgrade
        rewindable_stream.rewind();
        match tokio_tungstenite::accept_async(rewindable_stream).await {
            Ok(ws_stream) => {
                handle_websocket(ws_stream, server_state, nats_connection).await;
            }
            Err(e) => {
                eprintln!("Failed to accept websocket: {}", e);
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    age: String,
}

fn verify_token(
    token: &str,
    settings: &ServerSettings,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();

    if settings.jwt_validation_disabled {
        // Development mode - disable signature validation
        log::warn!(
            "⚠️  JWT signature validation is DISABLED - for development only! \
             Set JWT_VALIDATION_DISABLED=false for production."
        );
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        validation.validate_aud = false;
        let secret = b"any_secret_key"; // The actual value doesn't matter when validation is disabled
        let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)?;
        Ok(token_data.claims)
    } else {
        // Production mode - proper JWT validation
        validation.validate_exp = true;
        validation.validate_aud = false; // Can be enabled if audience is specified

        // Load the public key for verification
        let public_key_path = settings.jwt_public_key_path.as_ref().ok_or_else(|| {
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)
        })?;

        let public_key_pem = std::fs::read_to_string(public_key_path).map_err(|e| {
            error!(
                "Failed to read JWT public key from {}: {}",
                public_key_path, e
            );
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)
        })?;

        // Support both RSA and ECDSA keys
        let decoding_key = if public_key_pem.contains("BEGIN RSA PUBLIC KEY")
            || public_key_pem.contains("BEGIN PUBLIC KEY")
        {
            validation.algorithms = vec![
                jsonwebtoken::Algorithm::RS256,
                jsonwebtoken::Algorithm::RS384,
                jsonwebtoken::Algorithm::RS512,
            ];
            DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?
        } else if public_key_pem.contains("BEGIN EC PUBLIC KEY") {
            validation.algorithms = vec![
                jsonwebtoken::Algorithm::ES256,
                jsonwebtoken::Algorithm::ES384,
            ];
            DecodingKey::from_ec_pem(public_key_pem.as_bytes())?
        } else {
            error!("Unsupported JWT public key format");
            return Err(jsonwebtoken::errors::Error::from(
                jsonwebtoken::errors::ErrorKind::InvalidKeyFormat,
            ));
        };

        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        info!(
            "JWT signature verified successfully for subject: {}",
            token_data.claims.sub
        );
        Ok(token_data.claims)
    }
}

async fn handle_binary_message(
    connection_state: &Arc<ConnectionState>,
    server_state: &Arc<ServerState>,
    data: Vec<u8>,
    nats_connection: Arc<NatsConnection>,
) -> Option<Message> {
    if data.is_empty() {
        println!("Invalid message format");
        return None;
    }
    let message_type = MessageType::from_u8(data[0]);
    let payload = &data[1..data.len()];

    match message_type {
        Some(MessageType::PublicKey) => handle_public_key(connection_state, payload).await, // incoming
        Some(MessageType::KasPublicKey) => handle_kas_public_key(payload).await, // outgoing
        Some(MessageType::Rewrap) => {
            handle_rewrap(connection_state, payload, &server_state.settings).await
        } // incoming
        Some(MessageType::RewrappedKey) => None,                                 // outgoing
        Some(MessageType::Nats) => {
            handle_nats_publish(
                connection_state,
                payload,
                &server_state.settings,
                nats_connection,
            )
            .await
        } // internal
        Some(MessageType::Event) => handle_event(server_state, payload, nats_connection).await, // embedded
        Some(MessageType::Error) => {
            // Error messages are sent from server to client, not received
            error!("Received unexpected Error message type from client");
            None
        }
        None => {
            // Unknown message type
            None
        }
    }
}

async fn handle_nats_publish(
    _: &Arc<ConnectionState>,
    payload: &[u8],
    settings: &ServerSettings,
    nats_connection: Arc<NatsConnection>,
) -> Option<Message> {
    match NATSMessage::new(payload) {
        Ok(nanotdf_msg) => {
            // Check if NATS client is available before attempting to send
            if let Some(nats_client) = nats_connection.get_client().await {
                if let Err(e) = nanotdf_msg
                    .send_to_nats(&nats_client, settings.nats_subject.clone())
                    .await
                {
                    error!("Failed to send NanoTDF message to NATS: {}", e);
                } else {
                    info!("NanoTDF message sent to NATS successfully");
                }
            } else {
                error!("NATS client not available - message not sent");
            }
        }
        Err(e) => {
            error!("Failed to create NanoTDFMessage: {}", e);
        }
    }
    None
}

async fn handle_rewrap(
    connection_state: &Arc<ConnectionState>,
    payload: &[u8],
    settings: &ServerSettings,
) -> Option<Message> {
    // Validate payload size before processing
    if payload.len() > MAX_NANOTDF_SIZE {
        error!(
            "Rewrap request exceeds maximum size: {} bytes (max: {} bytes)",
            payload.len(),
            MAX_NANOTDF_SIZE
        );
        return Some(
            ErrorResponse::invalid_format(format!(
                "Rewrap request exceeds maximum size: {} bytes (max: {} bytes)",
                payload.len(),
                MAX_NANOTDF_SIZE
            ))
            .to_message(),
        );
    }

    // timing
    let start_time = Instant::now();
    // session shared secret
    let session_shared_secret = {
        let shared_secret = connection_state.shared_secret_lock.read().unwrap();
        shared_secret.clone()
    };
    if session_shared_secret.is_none() {
        error!("Rewrap attempted before key agreement - no session secret");
        return Some(
            ErrorResponse::invalid_format("Session not established - perform key agreement first")
                .to_message(),
        );
    }
    let session_shared_secret = session_shared_secret.unwrap();
    // Parse NanoTDF header
    let mut parser = BinaryParser::new(payload);
    let header = match BinaryParser::parse_header(&mut parser) {
        Ok(header) => header,
        Err(e) => {
            error!("Failed to parse NanoTDF header: {:?}", e);
            return Some(
                ErrorResponse::invalid_format(format!("Invalid NanoTDF header: {}", e))
                    .to_message(),
            );
        }
    };
    // timing
    let parse_time = start_time.elapsed();
    log_timing(settings, "Time to parse header", parse_time);
    // TDF ephemeral key
    let tdf_ephemeral_key_bytes = header.get_ephemeral_key();
    if tdf_ephemeral_key_bytes.len() != 33 {
        error!(
            "Invalid NanoTDF ephemeral key length: {} (expected 33)",
            tdf_ephemeral_key_bytes.len()
        );
        return Some(
            ErrorResponse::invalid_format(format!(
                "Invalid ephemeral key size: {} bytes",
                tdf_ephemeral_key_bytes.len()
            ))
            .to_message(),
        );
    }
    // TDF contract
    let policy = header.get_policy();
    // println!("policy: {:?}", policy);
    let locator: Option<ResourceLocator>;
    let policy_body: Option<&[u8]> = None;
    let mut metadata: Option<Metadata> = None;

    match policy.policy_type {
        PolicyType::Remote => {
            info!("Processing remote policy");
            locator = policy.get_locator().clone();

            // Fetch remote policy if HTTP/HTTPS URL
            if let Some(ref loc) = locator {
                if loc.protocol_enum == ProtocolEnum::Http
                    || loc.protocol_enum == ProtocolEnum::Https
                {
                    info!("Fetching remote policy from: {}", loc.body);
                    // TODO: Implement actual HTTP fetch of remote policy
                    // For now, return error indicating feature not complete
                    error!("Remote policy fetching not yet implemented");
                    return Some(
                        ErrorResponse::invalid_format(
                            "Remote policy fetching via HTTP/HTTPS not yet implemented",
                        )
                        .to_message(),
                    );

                    // Future implementation:
                    // match reqwest::get(&loc.body).await {
                    //     Ok(response) => {
                    //         match response.bytes().await {
                    //             Ok(bytes) => {
                    //                 metadata = match root_as_metadata(&bytes) {
                    //                     Ok(meta) => Some(meta),
                    //                     Err(e) => {
                    //                         error!("Failed to parse remote policy metadata: {}", e);
                    //                         return Some(
                    //                             ErrorResponse::invalid_format(format!(
                    //                                 "Invalid remote policy metadata: {}",
                    //                                 e
                    //                             ))
                    //                             .to_message(),
                    //                         );
                    //                     }
                    //                 };
                    //             }
                    //             Err(e) => {
                    //                 error!("Failed to read remote policy response: {}", e);
                    //                 return Some(
                    //                     ErrorResponse::invalid_format(format!(
                    //                         "Failed to fetch remote policy: {}",
                    //                         e
                    //                     ))
                    //                     .to_message(),
                    //                 );
                    //             }
                    //         }
                    //     }
                    //     Err(e) => {
                    //         error!("Failed to fetch remote policy: {}", e);
                    //         return Some(
                    //             ErrorResponse::invalid_format(format!(
                    //                 "Failed to fetch remote policy: {}",
                    //                 e
                    //             ))
                    //             .to_message(),
                    //         );
                    //     }
                    // }
                }
            }
        }
        PolicyType::Embedded => {
            info!("Processing embedded policy");
            if let Some(body) = &policy.body {
                info!("Metadata buffer size: {}", body.len());
                metadata = match root_as_metadata(body) {
                    Ok(metadata) => Some(metadata),
                    Err(e) => {
                        error!("Failed to parse embedded policy metadata: {}", e);
                        return Some(
                            ErrorResponse::invalid_format(format!(
                                "Invalid embedded policy metadata: {}",
                                e
                            ))
                            .to_message(),
                        );
                    }
                };
                info!("Parsed metadata: {:#?}", metadata);

                // For embedded policies with rating metadata, infer content rating contract
                // TODO: Add contract_id field to metadata schema or use policy binding
                // to explicitly specify which contract to use
                if let Some(ref meta) = metadata {
                    if meta.rating().is_some() {
                        locator = Some(ResourceLocator {
                            protocol_enum: ProtocolEnum::SharedResource,
                            body: "5HKLo6CKbt1Z5dU4wZ3MiufeZzjM6JGwKUWUQ6a91fmuA6RB".to_string(),
                        });
                        info!("Inferred content rating contract from metadata");
                    } else {
                        // Metadata present but no rating - no contract enforcement
                        locator = None;
                        info!("No rating in metadata - skipping contract enforcement");
                    }
                } else {
                    locator = None;
                }
            } else {
                locator = None;
            }
        }
    }

    // Verify policy binding if present
    // Policy binding ensures integrity of the policy by cryptographically binding it
    // to either an ECDSA signature or GMAC tag
    if let Some(binding_bytes) = policy.get_binding() {
        info!("Policy binding present ({} bytes)", binding_bytes.len());

        let ecc_mode = header.get_ecc_mode();

        // Validate binding format based on binding type
        if ecc_mode.use_ecdsa_binding {
            // ECDSA binding - validate signature format
            let expected_size = match ecc_mode.ephemeral_ecc_params_enum {
                nanotdf::ECDSAParams::Secp256r1 | nanotdf::ECDSAParams::Secp256k1 => 64,
                nanotdf::ECDSAParams::Secp384r1 => 96,
                nanotdf::ECDSAParams::Secp521r1 => 132,
            };

            if binding_bytes.len() != expected_size {
                error!(
                    "Invalid ECDSA binding size: {} bytes (expected {} for {:?})",
                    binding_bytes.len(),
                    expected_size,
                    ecc_mode.ephemeral_ecc_params_enum
                );
                return Some(
                    ErrorResponse::invalid_format(format!(
                        "Invalid policy binding signature size: {} bytes (expected {})",
                        binding_bytes.len(),
                        expected_size
                    ))
                    .to_message(),
                );
            }

            info!(
                "ECDSA policy binding format validated ({:?})",
                ecc_mode.ephemeral_ecc_params_enum
            );

            // For full ECDSA verification, we need the public key from the policy authority
            // This would typically be:
            // 1. Embedded in the policy metadata as a JWK or raw bytes
            // 2. Retrieved from a trusted authority/certificate
            // 3. Derived from a known policy signing key
            //
            // Without the public key, we can only validate format
            log::warn!(
                "ECDSA policy binding signature format valid, but cryptographic verification \
                 requires policy authority public key (not implemented)"
            );
        } else {
            // GMAC binding - validate tag size
            if binding_bytes.len() != 16 {
                error!(
                    "Invalid GMAC binding size: {} bytes (expected 16)",
                    binding_bytes.len()
                );
                return Some(
                    ErrorResponse::invalid_format(format!(
                        "Invalid policy binding GMAC tag size: {} bytes (expected 16)",
                        binding_bytes.len()
                    ))
                    .to_message(),
                );
            }

            info!("GMAC policy binding format validated");

            // GMAC verification requires the symmetric key derived during rewrap
            // The GMAC tag is computed over the policy bytes using the payload key
            // We'll verify this later in the rewrap process after deriving the key
            log::warn!(
                "GMAC policy binding tag format valid, but cryptographic verification \
                 requires payload key (deferred to rewrap)"
            );
        }
    } else {
        info!("No policy binding present");
    }

    if let Some(locator) = &locator {
        if locator.protocol_enum == ProtocolEnum::SharedResource {
            info!("Evaluating contract: {}", locator.body.clone());
            if !locator.body.is_empty() {
                //  "Verified 18+"
                let claims_result = match connection_state.claims_lock.read() {
                    Ok(read_lock) => match read_lock.clone() {
                        Some(value) => Ok(value.sub),
                        None => Err("Error: Clone cannot be performed"),
                    },
                    Err(_) => Err("Error: Read lock cannot be obtained"),
                };
                let verified_age_result = match connection_state
                    .claims_lock
                    .read()
                    .expect("Error: Read lock cannot be obtained")
                    .clone()
                {
                    Some(claims) => Ok(claims.age == "Verified 18+"),
                    None => Err("Error: Claims data not available"),
                };
                // geo_fence_contract
                if locator
                    .body
                    .contains("5H6sLwXKBv3cdm5VVRxrvA8p5cux2Rrni5CQ4GRyYKo4b9B4")
                {
                    info!("Processing geofence contract");
                    let _contract = geo_fence_contract::geo_fence_contract::GeoFenceContract::new();

                    // Parse geofence bounds from policy body
                    // Expected format: 6 f64 values (48 bytes total)
                    // min_lat, max_lat, min_lon, max_lon, min_alt, max_alt
                    let _geofence = if let Some(body) = policy_body {
                        if body.len() >= 48 {
                            // Parse 6 f64 values from little-endian bytes
                            let mut values = [0f64; 6];
                            for (i, value) in values.iter_mut().enumerate() {
                                let start = i * 8;
                                let bytes = &body[start..start + 8];
                                *value = f64::from_le_bytes(bytes.try_into().unwrap_or([0u8; 8]));
                            }
                            Geofence3D {
                                min_latitude: values[0],
                                max_latitude: values[1],
                                min_longitude: values[2],
                                max_longitude: values[3],
                                min_altitude: values[4],
                                max_altitude: values[5],
                            }
                        } else {
                            error!(
                                "Policy body too small for geofence data: {} bytes (expected 48)",
                                body.len()
                            );
                            return Some(
                                ErrorResponse::invalid_format(
                                    "Geofence policy body must contain 48 bytes (6 f64 values)",
                                )
                                .to_message(),
                            );
                        }
                    } else {
                        error!("Geofence policy missing body data");
                        return Some(
                            ErrorResponse::invalid_format("Geofence policy requires body data")
                                .to_message(),
                        );
                    };

                    // Extract coordinates from JWT claims
                    // TODO: Add latitude/longitude/altitude fields to Claims struct
                    // For now, return error indicating feature not complete
                    error!("Geofence coordinate extraction from JWT claims not yet implemented");
                    return Some(
                        ErrorResponse::invalid_format(
                            "Geofence validation requires location fields in JWT claims (feature incomplete)",
                        )
                        .to_message(),
                    );

                    // Future implementation once Claims struct has location fields:
                    // let coordinate = match connection_state.claims_lock.read() {
                    //     Ok(read_lock) => match read_lock.clone() {
                    //         Some(claims) => geo_fence_contract::geo_fence_contract::Coordinate3D {
                    //             latitude: claims.latitude,
                    //             longitude: claims.longitude,
                    //             altitude: claims.altitude,
                    //         },
                    //         None => {
                    //             return Some(ErrorResponse::policy_denied(
                    //                 "Geofence validation requires authentication"
                    //             ).to_message());
                    //         }
                    //     },
                    //     Err(_) => {
                    //         return Some(ErrorResponse::policy_denied(
                    //             "Failed to read authentication claims"
                    //         ).to_message());
                    //     }
                    // };
                    //
                    // if !contract.is_within_geofence(geofence, coordinate) {
                    //     error!("Geofence policy denied access - location outside allowed area");
                    //     let total_time = start_time.elapsed();
                    //     log_timing(settings, "Time to deny (geofence)", total_time);
                    //     return Some(
                    //         ErrorResponse::policy_denied(
                    //             "Access denied - location outside permitted geofence",
                    //         )
                    //         .to_message(),
                    //     );
                    // }
                    // info!("Geofence validation passed");
                }
                // content_rating
                else if locator
                    .body
                    .contains("5HKLo6CKbt1Z5dU4wZ3MiufeZzjM6JGwKUWUQ6a91fmuA6RB")
                {
                    println!("contract content rating");
                    let contract = ContentRating::new();
                    // Parse the content rating data from the policy body
                    // get entitlements
                    let age_level = if verified_age_result.unwrap_or(false) {
                        AgeLevel::Adults
                    } else {
                        AgeLevel::Kids
                    };
                    if metadata.is_none() {
                        println!("metadata is null");
                        return None;
                    }
                    let rating_data = metadata.unwrap().rating()?;
                    let rating = Rating {
                        violent: convert_rating_level(rating_data.violent()),
                        sexual: convert_rating_level(rating_data.sexual()),
                        profane: convert_rating_level(rating_data.profane()),
                        substance: convert_rating_level(rating_data.substance()),
                        hate: convert_rating_level(rating_data.hate()),
                        harm: convert_rating_level(rating_data.harm()),
                        mature: convert_rating_level(rating_data.mature()),
                        bully: convert_rating_level(rating_data.bully()),
                    };
                    // Format age level before check_content consumes it
                    let age_level_str = format!("{:?}", age_level);
                    if !contract.check_content(age_level, rating) {
                        error!(
                            "Content rating policy denied access for age level: {}",
                            age_level_str
                        );
                        return Some(
                            ErrorResponse::policy_denied(format!(
                                "Content not suitable for age level: {}",
                                age_level_str
                            ))
                            .to_message(),
                        );
                    }
                }
                // simple_abac
                else if locator
                    .body
                    .contains("5Cqk3ERPToSMuY8UoKJtcmo4fs1iVyQpq6ndzWzpzWezAF1W")
                {
                    let contract = contract_simple_abac::simple_abac::SimpleAbac::new();
                    if claims_result.is_ok()
                        && !contract.check_access(claims_result.unwrap(), locator.body.clone())
                    {
                        error!("ABAC policy denied access for user claims");
                        // timing
                        let total_time = start_time.elapsed();
                        log_timing(settings, "Time to deny (ABAC)", total_time);
                        return Some(
                            ErrorResponse::policy_denied(
                                "Access denied by attribute-based access control policy",
                            )
                            .to_message(),
                        );
                    }
                }
            }
        }
    }
    // Deserialize the public key sent by the client
    let tdf_ephemeral_public_key = match PublicKey::from_sec1_bytes(tdf_ephemeral_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            info!("Error deserializing TDF ephemeral public key: {:?}", e);
            return None;
        }
    };
    // KAS key
    let kas_private_key_bytes = get_kas_private_key_bytes().unwrap();
    let kas_private_key_array: [u8; 32] = match kas_private_key_bytes.try_into() {
        Ok(key) => key,
        Err(_) => return None,
    };
    let kas_private_key = SecretKey::from_bytes(&kas_private_key_array.into())
        .map_err(|_| "Invalid private key")
        .ok()?;

    // Perform custom ECDH
    let ecdh_start = Instant::now();
    let dek_shared_secret_bytes =
        match crypto::custom_ecdh(&kas_private_key, &tdf_ephemeral_public_key) {
            Ok(secret) => secret,
            Err(e) => {
                info!("Error performing ECDH: {:?}", e);
                return None;
            }
        };
    let ecdh_time = ecdh_start.elapsed();
    log_timing(settings, "Time for ECDH operation", ecdh_time);

    // Determine HKDF salt based on NanoTDF version
    let nanotdf_salt = if let Some(version) = crypto::detect_nanotdf_version(payload) {
        crypto::compute_nanotdf_salt(version)
    } else {
        // Fallback to v12 for backward compatibility
        crypto::compute_nanotdf_salt(crypto::NANOTDF_VERSION_V12)
    };

    // Use NanoTDF-compatible HKDF: empty info parameter per spec section 4
    let info = b"";

    let encryption_start = Instant::now();
    let (nonce_vec, wrapped_dek) = match crypto::rewrap_dek(
        &dek_shared_secret_bytes,
        &session_shared_secret,
        &nanotdf_salt,
        info,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Rewrap DEK failed: {}", e);
            return Some(
                ErrorResponse::crypto_error(format!("Failed to rewrap key: {}", e)).to_message(),
            );
        }
    };
    let encryption_time = encryption_start.elapsed();
    log_timing(settings, "Time for AES-GCM encryption", encryption_time);

    // binary response
    let mut response_data = Vec::new();
    response_data.push(MessageType::RewrappedKey as u8);
    response_data.extend_from_slice(tdf_ephemeral_key_bytes);
    response_data.extend_from_slice(&nonce_vec);
    response_data.extend_from_slice(&wrapped_dek);

    let total_time = start_time.elapsed();
    log_timing(settings, "Total time for handle_rewrap", total_time);

    Some(Message::Binary(response_data))
}

async fn handle_public_key(
    connection_state: &Arc<ConnectionState>,
    payload: &[u8],
) -> Option<Message> {
    {
        let shared_secret_lock = connection_state.shared_secret_lock.read();
        let shared_secret = shared_secret_lock.unwrap();
        if shared_secret.is_some() {
            // Session already established - ignore duplicate key exchange
            return None;
        }
    }

    if payload.len() != 33 {
        error!(
            "Invalid client public key size: {} bytes (expected 33)",
            payload.len()
        );
        return Some(
            ErrorResponse::invalid_format(format!(
                "Invalid public key size: {} bytes (expected 33 for compressed P-256)",
                payload.len()
            ))
            .to_message(),
        );
    }

    // Deserialize the public key sent by the client
    let client_public_key = match PublicKey::from_sec1_bytes(payload) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to deserialize client public key: {:?}", e);
            return Some(
                ErrorResponse::crypto_error(format!("Invalid P-256 public key: {}", e))
                    .to_message(),
            );
        }
    };
    // Generate an ephemeral private key
    let server_private_key = EphemeralSecret::random(&mut OsRng);
    let server_public_key = PublicKey::from(&server_private_key);
    // Perform the key agreement
    let shared_secret = server_private_key.diffie_hellman(&client_public_key);
    let shared_secret_bytes = shared_secret.raw_secret_bytes();
    // println!("Shared Secret +++++++++++++");
    // println!("Shared Secret: {}", hex::encode(shared_secret_bytes));
    // println!("Shared Secret +++++++++++++");
    {
        let shared_secret = connection_state.shared_secret_lock.write();
        *shared_secret.unwrap() = Some(shared_secret_bytes.to_vec());
    }
    // session salt
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    {
        let mut salt_lock = connection_state.salt_lock.write().unwrap();
        *salt_lock = Some(salt.to_vec());
    }
    // println!("Session Salt: {}", hex::encode(salt));
    // Convert to compressed representation
    let compressed_public_key = server_public_key.to_encoded_point(true);
    let compressed_public_key_bytes = compressed_public_key.as_bytes();
    // Send server_public_key as publicKey message
    let mut response_data = Vec::new();
    // Appending MessageType::PublicKey
    response_data.push(MessageType::PublicKey as u8);
    // Appending server_public_key bytes
    response_data.extend_from_slice(compressed_public_key_bytes);
    // Appending salt bytes
    response_data.extend_from_slice(&salt);
    Some(Message::Binary(response_data))
}

async fn handle_kas_public_key(_: &[u8]) -> Option<Message> {
    // println!("Handling KAS public key");
    if let Some(kas_public_key_bytes) = get_kas_public_key() {
        // println!("KAS Public Key Size: {} bytes", kas_public_key_bytes.len());
        // println!("KAS Public Key Hex: {}", hex::encode(&kas_public_key_bytes));
        let mut response_data = Vec::new();
        response_data.push(MessageType::KasPublicKey as u8);
        response_data.extend_from_slice(&kas_public_key_bytes);
        return Some(Message::Binary(response_data));
    }
    None
}

async fn handle_nats_subscription(
    nats_connection: Arc<NatsConnection>,
    subject: String,
    connection_state: Arc<ConnectionState>,
) {
    loop {
        if let Some(client) = nats_connection.get_client().await {
            match client.subscribe(subject.clone()).await {
                Ok(mut subscription) => {
                    info!("Subscribed to NATS subject: {}", subject);
                    while let Some(msg) = subscription.next().await {
                        if let Err(e) = handle_nats(msg, connection_state.clone()).await {
                            error!("Error handling NATS message: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to subscribe to NATS subject: {}. Retrying in {:?}...",
                        e, NATS_RETRY_INTERVAL
                    );
                }
            }
        }
        tokio::time::sleep(NATS_RETRY_INTERVAL).await;
    }
}

async fn handle_nats(
    msg: NatsMessage,
    connection_state: Arc<ConnectionState>,
) -> Result<(), Box<dyn std::error::Error>> {
    // it nanotdf, then do a message, otherwise it is a Flatbuffers event
    let message_type = if msg.payload[0..3].iter().eq(&[0x4C, 0x31, 0x4C]) {
        MessageType::Nats
    } else {
        MessageType::Event
    };

    let ws_message = Message::Binary(
        vec![message_type as u8]
            .into_iter()
            .chain(msg.payload)
            .collect(),
    );
    connection_state.outgoing_tx.send(ws_message)?;
    Ok(())
}

async fn handle_event(
    server_state: &Arc<ServerState>,
    payload: &[u8],
    nats_connection: Arc<NatsConnection>,
) -> Option<Message> {
    let start_time = Instant::now();
    println!(
        "Payload (first 20 bytes in hex, space-delimited): {}",
        payload
            .iter()
            .take(20)
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(" ")
    );
    // Size validation for type 0x06
    const MAX_EVENT_SIZE: usize = 2000; // Adjust this value as needed
    if payload.len() > MAX_EVENT_SIZE {
        error!(
            "Event payload exceeds maximum allowed size of {} bytes",
            MAX_EVENT_SIZE
        );
        return None;
    }
    let mut event_data: Option<Vec<u8>> = None;
    if let Ok(event) = root::<Event>(payload) {
        println!("Event Action: {:?}", event.action());
        println!("Event Timestamp: {:?}", event.timestamp());
        println!("Event Status: {:?}", event.status());
        println!("Event Data Type: {:?}", event.data_type());
        // S3 store
        match event.action() {
            Action::store => {
                if let Some(cache_event) = event.data_as_cache_event() {
                    if let (Some(target_id), Some(target_payload)) =
                        (cache_event.target_id(), cache_event.target_payload())
                    {
                        // Create S3 key using target_id
                        let target_id_str = bs58::encode(target_id.bytes()).into_string();
                        let s3_key = format!("{}/data", target_id_str);

                        // Upload to S3
                        return match server_state
                            .s3_client
                            .put_object()
                            .bucket(&server_state.settings.s3_bucket)
                            .key(&s3_key)
                            .body(aws_sdk_s3::primitives::ByteStream::from(
                                target_payload.bytes().to_vec(),
                            ))
                            .send()
                            .await
                        {
                            Ok(_) => {
                                info!("Successfully stored object in S3: {}", s3_key);
                                let mut response = Vec::new();
                                response.push(MessageType::Event as u8);
                                response.extend_from_slice(b"Successfully stored");
                                Some(Message::Binary(response))
                            }
                            Err(e) => {
                                error!("Failed to store object in S3: {}", e);
                                None
                            }
                        };
                    }
                }
            }
            _ => {
                error!("Unhandled action: {:?}", event.action());
                drop(None::<Message>);
            }
        }
        // redis connection
        let mut redis_conn = match server_state
            .redis_client
            .get_multiplexed_async_connection()
            .await
        {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to connect to Redis: {}", e);
                return None;
            }
        };
        // Deserialize the event data based on its type
        match event.data_type() {
            EventData::UserEvent => {
                if let Some(user_event) = event.data_as_user_event() {
                    println!("User Event:");
                    println!("  Source Type: {:?}", user_event.source_type());
                    println!("  Target Type: {:?}", user_event.target_type());
                    println!("  Source ID: {:?}", user_event.source_id());
                    println!("  Target ID: {:?}", user_event.target_id());
                    let target_id = user_event.target_id().unwrap();
                    // Retrieve the event object from Redis
                    event_data = match redis_conn.get::<_, Vec<u8>>(target_id.bytes()).await {
                        Ok(data) => {
                            println!("redis target_id: {:?}", target_id);
                            println!("redis data size: {} bytes", data.len());
                            if data.is_empty() {
                                error!("Retrieved data from Redis has size 0");
                                return None;
                            }
                            Some(data)
                        }
                        Err(e) => {
                            error!("Failed to retrieve event from Redis: {}", e);
                            return None;
                        }
                    };
                    // TODO if cache miss then route to device
                } else {
                    error!("Failed to parse user event from payload");
                    return None;
                }
            }
            EventData::CacheEvent => {
                if let Some(cache_event) = event.data_as_cache_event() {
                    println!("Cache Event:");
                    println!("  Target ID: {:?}", cache_event.target_id());
                    println!("  Target Payload: {:?}", cache_event.target_payload());
                    println!(
                        "  Target Payload Size: {:?}",
                        cache_event.target_payload()?.bytes().len()
                    );
                    println!("  TTL: {:?}", cache_event.ttl());
                    println!("  One Time Access: {:?}", cache_event.one_time_access());
                    // Cache the object in Redis with specified TTL
                    let ttl = cache_event.ttl();
                    if ttl > 0 {
                        if let (Some(target_id), Some(target_payload)) =
                            (cache_event.target_id(), cache_event.target_payload())
                        {
                            let target_id_bytes = target_id.bytes();
                            let target_payload_bytes = target_payload.bytes();
                            redis_conn
                                .set_ex::<_, _, String>(
                                    target_id_bytes,
                                    target_payload_bytes,
                                    ttl as u64,
                                )
                                .await
                                .map_err(|e| {
                                    error!("Failed to cache data in Redis: {}", e);
                                })
                                .ok()?;
                        } else {
                            error!("target_id or target_payload was None while caching with TTL");
                            return None;
                        }
                    } else if let (Some(target_id), Some(target_payload)) =
                        (cache_event.target_id(), cache_event.target_payload())
                    {
                        let target_id_bytes = target_id.bytes();
                        let target_payload_bytes = target_payload.bytes();
                        redis_conn
                            .set::<_, _, String>(target_id_bytes, target_payload_bytes)
                            .await
                            .map_err(|e| {
                                error!("Failed to cache data in Redis: {}", e);
                            })
                            .ok()?;
                    } else {
                        error!("target_id or target_payload was None while caching without TTL");
                    }
                    event_data = Some(cache_event.target_payload().unwrap().bytes().to_vec());
                }
            }
            EventData::RouteEvent => {
                if let Some(route_event) = event.data_as_route_event() {
                    if let Some(target_id) = route_event.target_id() {
                        println!("Route Event:");
                        println!("  Target ID: {:?}", target_id);
                        let public_id = bs58::encode(target_id.bytes()).into_string();
                        println!("  Public ID: {}", public_id);
                        let subject = format!("profile.{}", public_id);
                        println!("  subject: {}", subject);
                        // Create NATS message
                        // Create NATS message
                        let nats_message = match NATSMessage::new(payload) {
                            Ok(msg) => msg,
                            Err(e) => {
                                error!("Failed to create NATS message: {}", e);
                                return None;
                            }
                        };
                        // Get NATS client
                        if let Some(nats_client) = nats_connection.get_client().await {
                            // Send the event to NATS
                            match nats_message.send_to_nats(&nats_client, subject).await {
                                Ok(_) => {
                                    println!("Successfully sent route event to NATS");
                                    return None;
                                }
                                Err(e) => {
                                    error!("Failed to send route event to NATS: {}", e);
                                    return None;
                                }
                            }
                        } else {
                            error!("NATS client not available");
                            return None;
                        }
                    } else {
                        error!("Target ID is missing.");
                        return None;
                    }
                }
            }
            EventData::NONE => {
                error!("No event data");
            }
            _ => {
                error!("Unknown event data type: {:?}", event.data_type());
            }
        }
    } else {
        error!("Failed to parse Event from payload");
        return None;
    }
    let response_data = match event_data {
        Some(data) => {
            let mut response = Vec::new();
            response.push(MessageType::Event as u8);
            response.extend_from_slice(&data);
            response
        }
        None => {
            error!("Event not found in Redis");
            let mut response = Vec::new();
            response.push(MessageType::Event as u8);
            response.extend_from_slice(b"Event not found");
            response
        }
    };

    let total_time = start_time.elapsed();
    log_timing(
        &server_state.settings,
        "Total time for handle_event",
        total_time,
    );

    Some(Message::Binary(response_data))
}

fn init_kas_keys(key_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pem_content = std::fs::read_to_string(key_path)?;
    let ec_pem_contents = pem_content.as_bytes();
    let pem = pem::parse(ec_pem_contents)?;
    if pem.tag() != "EC PRIVATE KEY" {
        return Err("Not an EC private key".into());
    }
    let kas_private_key = SecretKey::from_sec1_der(pem.contents())?;
    // Derive the public key from the private key
    let kas_public_key = kas_private_key.public_key();
    // Get the compressed representation of the public key
    let kas_public_key_compressed = kas_public_key.to_encoded_point(true);
    let kas_public_key_bytes = kas_public_key_compressed.as_bytes().to_vec();
    // Ensure the public key is 33 bytes
    assert_eq!(
        kas_public_key_bytes.len(),
        33,
        "KAS public key should be 33 bytes"
    );
    let kas_keys = KasKeys {
        public_key: kas_public_key_bytes,
        private_key: kas_private_key.to_bytes().to_vec(),
    };
    KAS_KEYS
        .set(Arc::new(kas_keys))
        .map_err(|_| "KAS keys already initialized".into())
}

fn get_kas_public_key() -> Option<Vec<u8>> {
    KAS_KEYS.get().map(|keys| keys.public_key.clone())
}

fn get_kas_private_key_bytes() -> Option<Vec<u8>> {
    KAS_KEYS.get().map(|keys| keys.private_key.clone())
}

struct ServerState {
    settings: ServerSettings,
    redis_client: RedisClient,
    s3_client: s3::Client,
}

impl ServerState {
    async fn new(settings: ServerSettings) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Attempting to connect to Redis at {}", settings.redis_url);
        let redis_client = match RedisClient::open(settings.redis_url.clone()) {
            Ok(client) => {
                info!("Successfully connected to Redis server");
                client
            }
            Err(e) => {
                error!("Failed to connect to Redis server: {}", e);
                return Err(Box::new(e));
            }
        };

        // Initialize AWS S3 client
        let config = aws_config::load_from_env().await;
        let s3_client = s3::Client::new(&config);

        Ok(ServerState {
            settings,
            redis_client,
            s3_client,
        })
    }
}

#[derive(Debug, Deserialize, Clone)]
struct ServerSettings {
    port: u16,
    tls_enabled: bool,
    tls_cert_path: String,
    tls_key_path: String,
    kas_key_path: String,
    enable_timing_logs: bool,
    nats_url: String,
    nats_subject: String,
    redis_url: String,
    jwt_validation_disabled: bool,
    jwt_public_key_path: Option<String>,
    s3_bucket: String,
}

fn log_timing(settings: &ServerSettings, message: &str, duration: std::time::Duration) {
    if settings.enable_timing_logs {
        info!("{}: {:?}", message, duration);
    }
}
fn load_config() -> Result<ServerSettings, Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    Ok(ServerSettings {
        port: env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()?,
        tls_enabled: env::var("TLS_CERT_PATH").is_ok(),
        tls_cert_path: env::var("TLS_CERT_PATH").unwrap_or_else(|_| {
            current_dir
                .join("fullchain.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        tls_key_path: env::var("TLS_KEY_PATH").unwrap_or_else(|_| {
            current_dir
                .join("privkey.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        kas_key_path: env::var("KAS_KEY_PATH").unwrap_or_else(|_| {
            current_dir
                .join("recipient_private_key.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        enable_timing_logs: env::var("ENABLE_TIMING_LOGS")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false),
        nats_url: env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string()),
        nats_subject: env::var("NATS_SUBJECT").unwrap_or_else(|_| "nanotdf.messages".to_string()),
        redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
        jwt_validation_disabled: env::var("JWT_VALIDATION_DISABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true),
        jwt_public_key_path: env::var("JWT_PUBLIC_KEY_PATH").ok(),
        s3_bucket: env::var("S3_BUCKET").unwrap_or_else(|_| "default-bucket".to_string()),
    })
}

/// Validate configuration parameters with clear error messages
fn validate_config(settings: &ServerSettings) -> Result<(), Box<dyn std::error::Error>> {
    // Validate port range
    if settings.port == 0 {
        return Err("PORT must be greater than 0".into());
    }

    // Validate TLS configuration
    if settings.tls_enabled {
        if settings.tls_cert_path.is_empty() {
            return Err("TLS_CERT_PATH must be set when TLS is enabled".into());
        }
        if settings.tls_key_path.is_empty() {
            return Err("TLS_KEY_PATH must be set when TLS is enabled".into());
        }
        // Check if cert file exists
        if !std::path::Path::new(&settings.tls_cert_path).exists() {
            return Err(
                format!("TLS certificate file not found: {}", settings.tls_cert_path).into(),
            );
        }
        // Check if key file exists
        if !std::path::Path::new(&settings.tls_key_path).exists() {
            return Err(format!("TLS key file not found: {}", settings.tls_key_path).into());
        }
    }

    // Validate KAS key path
    if settings.kas_key_path.is_empty() {
        return Err("KAS_KEY_PATH must be set".into());
    }
    if !std::path::Path::new(&settings.kas_key_path).exists() {
        return Err(format!("KAS private key file not found: {}", settings.kas_key_path).into());
    }

    // Validate NATS URL format
    if !settings.nats_url.starts_with("nats://") && !settings.nats_url.starts_with("tls://") {
        return Err(format!(
            "NATS_URL must start with 'nats://' or 'tls://': {}",
            settings.nats_url
        )
        .into());
    }

    // Validate NATS subject is not empty
    if settings.nats_subject.is_empty() {
        return Err("NATS_SUBJECT must not be empty".into());
    }

    // Validate Redis URL format
    if !settings.redis_url.starts_with("redis://") && !settings.redis_url.starts_with("rediss://") {
        return Err(format!(
            "REDIS_URL must start with 'redis://' or 'rediss://': {}",
            settings.redis_url
        )
        .into());
    }

    // Validate JWT configuration
    if !settings.jwt_validation_disabled && settings.jwt_public_key_path.is_none() {
        return Err("JWT_PUBLIC_KEY_PATH must be set when JWT validation is enabled".into());
    }
    if let Some(ref jwt_key_path) = settings.jwt_public_key_path {
        if !std::path::Path::new(jwt_key_path).exists() {
            return Err(format!("JWT public key file not found: {}", jwt_key_path).into());
        }
    }

    // Validate S3 bucket name
    if settings.s3_bucket.is_empty() {
        return Err("S3_BUCKET must not be empty".into());
    }

    info!("✓ Configuration validation passed");
    Ok(())
}

/// Validate media DRM configuration parameters
fn validate_media_config(
    max_concurrent_streams: u32,
    media_metrics_subject: &str,
    enable_analytics: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate max concurrent streams range
    if max_concurrent_streams == 0 {
        return Err("MAX_CONCURRENT_STREAMS must be greater than 0".into());
    }
    if max_concurrent_streams > 100 {
        return Err("MAX_CONCURRENT_STREAMS must not exceed 100 (current: {})".into());
    }

    // Validate metrics subject when analytics is enabled
    if enable_analytics && media_metrics_subject.is_empty() {
        return Err(
            "MEDIA_METRICS_SUBJECT must not be empty when ENABLE_MEDIA_ANALYTICS=true".into(),
        );
    }

    info!(
        "✓ Media DRM configuration validation passed (max_streams={}, analytics={})",
        max_concurrent_streams, enable_analytics
    );
    Ok(())
}

async fn load_apple_app_site_association() -> Arc<RwLock<String>> {
    let content = fs::read_to_string("apple-app-site-association.json")
        .await
        .expect("Failed to read apple-app-site-association.json");
    Arc::new(RwLock::new(content))
}
struct RewindableStream<S> {
    stream: S,
    buffer: Vec<u8>,
    position: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> RewindableStream<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
            position: 0,
        }
    }

    fn rewind(&mut self) {
        self.position = 0;
    }

    async fn read_until(&mut self, delimiter: u8) -> std::io::Result<Vec<u8>> {
        let mut result = Vec::new();
        loop {
            if self.position < self.buffer.len() {
                let byte = self.buffer[self.position];
                self.position += 1;
                result.push(byte);
                if byte == delimiter {
                    break;
                }
            } else {
                let mut buf = [0u8; 1024];
                let n = self.stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                self.buffer.extend_from_slice(&buf[..n]);
            }
        }
        Ok(result)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RewindableStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.position < self.buffer.len() {
            let remaining = self.buffer.len() - self.position;
            let to_read = buf.remaining().min(remaining);
            buf.put_slice(&self.buffer[self.position..self.position + to_read]);
            self.position += to_read;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RewindableStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn convert_rating_level(level: arkavo::RatingLevel) -> RatingLevel {
    match level.0 {
        x if x == arkavo::RatingLevel::unused.0 => RatingLevel::Unused,
        x if x == arkavo::RatingLevel::none.0 => RatingLevel::None,
        x if x == arkavo::RatingLevel::mild.0 => RatingLevel::Mild,
        x if x == arkavo::RatingLevel::moderate.0 => RatingLevel::Moderate,
        x if x == arkavo::RatingLevel::severe.0 => RatingLevel::Severe,
        _ => RatingLevel::Unused, // Default to Unused for any invalid values
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use elliptic_curve::ScalarPrimitive;
    use elliptic_curve::{CurveArithmetic, NonZeroScalar};
    use p256::NistP256;

    use super::*;

    #[tokio::test]
    async fn test_ephemeral_key_pair_and_custom_ecdh() {
        // Generate an ephemeral server key pair
        let server_private_key = EphemeralSecret::random(&mut OsRng);

        // Generate an ephemeral client key pair
        let client_private_key = EphemeralSecret::random(&mut OsRng);
        let client_public_key = PublicKey::from(&client_private_key);
        // Serialize the client public key
        let client_public_key_compressed = client_public_key.to_encoded_point(true);
        let client_public_key_bytes = client_public_key_compressed.as_bytes().to_vec();

        // Perform key agreement with the server's private key and the other party's (client's) public key
        let shared_secret = server_private_key.diffie_hellman(&client_public_key);

        // Convert the shared_secret into bytes
        let shared_secret_bytes = shared_secret.raw_secret_bytes().to_vec();
        let key_agreement_secret = hex::encode(shared_secret_bytes);
        // println!("Key agreement secret: {}", key_agreement_secret);

        let debug_server_private_key: DebugEphemeralSecret<NistP256> =
            unsafe { std::mem::transmute(server_private_key) };
        let secret_key = SecretKey::new(ScalarPrimitive::from(debug_server_private_key.scalar));
        // Deserialize the public key of client
        let public_key = PublicKey::from_sec1_bytes(&client_public_key_bytes)
            .expect("Error deserializing client public key");

        // Run custom ECDH
        let result = crypto::custom_ecdh(&secret_key, &public_key).expect("Error performing ECDH");

        let computed_secret = hex::encode(result);
        // println!("Computed shared secret: {}", computed_secret);

        assert_eq!(
            key_agreement_secret, computed_secret,
            "Key agreement secret does not match with computed shared secret."
        );
    }

    #[test]
    fn test_ecdh_known_values() -> Result<(), Box<dyn Error>> {
        // These are example values and should be replaced with actual test vectors
        // kas_private_key_bytes
        let server_private = "472c179ab235274ecb6678bcc5aa0a8578fc59b7431dd8dd37adbeb60c637618";
        let server_public = "03689f8463a91340e347847414f5ef67a6013ab7236b2229c70b717974ee74eb6c";
        // tdf_ephemeral_key
        let client_public = "02c8eee0d2c24780cbc29169739acc68904bdee3c0553d5ec1183ba476942de686";
        // kas_private_key_bytes
        let private_key_bytes = hex::decode(server_private).unwrap();
        // tdf_ephemeral_public_key
        let public_key_bytes = hex::decode(client_public).unwrap();
        // dek_shared_secret - from swift client
        // let expected_shared_secret = "0c53a5afa08acf1f2000cd9c050d35eca472d625a010146991aed9da05114e3b";
        let expected_shared_secret =
            "d5da0342ae4458cece9b3eb2d253c6212e9612ab9f8c9a4249ee4c9c59ccda13";

        let client_public_key = PublicKey::from_sec1_bytes(&public_key_bytes).unwrap();
        let kas_private_key_option: Option<[u8; 32]> = private_key_bytes.clone().try_into().ok();
        let kas_private_key_array = match kas_private_key_option {
            Some(array) => array,
            None => {
                return Err(Box::new(std::io::Error::other(
                    "Could not convert to array.",
                )))
            }
        };
        let server_secret_key = SecretKey::from_bytes(&kas_private_key_array.into())
            .map_err(|_| "Invalid private key")
            .ok();
        let server_secret_key = server_secret_key.unwrap();

        let server_public_key = server_secret_key.public_key();
        let compressed_public_key = server_public_key.to_encoded_point(true);
        let compressed_public_key_bytes = compressed_public_key.as_bytes();
        // println!("KAS Public Key Hex: {}", hex::encode(compressed_public_key_bytes));
        assert_eq!(hex::encode(compressed_public_key_bytes), server_public);

        let result = crypto::custom_ecdh(&server_secret_key, &client_public_key).unwrap();
        assert_eq!(hex::encode(result), expected_shared_secret);
        Ok(())
    }
    pub struct DebugEphemeralSecret<C>
    where
        C: CurveArithmetic,
    {
        pub scalar: NonZeroScalar<C>,
    }
}
