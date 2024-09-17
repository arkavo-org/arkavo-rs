mod contracts;

use std::env;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::RwLock;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::contracts::contract_simple_abac;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::{Aead, Key};
use aes_gcm::Aes256Gcm;
use async_nats::Message as NatsMessage;
use async_nats::{Client as NatsClient, PublishError};
use elliptic_curve::point::AffineCoordinates;
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use jsonwebtoken::{decode, DecodingKey, Validation};
use log::{error, info};
use nanotdf::{BinaryParser, ProtocolEnum};
use once_cell::sync::OnceCell;
use p256::ecdh::EphemeralSecret;
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_native_tls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;

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

#[derive(Debug)]
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
}

impl MessageType {
    fn from_u8(value: u8) -> Option<MessageType> {
        match value {
            0x01 => Some(MessageType::PublicKey),
            0x02 => Some(MessageType::KasPublicKey),
            0x03 => Some(MessageType::Rewrap),
            0x04 => Some(MessageType::RewrappedKey),
            0x05 => Some(MessageType::Nats),
            _ => None,
        }
    }
}

struct KasKeys {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

static KAS_KEYS: OnceCell<Arc<KasKeys>> = OnceCell::new();
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    // Load configuration
    let settings = load_config()?;
    // Load and cache the apple-app-site-association.json file
    let apple_app_site_association = load_apple_app_site_association().await;
    // Initialize KAS keys
    init_kas_keys(&settings.kas_key_path)?;

    // Set up TLS if not disabled
    let tls_acceptor = if settings.tls_enabled {
        Some(TlsAcceptor::from(load_tls_config(
            &settings.tls_cert_path,
            &settings.tls_key_path,
        )?))
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
    // Bind the server
    let listener = TcpListener::bind(format!("0.0.0.0:{}", settings.port)).await?;
    println!("Listening on: 0.0.0.0:{}", settings.port);

    // Accept connections
    while let Ok((stream, _)) = listener.accept().await {
        let tls_acceptor_clone = tls_acceptor.clone();
        let settings_clone = settings.clone();
        let nats_connection_clone = nats_connection.clone();
        let apple_app_site_association_clone = apple_app_site_association.clone();

        tokio::spawn(async move {
            // Use a trait object to hold either TcpStream or TlsStream<TcpStream>
            let stream: Box<dyn AsyncStream> = if let Some(tls_acceptor) = tls_acceptor_clone {
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
                &settings_clone,
                nats_connection_clone,
                apple_app_site_association_clone,
            )
            .await;
        });
    }

    Ok(())
}

fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<native_tls::TlsAcceptor, Box<dyn std::error::Error>> {
    let cert = std::fs::read(cert_path)?;
    let key = std::fs::read(key_path)?;

    let identity = native_tls::Identity::from_pkcs8(&cert, &key)?;
    let acceptor = native_tls::TlsAcceptor::new(identity)?;

    Ok(acceptor)
}

async fn handle_websocket(
    mut ws_stream: tokio_tungstenite::WebSocketStream<
        impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    >,
    settings: &ServerSettings,
    nats_connection: Arc<NatsConnection>,
) {
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
    // Create ConnectionState with the outgoing channel
    let connection_state = Arc::new(ConnectionState::new(outgoing_tx));
    // Set up NATS subscription for this connection
    let nats_task = tokio::spawn(handle_nats_subscription(
        nats_connection.clone(),
        settings.nats_subject.clone(),
        connection_state.clone(),
    ));
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
                            // println!("token: {}", token);
                            match verify_token(&token) {
                                Ok(claims) => {
                                    println!("Valid JWT received. Claims: {:?}", claims);
                                    // store the claims
                                    {
                                        let mut claims_lock = connection_state.claims_lock.write().unwrap();
                                        *claims_lock = Some(claims);
                                    }
                                }
                                Err(e) => {
                                    println!("Invalid JWT: {}", e);
                                }
                            }
                        } else if let Some(response) = handle_binary_message(&connection_state, msg.into_data(), settings, nats_connection.clone()).await {
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
}

async fn handle_connection(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    settings: &ServerSettings,
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
                handle_websocket(ws_stream, settings, nats_connection).await;
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
}
fn verify_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let secret = b"any_secret_key"; // The actual value doesn't matter when signature validation is disabled
    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)?;
    // println!("Decoded token: {:?}", token_data.claims);
    Ok(token_data.claims)
}

async fn handle_binary_message(
    connection_state: &Arc<ConnectionState>,
    data: Vec<u8>,
    settings: &ServerSettings,
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
        Some(MessageType::Rewrap) => handle_rewrap(connection_state, payload, settings).await, // incoming
        Some(MessageType::RewrappedKey) => None, // outgoing
        Some(MessageType::Nats) => {
            handle_nats_publish(connection_state, payload, settings, nats_connection).await
        } // internal
        None => {
            println!("Unknown message type: {:?}", message_type);
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
            let nats_client = nats_connection.get_client().await;
            if let Err(e) = nanotdf_msg
                .send_to_nats(&nats_client.unwrap(), settings.nats_subject.clone())
                .await
            {
                error!("Failed to send NanoTDF message to NATS: {}", e);
            } else {
                info!("NanoTDF message sent to NATS successfully");
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
    // timing
    let start_time = Instant::now();
    // session shared secret
    let session_shared_secret = {
        let shared_secret = connection_state.shared_secret_lock.read().unwrap();
        shared_secret.clone()
    };
    if session_shared_secret.is_none() {
        info!("Shared Secret not set");
        return None;
    }
    let session_shared_secret = session_shared_secret.unwrap();
    // Parse NanoTDF header
    let mut parser = BinaryParser::new(payload);
    let header = match BinaryParser::parse_header(&mut parser) {
        Ok(header) => header,
        Err(e) => {
            info!("Error parsing header: {:?}", e);
            return None;
        }
    };
    // timing
    let parse_time = start_time.elapsed();
    log_timing(settings, "Time to parse header", parse_time);
    // TDF ephemeral key
    let tdf_ephemeral_key_bytes = header.get_ephemeral_key();
    if tdf_ephemeral_key_bytes.len() != 33 {
        info!("Invalid TDF compressed ephemeral key length");
        return None;
    }
    // TDF contract
    let policy = header.get_policy();
    let locator = policy.get_locator();
    let locator = match locator {
        Some(locator) => locator,
        None => {
            info!("Missing TDF locator");
            return None;
        }
    };
    if locator.protocol_enum == ProtocolEnum::SharedResource {
        // println!("contract {}", locator.body.clone());
        if !locator.body.is_empty() {
            let claims_result = match connection_state.claims_lock.read() {
                Ok(read_lock) => match read_lock.clone() {
                    Some(value) => Ok(value.sub),
                    None => Err("Error: Clone cannot be performed"),
                },
                Err(_) => Err("Error: Read lock cannot be obtained"),
            };
            // execute contract
            let contract = contract_simple_abac::simple_abac::SimpleAbac::new();
            if claims_result.is_ok()
                && !contract.check_access(claims_result.unwrap(), locator.body.clone())
            {
                // binary response
                let mut response_data = Vec::new();
                response_data.push(MessageType::RewrappedKey as u8);
                response_data.extend_from_slice(tdf_ephemeral_key_bytes);
                // timing
                let total_time = start_time.elapsed();
                log_timing(settings, "Time to deny", total_time);
                // DENY
                return Some(Message::Binary(response_data));
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
    let dek_shared_secret_bytes = match custom_ecdh(&kas_private_key, &tdf_ephemeral_public_key) {
        Ok(secret) => secret,
        Err(e) => {
            info!("Error performing ECDH: {:?}", e);
            return None;
        }
    };
    let ecdh_time = ecdh_start.elapsed();
    log_timing(settings, "Time for ECDH operation", ecdh_time);

    // Encrypt dek_shared_secret with symmetric key using AES GCM
    let salt = connection_state.salt_lock.read().unwrap().clone().unwrap();
    let info = "rewrappedKey".as_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &session_shared_secret);
    let mut derived_key = [0u8; 32];
    hkdf.expand(info, &mut derived_key)
        .expect("HKDF expansion failed");

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = GenericArray::from_slice(&nonce);

    let key = Key::<Aes256Gcm>::from(derived_key);
    let cipher = Aes256Gcm::new(&key);

    let encryption_start = Instant::now();
    let wrapped_dek = cipher
        .encrypt(nonce, dek_shared_secret_bytes.as_ref())
        .expect("encryption failure!");
    let encryption_time = encryption_start.elapsed();
    log_timing(settings, "Time for AES-GCM encryption", encryption_time);

    // binary response
    let mut response_data = Vec::new();
    response_data.push(MessageType::RewrappedKey as u8);
    response_data.extend_from_slice(tdf_ephemeral_key_bytes);
    response_data.extend_from_slice(nonce);
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
            // println!("Shared Secret Connection: {}", hex::encode(shared_secret.clone().unwrap()));
            return None;
        }
    }
    // println!("Client Public Key payload: {}", hex::encode(payload.as_ref()));
    if payload.len() != 33 {
        println!("Client Public Key wrong size");
        println!("Client Public Key length: {}", payload.len());
        return None;
    }
    // Deserialize the public key sent by the client
    let client_public_key = match PublicKey::from_sec1_bytes(payload) {
        Ok(key) => key,
        Err(e) => {
            println!("Error deserializing client public key: {:?}", e);
            return None;
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
                        if let Err(e) = handle_nats_message(msg, connection_state.clone()).await {
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
async fn handle_nats_message(
    msg: NatsMessage,
    connection_state: Arc<ConnectionState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws_message = Message::Binary(
        vec![MessageType::Nats as u8]
            .into_iter()
            .chain(msg.payload)
            .collect(),
    );
    connection_state.outgoing_tx.send(ws_message)?;
    Ok(())
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

fn custom_ecdh(
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Get the scalar from the secret key
    let scalar = secret_key.to_nonzero_scalar();
    // println!("scalar {}", hex::encode(scalar.to_bytes()));

    // Get the public key point
    let public_key_point = public_key.to_projective();

    // Perform the ECDH operation
    let shared_point = (public_key_point * *scalar).to_affine();

    // Extract the x-coordinate as the shared secret
    let x_coordinate = shared_point.x();
    let shared_secret = x_coordinate.to_vec();
    // println!("Raw shared secret: {}", hex::encode(&shared_secret));

    Ok(shared_secret)
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
                .join("../../fullchain.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        tls_key_path: env::var("TLS_KEY_PATH").unwrap_or_else(|_| {
            current_dir
                .join("../../privkey.pem")
                .to_str()
                .unwrap()
                .to_string()
        }),
        kas_key_path: env::var("KAS_KEY_PATH").unwrap_or_else(|_| {
            current_dir
                .join("../../recipient_private_key.pem")
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
    })
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
        let result = custom_ecdh(&secret_key, &public_key).expect("Error performing ECDH");

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
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
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

        let result = custom_ecdh(&server_secret_key, &client_public_key).unwrap();
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
