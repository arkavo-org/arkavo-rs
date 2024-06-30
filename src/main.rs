use std::sync::Arc;
use std::sync::RwLock;

use aes_gcm::aead::{Key, NewAead};
use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::Aes256Gcm;
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use once_cell::sync::OnceCell;
use p256::{
    elliptic_curve::sec1::ToEncodedPoint,
    ProjectivePoint,
    PublicKey,
    SecretKey,
};
use p256::ecdh::EphemeralSecret;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

use crate::nanotdf::BinaryParser;

mod nanotdf;

#[derive(Serialize, Deserialize, Debug)]
struct PublicKeyMessage {
    salt: Vec<u8>,
    public_key: Vec<u8>,
}

#[derive(Debug)]
struct ConnectionState {
    salt_lock: RwLock<Option<Vec<u8>>>,
    shared_secret_lock: RwLock<Option<Vec<u8>>>,
}

impl ConnectionState {
    fn new() -> Self {
        println!("New ConnectionState");
        ConnectionState {
            salt_lock: RwLock::new(None),
            shared_secret_lock: RwLock::new(None),
        }
    }
}

#[derive(Debug)]
enum MessageType {
    PublicKey = 0x01,
    KasPublicKey = 0x02,
    Rewrap = 0x03,
    RewrappedKey = 0x04,
}

impl MessageType {
    fn from_u8(value: u8) -> Option<MessageType> {
        match value {
            0x01 => Some(MessageType::PublicKey),
            0x02 => Some(MessageType::KasPublicKey),
            0x03 => Some(MessageType::Rewrap),
            0x04 => Some(MessageType::RewrappedKey),
            _ => None,
        }
    }
}

struct KasKeys {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

static KAS_KEYS: OnceCell<Arc<KasKeys>> = OnceCell::new();

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // KAS public key
    init_kas_keys().expect("KAS key not loaded");
    // Bind the server to localhost on port 8080
    let try_socket = TcpListener::bind("0.0.0.0:8080").await;
    let listener = match try_socket {
        Ok(socket) => socket,
        Err(e) => {
            println!("Failed to bind to port: {}", e);
            return;
        }
    };
    println!("Listening on: 0.0.0.0:8080");
    // Accept connections
    while let Ok((stream, _)) = listener.accept().await {
        let connection_state = Arc::new(ConnectionState::new());
        tokio::spawn(async move {
            handle_connection(stream, connection_state).await
        });
    }
}

async fn handle_connection(stream: TcpStream, connection_state: Arc<ConnectionState>) {
    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("Error during the websocket handshake occurred: {}", e);
            return;
        }
    };
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    // Handle incoming WebSocket messages
    while let Some(message) = ws_receiver.next().await {
        match message {
            Ok(msg) => {
                // println!("Received message: {:?}", msg);
                if msg.is_close() {
                    println!("Received a close message.");
                    return;
                }
                if let Some(response) = handle_binary_message(&connection_state, msg.into_data()).await
                {
                    // TODO remove clone
                    ws_sender.send(response.clone()).await.expect("ws send failed");
                }
            }
            Err(e) => {
                eprintln!("Error reading message: {}", e);
                break;
            }
        }
    }
}

async fn handle_binary_message(
    connection_state: &Arc<ConnectionState>,
    data: Vec<u8>,
) -> Option<Message> {
    if data.len() < 1 {
        println!("Invalid message format");
        return None;
    }
    let message_type = MessageType::from_u8(data[0]);
    let payload = &data[1..data.len()];

    match message_type {
        Some(MessageType::PublicKey) => handle_public_key(connection_state, payload).await,
        Some(MessageType::KasPublicKey) => handle_kas_public_key(payload).await,
        Some(MessageType::Rewrap) => handle_rewrap(connection_state, payload).await,
        Some(MessageType::RewrappedKey) => None,
        None => {
            println!("Unknown message type: {:?}", message_type);
            None
        }
    }
}

struct PrintOnDrop;

impl Drop for PrintOnDrop {
    fn drop(&mut self) {
        println!("END handle_rewrap");
    }
}

async fn handle_rewrap(
    connection_state: &Arc<ConnectionState>,
    payload: &[u8],
) -> Option<Message> {
    let _print_on_drop = PrintOnDrop;
    println!("BEGIN handle_rewrap");
    let session_shared_secret = {
        let shared_secret = connection_state.shared_secret_lock.read().unwrap();
        shared_secret.clone()
    };
    if session_shared_secret == None {
        println!("Shared Secret not set");
        return None;
    }
    let session_shared_secret = session_shared_secret.unwrap();
    // Parse NanoTDF header
    let mut parser = BinaryParser::new(payload);
    let header = match BinaryParser::parse_header(&mut parser) {
        Ok(header) => header,
        Err(e) => {
            println!("Error parsing header: {:?}", e);
            return None;
        }
    };
    // Extract the policy
    let policy = header.get_policy();
    println!("policy binding hex: {}", hex::encode(policy.get_binding().clone().unwrap()));
    // TDF ephemeral key
    let tdf_ephemeral_key_bytes = header.get_ephemeral_key();
    println!("tdf_ephemeral_key hex: {}", hex::encode(tdf_ephemeral_key_bytes));
    // Deserialize the public key sent by the client
    if tdf_ephemeral_key_bytes.len() != 33 {
        println!("Invalid TDF compressed ephemeral key length");
        return None;
    }
    // Deserialize the public key sent by the client
    let tdf_ephemeral_public_key = match PublicKey::from_sec1_bytes(tdf_ephemeral_key_bytes) {
        Ok(key) => key,
        Err(e) => {
            println!("Error deserializing TDF ephemeral public key: {:?}", e);
            return None;
        }
    };
    let kas_private_key_bytes = get_kas_private_key_bytes().unwrap();
    // Perform custom ECDH
    let dek_shared_secret_bytes = match custom_ecdh(&kas_private_key_bytes, &tdf_ephemeral_public_key) {
        Ok(secret) => secret,
        Err(e) => {
            println!("Error performing ECDH: {:?}", e);
            return None;
        }
    };
    // let hex_str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    // let dek_shared_secret_bytes = hex::decode(hex_str).expect("Decoding failed");
    println!("dek_shared_secret {}", hex::encode(&dek_shared_secret_bytes));
    // Encrypt dek_shared_secret with symmetric key using AES GCM
    let salt = connection_state.salt_lock.read().unwrap().clone().unwrap();
    let info = "rewrappedKey".as_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &session_shared_secret);
    let mut derived_key = [0u8; 32];
    hkdf.expand(info, &mut derived_key).expect("HKDF expansion failed");
    println!("Derived Session Key: {}", hex::encode(&derived_key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = GenericArray::from_slice(&nonce);
    println!("nonce {}", hex::encode(nonce));
    let key = Key::<Aes256Gcm>::from(derived_key);
    let cipher = Aes256Gcm::new(&key);
    let wrapped_dek = cipher.encrypt(nonce, dek_shared_secret_bytes.as_ref())
        .expect("encryption failure!");
    println!("Rewrapped Key and Authentication tag {}", hex::encode(&wrapped_dek));
    // binary response
    let mut response_data = Vec::new();
    response_data.push(MessageType::RewrappedKey as u8);
    response_data.extend_from_slice(tdf_ephemeral_key_bytes);
    response_data.extend_from_slice(&nonce);
    response_data.extend_from_slice(&wrapped_dek);
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
            println!("Shared Secret Connection: {}", hex::encode(shared_secret.clone().unwrap()));
            return None;
        }
    }
    println!("Client Public Key payload: {}", hex::encode(payload.as_ref()));
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
    println!("Shared Secret +++++++++++++");
    println!("Shared Secret: {}", hex::encode(shared_secret_bytes));
    println!("Shared Secret +++++++++++++");
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
    println!("Session Salt: {}", hex::encode(salt));
    // Convert to compressed representation
    let compressed_public_key = server_public_key.to_encoded_point(true);
    let compressed_public_key_bytes = compressed_public_key.as_bytes();
    // Send server_public_key as publicKey message
    let mut response_data = Vec::new();
    // Appending MessageType::PublicKey
    response_data.push(MessageType::PublicKey as u8);
    // Appending server_public_key bytes
    response_data.extend_from_slice(&compressed_public_key_bytes);
    // Appending salt bytes
    response_data.extend_from_slice(&salt);
    Some(Message::Binary(response_data))
}

async fn handle_kas_public_key(_: &[u8]) -> Option<Message> {
    println!("Handling KAS public key");
    if let Some(kas_public_key_bytes) = get_kas_public_key() {
        println!("KAS Public Key Size: {} bytes", kas_public_key_bytes.len());
        println!("KAS Public Key Hex: {}", hex::encode(&kas_public_key_bytes));
        let mut response_data = Vec::new();
        response_data.push(MessageType::KasPublicKey as u8);
        response_data.extend_from_slice(&kas_public_key_bytes);
        return Some(Message::Binary(response_data));
    }
    None
}

fn custom_ecdh(private_key_bytes: &[u8], public_key: &PublicKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Convert private key bytes to fixed-size array
    let private_key_array: [u8; 32] = private_key_bytes.try_into()
        .map_err(|_| "Invalid private key length")?;
    // Debug: Print the first and last byte of the private key (avoid printing the whole key for security reasons)
    println!("Private key first byte: 0x{:02x}, last byte: 0x{:02x}",
             private_key_array[0], private_key_array[31]);
    let secret_key = SecretKey::from_bytes((&private_key_array).into())
        .map_err(|_| "Invalid private key")?;
    let scalar = secret_key.to_nonzero_scalar();
    println!("scalar {}", scalar);
    // Get the public key point as ProjectivePoint
    let public_key_point: ProjectivePoint = public_key.to_projective();
    // Perform the ECDH operation
    let shared_point = (public_key_point * *scalar).to_affine();
    // Convert the resulting point to bytes (x-coordinate)
    let shared_secret = shared_point.to_encoded_point(false).x().unwrap().to_vec();
    // Hash the shared secret using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&shared_secret);
    let hashed_secret = hasher.finalize().to_vec();
    Ok(hashed_secret)
}

fn init_kas_keys() -> Result<(), Box<dyn std::error::Error>> {
    let pem_content = std::fs::read_to_string("recipient_private_key.pem")?;
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
    assert_eq!(kas_public_key_bytes.len(), 33, "KAS public key should be 33 bytes");
    let kas_keys = KasKeys {
        public_key: kas_public_key_bytes,
        private_key: kas_private_key.to_bytes().to_vec(),
    };
    KAS_KEYS.set(Arc::new(kas_keys))
        .map_err(|_| "KAS keys already initialized".into())
}

fn get_kas_public_key() -> Option<Vec<u8>> {
    KAS_KEYS.get().map(|keys| keys.public_key.clone())
}

fn get_kas_private_key_bytes() -> Option<Vec<u8>> {
    KAS_KEYS.get().map(|keys| keys.private_key.clone())
}