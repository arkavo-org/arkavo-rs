use std::sync::Arc;
use std::sync::RwLock;

use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Key};
use aes_gcm::aead::generic_array::GenericArray;
use futures_util::{SinkExt, StreamExt};
use once_cell::sync::OnceCell;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::{EphemeralSecret, PublicKey};

use nanotdf::BinaryParser;

use crate::nanotdf::Header;

mod nanotdf;

#[derive(Serialize, Deserialize, Debug)]
struct PublicKeyMessage {
    public_key: Vec<u8>,
}

#[derive(Debug)]
struct ConnectionState {
    // TODO x25519_dalek::SharedSecret``
    shared_secret: RwLock<Option<Vec<u8>>>,
}

impl ConnectionState {
    fn new() -> Self {
        println!("New ConnectionState");
        ConnectionState {
            shared_secret: RwLock::new(None),
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
    private_key: SecretKey,
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
                println!("Received message: {:?}", msg);
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

async fn handle_rewrap(
    connection_state: &Arc<ConnectionState>,
    payload: &[u8],
) -> Option<Message> {
    let session_shared_secret = {
        let shared_secret = connection_state.shared_secret.read().unwrap();
        shared_secret.clone()
    };
    println!("Shared Secret Connection: {}", hex::encode(session_shared_secret.clone().unwrap()));
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
    let policy = Header::get_policy(&header);
    println!("policy {:?}", policy);
    let policy = header.get_policy();
    println!("policy binding hex: {}", hex::encode(policy.get_binding().clone().unwrap()));
    println!("tdf_ephemeral_key hex: {}", hex::encode(header.get_ephemeral_key()));
    let tdf_ephemeral_key_bytes = header.get_ephemeral_key();
    // Deserialize the public key sent by the client
    if tdf_ephemeral_key_bytes.len() != 33 {
        return None;
    }
    // If length is 33, it is possible that the public key was prefixed with 0x04, which is common in some implementations
    let payload_arr = <[u8; 32]>::try_from(&tdf_ephemeral_key_bytes[1..]).unwrap();
    let tdf_ephemeral_public_key = PublicKey::from(payload_arr);
    println!("tdf_ephemeral_key {:?}", tdf_ephemeral_public_key);
    let kas_private_key = get_kas_private_key().unwrap();
    println!("kas_private_key {:?}", kas_private_key);
    // TODO Verify the policy binding
    // TODO Access check
    // Generate Symmetric Key
    // TODO use KAS private key in key agreement to find the DEK symmetric key
    // let secret_key = StaticSecret::from(kas_private_key.to_bytes());
    // // salt
    // let mut hasher = Sha256::new();
    // hasher.update(b"L1L");
    // let salt = hasher.finalize();
    // // Key derivative
    // let (derived_key, _, _) = Hkdf::<Sha256>::new(Some(&salt[..]), &session_key);
    // let derived_key_bytes = derived_key.to_bytes();
    let dek_shared_secret: Vec<u8> = vec![0; 32];
    println!("dek_shared_secret {:?}", dek_shared_secret);
    // Encrypt dek_shared_secret with session_shared_secret using AES GCM
    // Assuming `dek_shared_secret` and `session_shared_secret` as following,
    // let session_shared_secret: Vec<u8> = vec![0; 32];
    let session_shared_secret = session_shared_secret.unwrap();
    let key = Key::<Aes256Gcm>::from_slice(&session_shared_secret);
    let cipher = Aes256Gcm::new(&key);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = GenericArray::from_slice(&nonce);
    let mut wrapped_dek_shared_secret = cipher.encrypt(nonce, dek_shared_secret.as_ref())
        .expect("encryption failure!");
    let mut response_data = Vec::new();
    response_data.push(MessageType::RewrappedKey as u8);
    response_data.append(&mut wrapped_dek_shared_secret);
    return Some(Message::Binary(response_data));
}

async fn handle_public_key(
    connection_state: &Arc<ConnectionState>,
    payload: &[u8],
) -> Option<Message> {
    {
        let shared_secret_lock = connection_state.shared_secret.read();
        let shared_secret = shared_secret_lock.unwrap();
        if shared_secret.is_some() {
            println!("Shared Secret Connection: {}", hex::encode(shared_secret.clone().unwrap()));
            return None;
        }
    }
    println!("Client Public Key payload: {}", hex::encode(payload.as_ref()));
    if payload.len() != 32 {
        return None;
    }
    let payload_arr: [u8; 32];
    // Deserialize the public key sent by the client
    // If payload length is 33, compressed 32 with 1 leading byte
    payload_arr = <[u8; 32]>::try_from(&payload[..]).unwrap();
    let client_public_key = PublicKey::from(payload_arr);
    println!("Client Public Key: {:?}", client_public_key);
    // Generate an ephemeral private key
    let server_private_key = EphemeralSecret::random_from_rng(OsRng);
    let server_public_key = PublicKey::from(&server_private_key);
    // Perform the key agreement
    let shared_secret = server_private_key.diffie_hellman(&client_public_key);
    let shared_secret_bytes = shared_secret.as_bytes();
    println!("Shared Secret +++++++++++++");
    println!("Shared Secret: {}", hex::encode(shared_secret_bytes));
    println!("Shared Secret +++++++++++++");
    {
        let shared_secret = connection_state.shared_secret.write();
        *shared_secret.unwrap() = Some(shared_secret_bytes.to_vec());
    }
    // Convert server_public_key to bytes
    let server_public_key_bytes = server_public_key.to_bytes();
    // Send server_public_key as publicKey message
    let mut response_data = Vec::new();
    // Appending MessageType::PublicKey
    response_data.push(MessageType::PublicKey as u8);
    // Appending server_public_key bytes
    response_data.extend_from_slice(&server_public_key_bytes);
    Some(Message::Binary(response_data))
}

async fn handle_kas_public_key(_: &[u8]) -> Option<Message> {
    println!("Handling KAS public key");
    if let Some(kas_public_key_bytes) = get_kas_public_key() {
        println!("KAS Public Key Size: {} bytes", kas_public_key_bytes.len());
        let mut response_data = Vec::new();
        response_data.push(MessageType::KasPublicKey as u8);
        response_data.extend_from_slice(&kas_public_key_bytes);
        return Some(Message::Binary(response_data));
    }
    None
}

fn init_kas_keys() -> Result<(), Box<dyn std::error::Error>> {
    let pem_content = std::fs::read_to_string("recipient_private_key.pem")?;
    let ec_pem_contents = pem_content.as_bytes();
    let pem = pem::parse(ec_pem_contents)?;

    if pem.tag() != "EC PRIVATE KEY" {
        return Err("Not an EC private key".into());
    }

    let kas_private_key = SecretKey::from_sec1_der(pem.contents())?;
    let kas_public_key = kas_private_key.public_key();
    let kas_public_key_der = kas_public_key.to_encoded_point(true);
    let kas_public_key_der_bytes = kas_public_key_der.as_bytes().to_vec();

    let kas_keys = KasKeys {
        public_key: kas_public_key_der_bytes,
        private_key: kas_private_key,
    };

    KAS_KEYS.set(Arc::new(kas_keys))
        .map_err(|_| "KAS keys already initialized".into())
}

fn get_kas_public_key() -> Option<Vec<u8>> {
    KAS_KEYS.get().map(|keys| keys.public_key.clone())
}

fn get_kas_private_key() -> Option<SecretKey> {
    KAS_KEYS.get().map(|keys| keys.private_key.clone())
}