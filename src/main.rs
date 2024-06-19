use std::fs;
use std::sync::Arc;
use std::sync::RwLock;

use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Key};
use aes_gcm::aead::generic_array::GenericArray;
use futures_util::{SinkExt, StreamExt};
use lazy_static::lazy_static;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
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

#[derive(Serialize, Deserialize, Debug)]
struct ConnectionState {
    shared_secret: Option<Vec<u8>>,
}

impl ConnectionState {
    fn new() -> Self {
        ConnectionState {
            shared_secret: None,
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

lazy_static! {
    static ref KAS_PUBLIC_KEY_DER: RwLock<Option<Vec<u8>>> = RwLock::new(None);
}

const ENCRYPTED_PAYLOAD: &str = "\
                4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80\
                80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70\
                6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36\
                ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15\
                12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c\
                c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da";

#[tokio::main]
async fn main() {
    // KAS public key
    // Load the PEM file
    let pem_content = fs::read_to_string("recipient_private_key.pem").unwrap();
    // Load the private key from PEM format
    let ec_pem_contents = pem_content.as_bytes();
    // Parse the pem file
    let pem = pem::parse(ec_pem_contents).expect("Failed to parse the PEM.");
    // Ensure it's an EC private key
    if pem.tag() != "EC PRIVATE KEY" {
        println!("Not an EC private key: {:?}", pem.tag());
    }
    // Parse the private key
    let kas_private_key = SecretKey::from_sec1_der(pem.contents());
    // Check if successful and continue if Ok
    match kas_private_key {
        Ok(kas_private_key) => {
            // Derive the corresponding public key
            let kas_public_key = kas_private_key.public_key();
            let kas_public_key_der = kas_public_key.to_encoded_point(true);
            let kas_public_key_der_bytes = kas_public_key_der.as_bytes().to_vec();
            // Set static KAS_PUBLIC_KEY_DER
            {
                let mut kas_public_key_der = KAS_PUBLIC_KEY_DER.write().unwrap();
                *kas_public_key_der = Some(kas_public_key_der_bytes);
            }
        }
        Err(error) => println!("Problem with the secret key: {:?}", error),
    }
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
        let connection_state = Arc::new(Mutex::new(ConnectionState::new()));
        tokio::spawn(handle_connection(stream, connection_state));
    }
}

async fn handle_connection(stream: TcpStream, connection_state: Arc<Mutex<ConnectionState>>) {
    // FIXME read from rewrap
    let ec_bytes: Vec<u8> = hex::decode(ENCRYPTED_PAYLOAD.replace(" ", "")).unwrap();
    let _nanotdf = BinaryParser::new(&*ec_bytes);

    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("Error during the websocket handshake occurred: {}", e);
            return;
        }
    };
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    // TODO rewrap
    // let compressed_pub_key = get_compressed_public_key().await.expect("Failed to get compressed public key");

    // Handle incoming WebSocket messages
    while let Some(message) = ws_receiver.next().await {
        match message {
            Ok(msg) => {
                println!("Received message: {:?}", msg);
                if msg.is_close() {
                    println!("Received a close message.");
                    return;
                }
                if let Some(response) =
                    handle_binary_message(connection_state.clone(), msg.into_data()).await
                {
                    // TODO remove clone
                    ws_sender.send(response.clone()).await.unwrap();
                    println!("Message type first byte: {:?}", response.into_data().get(0));
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
    connection_state: Arc<Mutex<ConnectionState>>,
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
    connection_state: Arc<Mutex<ConnectionState>>,
    payload: &[u8],
) -> Option<Message> {
    let session_shared_secret = {
        let connection_state = connection_state.lock().await;
        // Ensure we have a shared secret
        match &connection_state.shared_secret {
            Some(secret) => Some(secret.clone()),
            None => {
                eprintln!("No shared secret available");
                None
            }
        }
    };
    println!("session shared_secret {:?}", session_shared_secret);
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
    println!("tdf_ephemeral_key {:?}", header.get_ephemeral_key());
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

    // TODO Verify the policy binding
    // TODO Access check
    // Generate Symmetric Key
    // TODO use KAS private key in key agreement to find the DEK symmetric key
    // // Read the DER-encoded private key
    // let der = KAS_PUBLIC_KEY_DER.read().unwrap().as_ref().unwrap().clone();
    // let kas_private_key = PKey::private_key_from_der(&der).unwrap();
    // let session_key = private_key.diffie_hellman(&public_key);
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
    let nonce: [u8; 12] = rand::thread_rng().gen(); // NONCE MUST BE UNIQUE FOR EACH MESSAGE
    let nonce = GenericArray::from_slice(&nonce);
    let mut wrapped_dek_shared_secret = cipher.encrypt(nonce, dek_shared_secret.as_ref())
        .expect("encryption failure!");
    let mut response_data = Vec::new();
    response_data.push(MessageType::RewrappedKey as u8);
    response_data.append(&mut wrapped_dek_shared_secret);
    return Some(Message::Binary(response_data));
}

async fn handle_public_key(
    connection_state: Arc<Mutex<ConnectionState>>,
    payload: &[u8],
) -> Option<Message> {
    // Generate an ephemeral private key
    let my_private_key = EphemeralSecret::random_from_rng(OsRng);
    let server_public_key = PublicKey::from(&my_private_key);
    let payload_arr: [u8; 32];
    // Deserialize the public key sent by the client
    if payload.len() == 33 {
        // If payload length is 33, it is possible that the public key was prefixed with 0x04, which is common in some implementations
        payload_arr = <[u8; 32]>::try_from(&payload[1..]).unwrap();
    } else if payload.len() != 32 {
        return None;
    } else {
        payload_arr = payload.try_into().unwrap();
    }
    let peer_public_key = PublicKey::from(payload_arr);
    println!("Peer Public Key: {}", hex::encode(peer_public_key.as_ref()));

    // Perform the key agreement
    let shared_secret = my_private_key.diffie_hellman(&peer_public_key);
    let shared_secret_bytes = shared_secret.as_bytes();
    println!("Shared Secret: {}", hex::encode(shared_secret_bytes));
    // Hash the shared secret
    let mut hasher = Sha256::new();
    hasher.update(shared_secret_bytes);
    let hashed_secret = hasher.finalize();
    // TODO calculate symmetricKey us hkdf

    // Convert server_public_key to bytes
    let server_public_key_bytes = server_public_key.to_bytes();
    // Determine prefix: 0x02 for even y, 0x03 for odd y
    let prefix = if server_public_key_bytes[31] % 2 == 0 { 0x02 } else { 0x03 };
    // Prepare a vector to hold the compressed key (1 byte prefix + 32 bytes key)
    let mut server_compressed_public_key = Vec::with_capacity(33);
    server_compressed_public_key.push(prefix);
    server_compressed_public_key.extend_from_slice(&server_public_key_bytes);
    println!("Compressed Server PublicKey: {:}", hex::encode(&server_compressed_public_key));
    println!("Server Public Key Size: {} bytes", &server_compressed_public_key.len());
    // Send server_public_key as publicKey message
    let mut response_data = Vec::new();
    // Appending MessageType::PublicKey
    response_data.push(MessageType::PublicKey as u8);
    // Appending my_public_key bytes
    response_data.append(&mut server_compressed_public_key);

    // Update the connection state with the hashed shared secret
    // TODO store symmetric key not shared secret
    let mut connection_state = connection_state.lock().await;
    connection_state.shared_secret = Some(hashed_secret.to_vec());
    Some(Message::Binary(response_data))
}

async fn handle_kas_public_key(payload: &[u8]) -> Option<Message> {
    println!("Received KAS public key: {:?}", payload);
    // TODO Use static KAS_PUBLIC_KEY_DER
    let kas_public_key_der = KAS_PUBLIC_KEY_DER.read().unwrap();
    if let Some(ref kas_public_key_bytes) = *kas_public_key_der {
        println!("KAS Public Key Size: {} bytes", kas_public_key_bytes.len());
        // TODO make sure compressed key of 33 bytes is sent not 65
        let mut response_data = Vec::new();
        response_data.push(MessageType::KasPublicKey as u8);
        response_data.append(&mut AsRef::<[u8]>::as_ref(kas_public_key_bytes).to_vec());
        return Some(Message::Binary(response_data));
    }
    return None;
}