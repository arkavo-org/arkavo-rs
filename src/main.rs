mod nanotdf;

use std::fs;
use std::sync::Arc;

use data_encoding::HEXUPPER;
use futures_util::{SinkExt, StreamExt};
use lazy_static::lazy_static;
use nanotdf::BinaryParser;
use openssl::ec::PointConversionForm;
use openssl::pkey::PKey;
use ring::{agreement, digest, rand};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

#[derive(Serialize, Deserialize, Debug)]
struct PublicKeyMessage {
    public_key: Vec<u8>,
}

#[derive(Debug)]
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

enum MessageType {
    PublicKey = 0x01,
    KasPublicKey = 0x02,
}

impl MessageType {
    fn from_u8(value: u8) -> Option<MessageType> {
        match value {
            0x01 => Some(MessageType::PublicKey),
            0x02 => Some(MessageType::KasPublicKey),
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
    println!("OpenSSL build info: {}", openssl::version::version());
    // KAS public key
    // Load the PEM file
    let pem_content = fs::read_to_string("recipient_private_key.pem").unwrap();
    // Load the private key from PEM format
    let pkey = PKey::private_key_from_pem(pem_content.as_bytes());
    let private_key = pkey.unwrap().ec_key().unwrap();
    // Extract public key
    let ec_group = private_key.group();
    let public_key = private_key.public_key();
    let mut bn_ctx = openssl::bn::BigNumContext::new().unwrap();
    let public_key_bytes = public_key
        .to_bytes(&ec_group, PointConversionForm::UNCOMPRESSED, &mut bn_ctx)
        .unwrap();
    // Hash the public key to get the fingerprint
    let fingerprint = digest::digest(&digest::SHA256, &*public_key_bytes);
    // Print the fingerprint in hexadecimal format
    println!(
        "KAS Public Key Fingerprint: {}",
        HEXUPPER.encode(fingerprint.as_ref())
    );
    // Set static KAS_PUBLIC_KEY_DER
    {
        // let mut kas_public_key_der = KAS_PUBLIC_KEY_DER.lock().await;
        // *kas_public_key_der = public_key_bytes;
        let mut kas_public_key_der = KAS_PUBLIC_KEY_DER.write().unwrap();
        *kas_public_key_der = Some(public_key_bytes);
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
    let _nanotdf = BinaryParser::new(ec_bytes);

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
                if let Some(response) =
                    handle_binary_message(connection_state.clone(), msg.into_data()).await
                {
                    let response = response.into();
                    ws_sender.send(response).await.unwrap();
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
        None => {
            println!("Unknown message type");
            None
        }
    }
}

async fn handle_public_key(
    connection_state: Arc<Mutex<ConnectionState>>,
    payload: &[u8],
) -> Option<Message> {
    let private_key =
        agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rand::SystemRandom::new())
            .unwrap();
    let server_public_key = private_key.compute_public_key().unwrap();
    // Hex
    let server_public_key_hex = hex::encode(server_public_key.as_ref());
    println!("Server Public Key: {}", server_public_key_hex);
    let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, payload);
    {
        let mut state = connection_state.lock().await;
        let temp_secret =
            agreement::agree_ephemeral(private_key, &peer_public_key, |key_material| {
                // consume key_material here and generally perform desired computations
                Ok::<_, ring::error::Unspecified>(key_material.to_vec())
            });
        match temp_secret {
            Ok(shared_secret) => {
                if let Ok(secret) = shared_secret {
                    println!("Shared secret stored: {:?}", secret);
                    state.shared_secret = Some(secret);
                }
            }
            Err(e) => {
                println!("Failed to get shared_secret: {}", e);
                return None;
            }
        }
    }
    // Send server_public_key in DER format
    Some(Message::Binary(server_public_key.as_ref().to_vec()))
}

async fn handle_kas_public_key(payload: &[u8]) -> Option<Message> {
    println!("Received KAS public key: {:?}", payload);
    // Use static KAS_PUBLIC_KEY_DER
    let kas_public_key_der = KAS_PUBLIC_KEY_DER.read().unwrap();
    if let Some(ref public_key) = *kas_public_key_der {
        return Some(Message::Binary(public_key.clone()));
    }
    return None;
}

// async fn get_compressed_public_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//     println!("get_compressed_public_key");
//     // Load the private key from DER format
//     // let mut file = File::open("recipient_private_key.der").await?;
//     // let mut private_key_der = vec![];
//     // file.read_to_end(&mut private_key_der).await?;
//     // let ec_key = EcKey::private_key_from_der(&private_key_der)?;
//     // Load the EC private key from the PEM file
//     let ec_key = load_ec_private_key("recipient_private_key.pem").await?;
//     // Generate EC private key
//     // let ec_key = generate_ecdh_key()?;
//
//     let curve_name = ec_key.group().curve_name();
//     match curve_name {
//         Some(nid) => {
//             let name = nid.long_name();
//             match name {
//                 Ok(value) => println!("Curve Name: {}", value),
//                 Err(_) => println!("Curve Name: failed to get"),
//             }
//         },
//         None => {
//             println!("failed to get curve_name");
//         }
//     }
//
//     // Extract private key
//     let private_key_bn_result = ec_key.private_key().to_owned();
//     let private_key_bn = match private_key_bn_result {
//         Ok(bn) => bn,
//         Err(e) => {
//             println!("Failed to extract private key: {}", e);
//             return Err(Box::new(e));
//         },
//     };
//     let private_key_hex = hex::encode(&private_key_bn.to_vec());
//
//     // Extract public key
//     let ec_group = ec_key.group();
//     let public_key = ec_key.public_key();
//     let mut ctx = openssl::bn::BigNumContext::new()?;
//     let public_key_bytes = public_key.to_bytes(&ec_group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
//
//     // Convert public key to hex
//     let public_key_hex = hex::encode(public_key_bytes);
//
//     // Log the information
//     println!("EC Private Key: {}", private_key_hex);
//     println!("EC Public Key: {}", public_key_hex);
//
//     // Get the compressed public key
//     let mut bn_ctx = openssl::bn::BigNumContext::new()?;
//     let compressed_pub_key = public_key.to_bytes(
//         &ec_key.group(),
//         PointConversionForm::COMPRESSED,
//         &mut bn_ctx,
//     )?;
//
//     Ok(compressed_pub_key)
// }
// fn generate_ecdh_key() -> Result<EcKey<Private>, Box<dyn Error>> {
//     // Create the EC group for P-256
//     let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
//
//     // Generate a new private key for the group
//     let ec_key = EcKey::generate(&ec_group)?;
//
//     Ok(ec_key)
// }

// async fn load_ec_private_key(filename: &str) -> Result<EcKey<Private>, Box<dyn Error>> {
//     // Read the PEM file content
//     let mut file = File::open(filename).await?;
//     let mut pem = String::new();
//     file.read_to_string(&mut pem).await?;
//
//     // Load the private key from PEM format
//     let pkey = PKey::private_key_from_pem(pem.as_bytes())?;
//     let ec_key = pkey.ec_key()?;
//
//     Ok(ec_key)
// }
