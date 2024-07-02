use std::env;
use std::sync::Arc;
use std::sync::RwLock;

use aes_gcm::aead::{Key, NewAead};
use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::Aes256Gcm;
use elliptic_curve::point::AffineCoordinates;
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use once_cell::sync::OnceCell;
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use p256::ecdh::EphemeralSecret;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::TlsAcceptor;
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
        // println!("New ConnectionState");
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

#[derive(Debug, Deserialize)]
struct ServerSettings {
    port: u16,
    tls_cert_path: String,
    tls_key_path: String,
    kas_key_path: String,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let settings = load_config()?;

    // Initialize KAS keys
    init_kas_keys(&settings.kas_key_path)?;

    // Set up TLS
    let tls_config = load_tls_config(&settings.tls_cert_path, &settings.tls_key_path)?;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    // Bind the server
    let listener = TcpListener::bind(format!("0.0.0.0:{}", settings.port)).await?;
    println!("Listening on: 0.0.0.0:{}", settings.port);

    // Accept connections
    while let Ok((stream, _)) = listener.accept().await {
        let tls_acceptor = tls_acceptor.clone();
        let connection_state = Arc::new(ConnectionState::new());

        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    handle_connection(tls_stream, connection_state).await;
                }
                Err(e) => eprintln!("Failed to accept TLS connection: {}", e),
            }
        });
    }

    Ok(())
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<native_tls::TlsAcceptor, Box<dyn std::error::Error>> {
    let cert = std::fs::read(cert_path)?;
    let key = std::fs::read(key_path)?;

    let identity = native_tls::Identity::from_pkcs8(&cert, &key)?;
    let acceptor = native_tls::TlsAcceptor::new(identity)?;

    Ok(acceptor)
}

async fn handle_connection(stream: tokio_native_tls::TlsStream<TcpStream>, connection_state: Arc<ConnectionState>) {
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
        // println!("END handle_rewrap");
    }
}

async fn handle_rewrap(
    connection_state: &Arc<ConnectionState>,
    payload: &[u8],
) -> Option<Message> {
    let _print_on_drop = PrintOnDrop;
    // println!("BEGIN handle_rewrap");
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
    // let policy = header.get_policy();
    // println!("policy binding hex: {}", hex::encode(policy.get_binding().clone().unwrap()));
    // TDF ephemeral key
    let tdf_ephemeral_key_bytes = header.get_ephemeral_key();
    // println!("tdf_ephemeral_key hex: {}", hex::encode(tdf_ephemeral_key_bytes));
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
    // println!("kas_private_key_bytes {}", hex::encode(&kas_private_key_bytes));
    let kas_private_key_array: [u8; 32] = match kas_private_key_bytes.try_into() {
        Ok(key) => key,
        Err(_) => return None,
    };
    let kas_private_key = SecretKey::from_bytes(&kas_private_key_array.into())
        .map_err(|_| "Invalid private key")
        .ok()?;
    // Perform custom ECDH
    let dek_shared_secret_bytes = match custom_ecdh(&kas_private_key, &tdf_ephemeral_public_key) {
        Ok(secret) => secret,
        Err(e) => {
            println!("Error performing ECDH: {:?}", e);
            return None;
        }
    };
    // Encrypt dek_shared_secret with symmetric key using AES GCM
    let salt = connection_state.salt_lock.read().unwrap().clone().unwrap();
    let info = "rewrappedKey".as_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &session_shared_secret);
    let mut derived_key = [0u8; 32];
    hkdf.expand(info, &mut derived_key).expect("HKDF expansion failed");
    // println!("Derived Session Key: {}", hex::encode(&derived_key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = GenericArray::from_slice(&nonce);
    // println!("nonce {}", hex::encode(nonce));
    let key = Key::<Aes256Gcm>::from(derived_key);
    let cipher = Aes256Gcm::new(&key);
    let wrapped_dek = cipher.encrypt(nonce, dek_shared_secret_bytes.as_ref())
        .expect("encryption failure!");
    // println!("Rewrapped Key and Authentication tag {}", hex::encode(&wrapped_dek));
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
    response_data.extend_from_slice(&compressed_public_key_bytes);
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

fn custom_ecdh(secret_key: &SecretKey, public_key: &PublicKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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

    // Hash the x-coordinate using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(x_coordinate);
    // let hashed_secret = hasher.finalize().to_vec();

    // println!("Hashed shared secret: {}", hex::encode(&hashed_secret));

    Ok(shared_secret)
}

fn load_config() -> Result<ServerSettings, Box<dyn std::error::Error>> {
    let current_dir = env::current_dir()?;

    Ok(ServerSettings {
        port: env::var("PORT").unwrap_or_else(|_| "8443".to_string()).parse()?,
        tls_cert_path: env::var("TLS_CERT_PATH")
            .unwrap_or_else(|_| current_dir.join("fullchain.pem").to_str().unwrap().to_string()),
        tls_key_path: env::var("TLS_KEY_PATH")
            .unwrap_or_else(|_| current_dir.join("privkey.pem").to_str().unwrap().to_string()),
        kas_key_path: env::var("KAS_KEY_PATH")
            .unwrap_or_else(|_| current_dir.join("recipient_private_key.pem").to_str().unwrap().to_string()),
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use elliptic_curve::{CurveArithmetic, NonZeroScalar};
    use elliptic_curve::ScalarPrimitive;
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

        let debug_server_private_key: DebugEphemeralSecret<NistP256> = unsafe {
            std::mem::transmute(server_private_key)
        };
        let secret_key = SecretKey::new(ScalarPrimitive::from(debug_server_private_key.scalar));
        // Deserialize the public key of client
        let public_key = PublicKey::from_sec1_bytes(&client_public_key_bytes)
            .expect("Error deserializing client public key");

        // Run custom ECDH
        let result = custom_ecdh(&secret_key, &public_key).expect("Error performing ECDH");

        let computed_secret = hex::encode(result);
        // println!("Computed shared secret: {}", computed_secret);

        assert_eq!(key_agreement_secret, computed_secret, "Key agreement secret does not match with computed shared secret.");
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
        let expected_shared_secret = "d5da0342ae4458cece9b3eb2d253c6212e9612ab9f8c9a4249ee4c9c59ccda13";

        let client_public_key = PublicKey::from_sec1_bytes(&public_key_bytes).unwrap();
        let kas_private_key_option: Option<[u8; 32]> = private_key_bytes.clone().try_into().ok();
        let kas_private_key_array = match kas_private_key_option {
            Some(array) => array,
            None => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Could not convert to array."))),
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
