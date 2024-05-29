extern crate crypto;
extern crate hex;
extern crate serde;
extern crate serde_json;

use std::error::Error;
use std::fmt;
use crypto::aead::{AeadDecryptor, AeadEncryptor};
use crypto::aes::KeySize::KeySize256;
use crypto::aes_gcm::AesGcm;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct NanoTDFHeader {
    magic_number: u16,
    version: u8,
    kas: ResourceLocator,
    ecc_mode: u8,
    payload_sig_mode: u8,
    policy: Vec<u8>,
    ephemeral_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ResourceLocator {
    protocol_enum: ProtocolEnum,
    body: String,
}

#[derive(Serialize, Deserialize, Debug)]
enum ProtocolEnum {
    Http = 0x00,
    Https = 0x01,
    Unreserved = 0x02,
    SharedResourceDirectory = 0xFF,
}

#[derive(Serialize, Deserialize, Debug)]
struct NanoTDFPayload {
    data: Vec<u8>,
}

#[derive(Debug)]
struct Header {
    magic_number: Vec<u8>,
    version: Vec<u8>,
    kas: ResourceLocator,
    ecc_mode: ECCAndBindingMode,
    payload_sig_mode: SymmetricAndPayloadConfig,
    policy: Policy,
    ephemeral_key: Vec<u8>,
}

#[derive(Debug)]
struct ECCAndBindingMode {
    use_ecdsa_binding: bool,
    ephemeral_ecc_params_enum: ECDSAParams,
}

#[derive(Debug)]
struct SymmetricAndPayloadConfig {
    has_signature: bool,
    signature_ecc_mode: Option<ECDSAParams>,
    symmetric_cipher_enum: Option<SymmetricCiphers>,
}

#[derive(Debug)]
enum PolicyType {
    Remote,
    Embedded,
}

#[derive(Debug)]
struct Policy {
    policy_type: PolicyType,
    body: Option<Vec<u8>>,
    remote: Option<ResourceLocator>,
    binding: Option<Vec<u8>>,
}

struct EmbeddedPolicyBody {
    content_length: u16,
    plaintext_ciphertext: Option<Vec<u8>>,
    policy_key_access: Option<Vec<u8>>,
}

#[derive(Debug)]
enum ECDSAParams {
    Secp256r1 = 0x00,
    Secp384r1 = 0x01,
    Secp521r1 = 0x02,
    Secp256k1 = 0x03,
}
#[derive(Debug)]
enum SymmetricCiphers {
    Gcm64 = 0x00,
    Gcm96 = 0x01,
    Gcm104 = 0x02,
    Gcm112 = 0x03,
    Gcm120 = 0x04,
    Gcm128 = 0x05,
}

struct Payload {
    length: u32,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    payload_mac: Vec<u8>,
}

fn encrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let iv = [0u8; 12]; // Initialization vector
    let mut gcm = AesGcm::new(KeySize256, key, &iv, &[]);
    let mut ciphertext = vec![0u8; data.len()];
    let mut tag = [0u8; 16];
    gcm.encrypt(data, &mut ciphertext, &mut tag);
    Some([ciphertext, tag.to_vec()].concat())
}

fn decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let iv = [0u8; 12]; // Initialization vector
    let mut gcm = AesGcm::new(KeySize256, key, &iv, &[]);
    let mut plaintext = vec![0u8; data.len() - 16];
    let mut tag = &data[data.len() - 16..];
    // AesGcm::decrypt(&mut gcm, &data[..data.len() - 16], tag, &mut plaintext);
    Some(plaintext)
}

pub(crate) struct BinaryParser {
    data: Vec<u8>,
    position: usize,
}

impl BinaryParser {
    pub(crate) fn new(data: Vec<u8>) -> Self {
        BinaryParser { data, position: 0 }
    }

    fn parse_header(&mut self) -> Result<Header, ParsingError> {
        let magic_number = self.read(MAGIC_NUMBER_SIZE)?;
        let version = self.read(VERSION_SIZE)?;
        let kas = self.read_kas_field()?;
        let ecc_mode = self.read_ecc_and_binding_mode()?;
        let payload_sig_mode = self.read_symmetric_and_payload_config()?;
        let policy = self.read_policy_field()?;
        let ephemeral_key = self.read(MIN_EPHEMERAL_KEY_SIZE)?;

        Ok(Header {
            magic_number,
            version,
            kas,
            ecc_mode,
            payload_sig_mode,
            policy,
            ephemeral_key,
        })
    }

    fn read(&mut self, length: usize) -> Result<Vec<u8>, ParsingError> {
        if self.position + length > self.data.len() {
            return Err(ParsingError::InvalidFormat);
        }
        let result = self.data[self.position..self.position + length].to_vec();
        self.position += length;
        Ok(result)
    }

    fn read_kas_field(&mut self) -> Result<ResourceLocator, ParsingError> {
        let protocol_enum = match self.read(1)?[0] {
            0x00 => ProtocolEnum::Http,
            0x01 => ProtocolEnum::Https,
            0x02 => ProtocolEnum::Unreserved,
            0xFF => ProtocolEnum::SharedResourceDirectory,
            _ => return Err(ParsingError::InvalidKas),
        };
        let body_length = self.read(1)?[0] as usize;
        let body = String::from_utf8(self.read(body_length)?).map_err(|_| ParsingError::InvalidKas)?;

        Ok(ResourceLocator {
            protocol_enum,
            body,
        })
    }

    fn read_policy_field(&mut self) -> Result<Policy, ParsingError> {
        let policy_type = match self.read(1)?[0] {
            0x00 => PolicyType::Remote,
            0x01 => PolicyType::Embedded,
            _ => return Err(ParsingError::InvalidPolicy),
        };

        match policy_type {
            PolicyType::Remote => {
                let remote = self.read_kas_field()?;
                Ok(Policy {
                    policy_type,
                    body: None,
                    remote: Some(remote),
                    binding: None,
                })
            }
            PolicyType::Embedded => {
                let body_length = self.read(2)?;
                let length = u16::from_be_bytes([body_length[0], body_length[1]]) as usize;
                let body = self.read(length)?;
                Ok(Policy {
                    policy_type,
                    body: Some(body),
                    remote: None,
                    binding: None,
                })
            }
        }
    }

    fn read_ecc_and_binding_mode(&mut self) -> Result<ECCAndBindingMode, ParsingError> {
        let use_ecdsa_binding = self.read(1)?[0] != 0;
        let ephemeral_ecc_params_enum = match self.read(1)?[0] {
            0x00 => ECDSAParams::Secp256r1,
            0x01 => ECDSAParams::Secp384r1,
            0x02 => ECDSAParams::Secp521r1,
            0x03 => ECDSAParams::Secp256k1,
            _ => return Err(ParsingError::InvalidEccMode),
        };

        Ok(ECCAndBindingMode {
            use_ecdsa_binding,
            ephemeral_ecc_params_enum,
        })
    }

    fn read_symmetric_and_payload_config(&mut self) -> Result<SymmetricAndPayloadConfig, ParsingError> {
        let has_signature = self.read(1)?[0] != 0;
        let signature_ecc_mode = if has_signature {
            Some(match self.read(1)?[0] {
                0x00 => ECDSAParams::Secp256r1,
                0x01 => ECDSAParams::Secp384r1,
                0x02 => ECDSAParams::Secp521r1,
                0x03 => ECDSAParams::Secp256k1,
                _ => return Err(ParsingError::InvalidEccMode),
            })
        } else {
            None
        };
        let symmetric_cipher_enum = Some(match self.read(1)?[0] {
            0x00 => SymmetricCiphers::Gcm64,
            0x01 => SymmetricCiphers::Gcm96,
            0x02 => SymmetricCiphers::Gcm104,
            0x03 => SymmetricCiphers::Gcm112,
            0x04 => SymmetricCiphers::Gcm120,
            0x05 => SymmetricCiphers::Gcm128,
            _ => return Err(ParsingError::InvalidPayloadSigMode),
        });

        Ok(SymmetricAndPayloadConfig {
            has_signature,
            signature_ecc_mode,
            symmetric_cipher_enum,
        })
    }

    fn parse_payload(&mut self, data: &[u8]) -> Option<Payload> {
        let mut start_index = 0;
        let length_data = &data[start_index..start_index + 3];
        let length = u32::from_be_bytes([0, length_data[0], length_data[1], length_data[2]]);
        start_index += 3;

        let iv = data[start_index..start_index + 3].to_vec();
        start_index += 3;

        let remaining_data_length = length as usize - iv.len() - 3;
        let ciphertext = data[start_index..start_index + remaining_data_length].to_vec();
        start_index += remaining_data_length;

        let payload_mac = data[start_index..].to_vec();

        Some(Payload {
            length,
            iv,
            ciphertext,
            payload_mac,
        })
    }
}

const MAGIC_NUMBER_SIZE: usize = 2;
const VERSION_SIZE: usize = 1;
const MIN_KAS_SIZE: usize = 3;
const MAX_KAS_SIZE: usize = 257;
const ECC_MODE_SIZE: usize = 1;
const PAYLOAD_SIG_MODE_SIZE: usize = 1;
const MIN_POLICY_SIZE: usize = 3;
const MAX_POLICY_SIZE: usize = 257;
const MIN_EPHEMERAL_KEY_SIZE: usize = 33;
const MAX_EPHEMERAL_KEY_SIZE: usize = 133;

#[derive(Debug)]
enum ParsingError {
    InvalidFormat,
    InvalidMagicNumber,
    InvalidVersion,
    InvalidKas,
    InvalidEccMode,
    InvalidPayloadSigMode,
    InvalidPolicy,
    InvalidEphemeralKey,
}

impl fmt::Display for ParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParsingError::InvalidFormat => f.write_str("InvalidFormat"),
            ParsingError::InvalidMagicNumber => f.write_str("InvalidMagicNumber"),
            ParsingError::InvalidVersion => f.write_str("InvalidVersion"),
            ParsingError::InvalidKas => f.write_str("InvalidKas"),
            ParsingError::InvalidEccMode => f.write_str("InvalidEccMode"),
            ParsingError::InvalidPayloadSigMode => f.write_str("InvalidPayloadSigMode"),
            ParsingError::InvalidPolicy => f.write_str("InvalidPolicy"),
            ParsingError::InvalidEphemeralKey => f.write_str("InvalidEphemeralKey"),
        }
    }
}

impl Error for ParsingError {}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use super::*;

    struct NanoTDFTests;

    impl NanoTDFTests {
        fn setup() -> Result<(), Box<dyn Error>> {
            // Put setup code here.
            Ok(())
        }

        fn teardown() -> Result<(), Box<dyn Error>> {
            // Put teardown code here.
            Ok(())
        }

        fn test_spec_example_binary_parser() -> Result<(), Box<dyn Error>> {
            let hex_string = "\
                4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80\
                80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70\
                6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36\
                ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15\
                12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c\
                c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da";

            let bytes = hex::decode(hex_string.replace(" ", ""))?;
            let mut parser = BinaryParser::new(bytes);
            let header = parser.parse_header()?;
            println!("{:?}", header);
            // Process header as needed
            Ok(())
        }
    }

    #[test]
    fn run_tests() -> Result<(), Box<dyn Error>> {
        NanoTDFTests::setup()?;
        NanoTDFTests::test_spec_example_binary_parser()?;
        NanoTDFTests::teardown()?;
        Ok(())
    }
}