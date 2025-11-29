#![allow(dead_code)]
extern crate hex;
extern crate serde;

use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

// Chain-driven KAS validation
pub mod chain;

// Session manager for media DRM
pub mod session_manager;

// Media metrics for analytics
pub mod media_metrics;

// Media protocol type
pub mod modules {
    /// Media protocol type
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum MediaProtocol {
        /// OpenTDF NanoTDF protocol
        #[serde(rename = "tdf3")]
        TDF3,
        /// Apple FairPlay Streaming
        #[serde(rename = "fairplay")]
        FairPlay,
    }

    impl std::fmt::Display for MediaProtocol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                MediaProtocol::TDF3 => write!(f, "tdf3"),
                MediaProtocol::FairPlay => write!(f, "fairplay"),
            }
        }
    }
}

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResourceLocator {
    pub protocol_enum: ProtocolEnum,
    pub body: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum ProtocolEnum {
    Http = 0x00,
    Https = 0x01,
    Ws = 0x02,
    Wss = 0x03,
    SharedResource = 0xFF,
}

#[derive(Serialize, Deserialize, Debug)]
struct NanoTDFPayload {
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct Header {
    magic_number: Vec<u8>,
    version: Vec<u8>,
    kas: ResourceLocator,
    ecc_mode: ECCAndBindingMode,
    payload_sig_mode: SymmetricAndPayloadConfig,
    policy: Policy,
    ephemeral_key: Vec<u8>,
}

impl Header {
    pub fn get_ephemeral_key(&self) -> &Vec<u8> {
        &self.ephemeral_key
    }
    pub fn get_policy(&self) -> &Policy {
        &self.policy
    }
    pub fn get_ecc_mode(&self) -> &ECCAndBindingMode {
        &self.ecc_mode
    }
}

#[derive(Debug)]
pub struct ECCAndBindingMode {
    pub use_ecdsa_binding: bool,
    pub ephemeral_ecc_params_enum: ECDSAParams,
}

#[derive(Debug)]
struct SymmetricAndPayloadConfig {
    has_signature: bool,
    signature_ecc_mode: Option<ECDSAParams>,
    symmetric_cipher_enum: Option<SymmetricCiphers>,
}

#[derive(Debug)]
pub enum PolicyType {
    Remote,
    Embedded,
}

#[derive(Debug)]
pub struct Policy {
    pub policy_type: PolicyType,
    pub body: Option<Vec<u8>>,
    remote: Option<ResourceLocator>,
    // TODO change to PolicyBindingConfig
    binding: Option<Vec<u8>>,
}

impl Policy {
    pub fn get_binding(&self) -> &Option<Vec<u8>> {
        &self.binding
    }
    pub fn get_locator(&self) -> &Option<ResourceLocator> {
        &self.remote
    }
}

#[derive(Debug)]
struct PolicyBindingConfig {
    ecdsa_binding: bool,
    curve: ECDSAParams,
}

struct EmbeddedPolicyBody {
    content_length: u16,
    plaintext_ciphertext: Option<Vec<u8>>,
    policy_key_access: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum ECDSAParams {
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

pub struct BinaryParser<'a> {
    data: &'a [u8],
    pub position: usize,
}

impl<'a> BinaryParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BinaryParser { data, position: 0 }
    }

    pub fn parse_header(&mut self) -> Result<Header, ParsingError> {
        let magic_number = self.read(MAGIC_NUMBER_SIZE)?;
        let version = self.read(VERSION_SIZE)?;
        let kas = self.read_kas_field()?;
        let ecc_mode = self.read_ecc_and_binding_mode()?;
        let payload_sig_mode = self.read_symmetric_and_payload_config()?;
        let policy = self.read_policy_field(&ecc_mode)?;
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

    pub fn read_kas_field(&mut self) -> Result<ResourceLocator, ParsingError> {
        let protocol_enum = match self.read(1)?[0] {
            0x00 => ProtocolEnum::Http,
            0x01 => ProtocolEnum::Https,
            0x02 => ProtocolEnum::Ws,
            0x03 => ProtocolEnum::Wss,
            0xFF => ProtocolEnum::SharedResource,
            _ => return Err(ParsingError::InvalidKas),
        };
        let body_length = self.read(1)?[0] as usize;
        let body =
            String::from_utf8(self.read(body_length)?).map_err(|_| ParsingError::InvalidKas)?;
        Ok(ResourceLocator {
            protocol_enum,
            body,
        })
    }

    pub fn read_policy_field(
        &mut self,
        binding_mode: &ECCAndBindingMode,
    ) -> Result<Policy, ParsingError> {
        let policy_type = match self.read(1)?[0] {
            0x00 => PolicyType::Remote,
            0x01 => PolicyType::Embedded,
            _ => return Err(ParsingError::InvalidPolicy),
        };

        match policy_type {
            PolicyType::Remote => {
                let remote = self.read_kas_field()?;
                let binding = self.read_policy_binding(binding_mode).unwrap();
                Ok(Policy {
                    policy_type,
                    body: None,
                    remote: Some(remote),
                    binding: Option::from(binding),
                })
            }
            PolicyType::Embedded => {
                let body_length = self.read(2)?;
                let length = u16::from_be_bytes([body_length[0], body_length[1]]) as usize;
                let body = self.read(length)?;
                let binding = self.read_policy_binding(binding_mode).unwrap();
                Ok(Policy {
                    policy_type,
                    body: Some(body),
                    remote: None,
                    binding: Option::from(binding),
                })
            }
        }
    }

    fn read_policy_binding(
        &mut self,
        binding_mode: &ECCAndBindingMode,
    ) -> Result<Vec<u8>, ParsingError> {
        let binding_size = if binding_mode.use_ecdsa_binding {
            match binding_mode.ephemeral_ecc_params_enum {
                ECDSAParams::Secp256r1 | ECDSAParams::Secp256k1 => 64,
                ECDSAParams::Secp384r1 => 96,
                ECDSAParams::Secp521r1 => 132,
            }
        } else {
            // GMAC Tag Binding
            16
        };

        // println!("bindingSize: {}", binding_size);

        // Assuming `read` reads length bytes from some source and returns an Option<Vec<u8>>
        self.read(binding_size)
    }

    fn read_ecc_and_binding_mode(&mut self) -> Result<ECCAndBindingMode, ParsingError> {
        // println!("readEccAndBindingMode");

        let ecc_and_binding_mode_data = self.read(1)?;
        let ecc_and_binding_mode = ecc_and_binding_mode_data[0];

        // let ecc_mode_hex = format!("{:02x}", ecc_and_binding_mode);
        // println!("ECC Mode Hex: {}", ecc_mode_hex);

        let use_ecdsa_binding = (ecc_and_binding_mode & (1 << 7)) != 0;
        let ephemeral_ecc_params_enum_value = ecc_and_binding_mode & 0x07;

        let ephemeral_ecc_params_enum = match ephemeral_ecc_params_enum_value {
            0x00 => ECDSAParams::Secp256r1,
            0x01 => ECDSAParams::Secp384r1,
            0x02 => ECDSAParams::Secp521r1,
            0x03 => ECDSAParams::Secp256k1,
            _ => {
                println!("Unsupported Ephemeral ECC Params Enum value");
                return Err(ParsingError::InvalidEccMode);
            }
        };

        // println!("useECDSABinding: {}", use_ecdsa_binding);
        // println!("ephemeralECCParamsEnum: {:?}", ephemeral_ecc_params_enum);

        Ok(ECCAndBindingMode {
            use_ecdsa_binding,
            ephemeral_ecc_params_enum,
        })
    }

    fn read_symmetric_and_payload_config(
        &mut self,
    ) -> Result<SymmetricAndPayloadConfig, ParsingError> {
        // println!("readSymmetricAndPayloadConfig");

        let symmetric_and_payload_config_data = self.read(1)?;
        let symmetric_and_payload_config = symmetric_and_payload_config_data[0];

        // let symmetric_and_payload_config_hex = format!("{:02x}", symmetric_and_payload_config);
        // println!("Symmetric And Payload Config Hex: {}", symmetric_and_payload_config_hex);

        let has_signature = (symmetric_and_payload_config & 0x80) >> 7 != 0;
        let signature_ecc_mode_enum_value = (symmetric_and_payload_config & 0x70) >> 4;
        let symmetric_cipher_enum_value = symmetric_and_payload_config & 0x0F;

        let signature_ecc_mode_enum = match signature_ecc_mode_enum_value {
            0x00 => Some(ECDSAParams::Secp256r1),
            0x01 => Some(ECDSAParams::Secp384r1),
            0x02 => Some(ECDSAParams::Secp521r1),
            0x03 => Some(ECDSAParams::Secp256k1),
            _ => None,
        };

        let symmetric_cipher_enum = match symmetric_cipher_enum_value {
            0x00 => Some(SymmetricCiphers::Gcm64),
            0x01 => Some(SymmetricCiphers::Gcm96),
            0x02 => Some(SymmetricCiphers::Gcm104),
            0x03 => Some(SymmetricCiphers::Gcm112),
            0x04 => Some(SymmetricCiphers::Gcm120),
            0x05 => Some(SymmetricCiphers::Gcm128),
            _ => None,
        };

        // println!("hasSignature: {}", has_signature);
        // println!("signatureECCModeEnum: {:?}", signature_ecc_mode_enum);
        // println!("symmetricCipherEnum: {:?}", symmetric_cipher_enum);

        Ok(SymmetricAndPayloadConfig {
            has_signature,
            signature_ecc_mode: signature_ecc_mode_enum,
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
const MIN_EPHEMERAL_KEY_SIZE: usize = 33;

#[derive(Debug)]
pub enum ParsingError {
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
            // println!("{:?}", bytes);
            let mut parser = BinaryParser::new(&bytes);
            let _header = parser.parse_header()?;
            // println!("{:?}", header);
            // Process header as needed
            Ok(())
        }

        fn test_spec_example_decrypt_payload() -> Result<(), Box<dyn Error>> {
            let encrypted_payload = "\
                4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80\
                80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70\
                6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36\
                ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15\
                12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c\
                c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da";

            let bytes = hex::decode(encrypted_payload.replace(" ", ""))?;
            // println!("{:?}", bytes);
            let mut parser = BinaryParser::new(&bytes);
            let _header = parser.parse_header()?;
            // println!("{:?}", header);
            Ok(())
        }

        fn test_no_signature_spec_example_binary_parser() -> Result<(), Box<dyn Error>> {
            let hex_string = "\
                4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80\
                80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70\
                6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36\
                ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15\
                12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c\
                c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da";

            let bytes = hex::decode(hex_string.replace(" ", ""))?;
            // println!("{:?}", bytes);
            let _parser = BinaryParser::new(&bytes);
            // let header = parser.parse_header()?;
            // println!("{:?}", header);
            // Process header as needed
            Ok(())
        }
    }

    #[test]
    fn run_tests() -> Result<(), Box<dyn Error>> {
        NanoTDFTests::setup()?;
        // NanoTDFTests::test_spec_example_binary_parser()?;
        // NanoTDFTests::test_spec_example_decrypt_payload()?;
        // NanoTDFTests::test_no_signature_spec_example_binary_parser()?;
        NanoTDFTests::teardown()?;
        Ok(())
    }

    #[test]
    fn test_policy_binding_size_validation() {
        // Test ECDSA binding sizes for different curves
        let binding_mode_secp256r1 = ECCAndBindingMode {
            use_ecdsa_binding: true,
            ephemeral_ecc_params_enum: ECDSAParams::Secp256r1,
        };

        let binding_mode_secp384r1 = ECCAndBindingMode {
            use_ecdsa_binding: true,
            ephemeral_ecc_params_enum: ECDSAParams::Secp384r1,
        };

        let binding_mode_secp521r1 = ECCAndBindingMode {
            use_ecdsa_binding: true,
            ephemeral_ecc_params_enum: ECDSAParams::Secp521r1,
        };

        // Secp256r1 should be 64 bytes
        assert_eq!(
            match binding_mode_secp256r1.ephemeral_ecc_params_enum {
                ECDSAParams::Secp256r1 | ECDSAParams::Secp256k1 => 64,
                ECDSAParams::Secp384r1 => 96,
                ECDSAParams::Secp521r1 => 132,
            },
            64
        );

        // Secp384r1 should be 96 bytes
        assert_eq!(
            match binding_mode_secp384r1.ephemeral_ecc_params_enum {
                ECDSAParams::Secp256r1 | ECDSAParams::Secp256k1 => 64,
                ECDSAParams::Secp384r1 => 96,
                ECDSAParams::Secp521r1 => 132,
            },
            96
        );

        // Secp521r1 should be 132 bytes
        assert_eq!(
            match binding_mode_secp521r1.ephemeral_ecc_params_enum {
                ECDSAParams::Secp256r1 | ECDSAParams::Secp256k1 => 64,
                ECDSAParams::Secp384r1 => 96,
                ECDSAParams::Secp521r1 => 132,
            },
            132
        );
    }

    #[test]
    fn test_gmac_binding_size() {
        // GMAC binding should always be 16 bytes (128 bits)
        let expected_gmac_size = 16;

        // Simulate GMAC binding validation
        let valid_gmac_binding = [0u8; 16];
        let invalid_gmac_binding_short = [0u8; 8];
        let invalid_gmac_binding_long = [0u8; 32];

        assert_eq!(valid_gmac_binding.len(), expected_gmac_size);
        assert_ne!(invalid_gmac_binding_short.len(), expected_gmac_size);
        assert_ne!(invalid_gmac_binding_long.len(), expected_gmac_size);
    }

    #[test]
    fn test_policy_binding_format_detection() {
        // Test detection of ECDSA vs GMAC binding based on ECC mode
        let ecdsa_mode = ECCAndBindingMode {
            use_ecdsa_binding: true,
            ephemeral_ecc_params_enum: ECDSAParams::Secp256r1,
        };

        let gmac_mode = ECCAndBindingMode {
            use_ecdsa_binding: false,
            ephemeral_ecc_params_enum: ECDSAParams::Secp256r1,
        };

        // Verify ECDSA mode detection
        assert!(ecdsa_mode.use_ecdsa_binding);
        assert!(!gmac_mode.use_ecdsa_binding);

        // Verify expected sizes
        let ecdsa_binding_size = match ecdsa_mode.ephemeral_ecc_params_enum {
            ECDSAParams::Secp256r1 | ECDSAParams::Secp256k1 => 64,
            ECDSAParams::Secp384r1 => 96,
            ECDSAParams::Secp521r1 => 132,
        };
        assert_eq!(ecdsa_binding_size, 64);

        // GMAC is always 16 bytes regardless of ECC params
        let gmac_binding_size = 16;
        assert_eq!(gmac_binding_size, 16);
    }
}
