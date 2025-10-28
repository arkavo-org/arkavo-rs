//
// base_constants.rs: Contains the constants that need to be defined for the Base class.
//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use serde::{Deserialize, Serialize};

use super::structures::base_fps_structures::{CertificateBundle, LegacyCertificate};

//FPSSDK Release Major and Minor Version
pub const FPS_SDK_MAJOR_VERSION: u32 = 26;
pub const FPS_SDK_MINOR_VERSION: u32 = 0;
pub const FPS_SDK_VERSION_CERTIFICATE_OID: &str = "1.2.840.113635.100.6.13.1.22";

// Standard sizes
pub const AES128_KEY_SZ: usize = 16;
pub const AES128_IV_SZ: usize = 16;
pub const AES128_BLOCK_SIZE: usize = 16;

// SPC v1 and CKC v1 field sizes as per specification for parsing
pub const FPS_V1_ASSET_ID_MIN_SZ: usize = 2;
pub const FPS_V1_ASSET_ID_MAX_SZ: usize = 200;
pub const FPS_V1_SKR1_INTEGRITY_SZ: usize = 16;
pub const FPS_V1_HASH_SZ: usize = 20;
pub const FPS_V3_HASH_SZ: usize = 32;
pub const FPS_V1_R2_SZ: usize = 21;
pub const FPS_V1_R2_V3_MAX_SZ: usize = 64;
pub const FPS_V1_R1_SZ: usize = 44;
pub const FPS_V1_HU_SZ: usize = 20;
pub const FPS_V1_SKR1_SZ: usize = 112;
pub const FPS_V1_SKR1_V3_MAX_SZ: usize = 256;
pub const FPS_V1_WRAPPED_KEY_SZ: usize = 128;
pub const FPS_V2_WRAPPED_KEY_SZ: usize = 256;

pub const FPS_ENCRYPTED_SECURITY_LEVEL_REPORT_TLLV_SIZE: usize = 32;

pub const NO_LEASE_DURATION: u32 = 0xFFFFFFFF;

pub const FPS_MAX_STREAM_ID_LENGTH: usize = 16;
pub const FPS_MAX_TITLE_ID_LENGTH: usize = 16;
pub const FPS_MAX_NUM_CRYPTO_VERSIONS: usize = 100;

pub const FPS_VENDOR_HASH_SIZE: usize = 8;
pub const FPS_PRODUCT_HASH_SIZE: usize = 8;

pub const FPS_CAPABILITIES_FLAGS_LENGTH: usize = 16;

pub const FPS_OFFLINE_CONTENTID_LENGTH: usize = 16;

pub const FPS_TLLV_TAG_SZ: usize = 8;
pub const FPS_TLLV_TOTAL_LENGTH_SZ: usize = 4;
pub const FPS_TLLV_VALUE_LENGTH_SZ: usize = 4;

pub const FPS_MAX_KEY_FORMATS: usize = 64;
pub const FPS_KEY_PAYLOAD_STRUCT_VERSION: u64 = 2;

pub const FPS_TLLV_SECURITY_LEVEL_TLLV_VERSION: u32 = 1;

// Sync TLLV Flag Field Definitions
pub const KD_SYNC_SPC_FLAG_REPORT: u64 = 1 << 0;
pub const KD_SYNC_SPC_FLAG_SECURE_INVALIDATION: u64 = 1 << 1;
pub const KD_SYNC_SPC_FLAG_SECURE_INVALIDATION_ALL: u64 = 1 << 2;
pub const KD_SYNC_SPC_FLAG_TITLEID_VALID: u64 = 1 << 3;
pub const KD_SYNC_SPC_FLAG_SUCCESS: u64 = 1 << 16;
pub const KD_SYNC_SPC_FLAG_OBJ_NOT_FOUND: u64 = 1 << 17;
pub const KD_SYNC_SPC_FLAG_OBJ_EXPIRED: u64 = 1 << 18;

pub const FPS_TLLV_OFFLINEKEY_TLLV_VERSION: u32 = 1;
pub const FPS_TLLV_OFFLINEKEY_TLLV_VERSION_2: u32 = 2;

pub const FPS_TLLV_SESSION_KEY_USED_TLLV_VERSION: u32 = 1;

//ENV Variable for certificate file location
pub const FPS_CERT_PATH: &str = "FPS_CERT_PATH";

// JSON parsing strings
// Input
pub const CREATE_CKC_STR: &str = "create-ckc";
pub const GET_CLIENT_INFO_STR: &str = "get-client-info";
pub const ID_STR: &str = "id";
pub const SPC_STR: &str = "spc";
pub const ASSET_INFO_STR: &str = "asset-info";
pub const ASSET_ID_STR: &str = "asset-id";
pub const CONTENT_KEY_STR: &str = "content-key";
pub const CONTENT_IV_STR: &str = "content-iv";
pub const LEASE_DURATION_STR: &str = "lease-duration";
pub const OFFLINE_HLS_STR: &str = "offline-hls";
pub const STREAM_ID_STR: &str = "stream-id"; /* unique id of each HLS stream */
pub const TITLE_ID_STR: &str = "title-id"; /* id of HLS title. Should be the same for all HLS sub-streams */
pub const RENTAL_DURATION_STR: &str = "rental-duration";
pub const PLAYBACK_DURATION_STR: &str = "playback-duration";
pub const HDCP_TYPE_STR: &str = "hdcp-type";
pub const CHECK_IN_STR: &str = "check-in";
pub const ENCRYPTION_SCHEME: &str = "encryption-scheme";

// Output
pub const STATUS_STR: &str = "status";
pub const HU_STR: &str = "hu";
pub const CKC_STR: &str = "ckc";

pub const OFFLINE_SYNC_STR: &str = "offline-sync";
pub const VERSION_STR: &str = "version";
pub const SERVER_CHALLENGE_STR: &str = "server-challenge";
pub const FLAGS_STR: &str = "flags";
pub const REPORT_STR: &str = "report";
pub const SECURE_INVALIDATION_ALL_STR: &str = "secure-invalidation-all";
pub const TITLE_ID_VALID_STR: &str = "title-id-valid";
pub const SUCCESS_STR: &str = "success";
pub const OBJ_NOT_FOUND_STR: &str = "obj-not-found";
pub const OBJ_EXPIRED_STR: &str = "obj-expired";
pub const DURATION_TO_EXPIRY_STR: &str = "duration-to-expiry";
pub const RECORDS_INVALIDATED_STR: &str = "records-invalidated";
pub const INVALIDATED_STREAM_IDS_STR: &str = "invalidated-stream-ids";

pub const DEVICE_IDENTITY_STR: &str = "device-identity";
pub const FPDI_VERSION_STR: &str = "fpdi-version";
pub const DEVICE_CLASS_STR: &str = "device-class";
pub const VENDOR_HASH_STR: &str = "vendor-hash";
pub const PRODUCT_HASH_STR: &str = "product-hash";
pub const FPS_REE_VERSION_STR: &str = "fps-ree-version"; // FPS REE Library Version
pub const FPS_TEE_VERSION_STR: &str = "fps-tee-version"; // FPS TEE Library Version
pub const OS_VERSION_STR: &str = "os-version"; // OS Version

pub const DEVICE_INFO_STR: &str = "device-info";
pub const DEVICE_TYPE_STR: &str = "device-type";

pub const CAPABILITIES_STR: &str = "capabilities";
pub const HDCP_STR: &str = "hdcp";
pub const OFFLINE_KEY_STR: &str = "offline-key";
pub const OFFLINE_KEY_2_STR: &str = "offline-key-2";
pub const SECURE_INVALIDATION_STR: &str = "secure-invalidation";
pub const SECURITY_LEVEL_BASELINE_STR: &str = "security-level-baseline";
pub const SECURITY_LEVEL_MAIN_STR: &str = "security-level-main";

pub const SECURITY_LEVEL_STR: &str = "security-level";
pub const MAIN_STR: &str = "main";
pub const BASELINE_STR: &str = "baseline";

pub const KDL_VERSION_STR: &str = "kdl-version";

pub const STREAMING_INDICATOR_STR: &str = "streaming-indicator";
pub const TRANSACTION_ID_STR: &str = "transaction-id";
pub const PLAYBACK_STATE_STR: &str = "playback-state";
pub const CREATION_DATE_STR: &str = "creation-date";
pub const STATE_STR: &str = "state";
pub const SESSION_ID_STR: &str = "session-id";

// Virtual Machine Output
pub const VM_DEVICE_INFO_STR: &str = "vm-device-info";
pub const HOST_DEVICE_CLASS_STR: &str = "host-device-class";
pub const HOST_OS_VERSION_STR: &str = "host-os-version";
pub const HOST_VM_PROTOCOL_VERSION: &str = "host-vm-protocol-version";
pub const GUEST_DEVICE_CLASS_STR: &str = "guest-device-class";
pub const GUEST_OS_VERSION_STR: &str = "guest-os-version";
pub const GUEST_VM_PROTOCOL_VERSION: &str = "guest-vm-protocol-version";

// Capabilities TLLV flags (delivered in SPC)
/// The client can enforce HDCP type1 (as well as type 0 or none values in HDCP TLLV when received in CKC)
pub const FPS_CAPABILITY_HDCP_TYPE1_ENFORCEMENT_SUPPORTED: u64 = 1;
/// The client can enforce dual expiry if sent by the server
pub const FPS_CAPABILITY_OFFLINE_KEY_SUPPORTED: u64 = 1 << 1;
/// The client can support check-in (secure delete) requests
pub const FPS_CAPABILITY_CHECK_IN_SUPPORTED: u64 = 1 << 2;
/// The client can support Offline Key TLLV V2
pub const FPS_CAPABILITY_OFFLINE_KEY_V2_SUPPORTED: u64 = 1 << 3;
/// The client can support enforcement of security level Baseline
pub const FPS_CAPABILITY_SECURITY_LEVEL_BASELINE_SUPPORTED: u64 = 1 << 4;
/// The client can support enforcement of security level Main
pub const FPS_CAPABILITY_SECURITY_LEVEL_MAIN_SUPPORTED: u64 = 1 << 5;

pub const FPS_KEY_DURATION_RESERVED_FIELD_VALUE: u32 = 0x86d34a3a;

/// Latest published macOS Kext Deny List version by Apple
pub const MIN_KDL_VERSION: u32 = 31;

// Video Session Key
pub const V3_PROTOCOL_VERSION_UUID: &[u8] = &[0x66, 0x44, 0xff, 0x2b, 0xa8, 0x7c, 0x99, 0xb6, 0xff, 0x96, 0x55, 0x27, 0x0c, 0xd0, 0x68, 0xa6];
pub const V3_PROTOCOL_ENCRYPTION_KEY_SEED: &[u8] = &[0x70, 0xd1, 0xe6, 0xc3, 0x4f, 0x07, 0xe8, 0x49, 0xb3, 0xa6, 0x24, 0x34, 0x0f, 0x4f, 0x17, 0x6d];
pub const V3_PROTOCOL_INTEGRITY_KEY_SEED: &[u8] = &[0x96, 0xd3, 0x43, 0x5f, 0x6e, 0xf0, 0x8d, 0x7d, 0x12, 0x1f, 0xa8, 0x6b, 0x25, 0x3e, 0x4a, 0xc9];
pub const V3_PROTOCOL_ENCRYPTION_IV_SEED: &[u8] = &[0xc1, 0x1b, 0x3e, 0xd1, 0xa3, 0x80, 0x3f, 0x4e, 0x13, 0x22, 0xa0, 0x88, 0x03, 0x14, 0x5a, 0xc6];

/// Version number of the SPC
///
/// v1 uses 1024-bit certificates
/// v2 uses 2048-bit certificates
pub enum SPCVersion {
    v1 = 1,
    v2 = 2,
    v3 = 3,
}

/// AES Encryption Mode
pub enum AESEncryptionMode {
    aesEncrypt = 0,
    aesDecrypt = 1,
}

/// AES Cipher Mode
pub enum AESEncryptionCipher {
    aesCBC = 0,
    aesECB = 1,
}

/// FairPlay Streaming Requested Key Type
pub enum FPSKeyTypeRequested {
    none = 0,
}

/// FairPlay Streaming License Type
pub enum FPSLicenseType {
    streaming = 0,
    offlineHLS = 1,
}

/// TLLV tag values used in SPC and CKC
#[repr(u64)]
pub enum FPSTLLVTagValue {
    r2Tag = 0x71b5595ac1521133,
    antiReplayTag = 0x89c90f12204106b2,
    sessionKeyR1Tag = 0x3d1a10b8bffac2ec,
    sessionKeyR1IntegrityTag = 0xb349d4809e910687,
    assetIDTag = 0x1bf7f53f5d5d5a1f,
    transactionIDTag = 0x47aa7ad3440577de,
    protocolVersionUsedTag = 0x5d81bcbcc7f61703,
    protocolVersionsSupportedTag = 0x67b8fb79ecce1a13,
    returnRequestTag = 0x19f9d4e5ab7609cb,
    r1Tag = 0xea74c4645d5efee9,
    streamingIndicatorTag = 0xabb0256a31843974,
    mediaPlaybackStateTag = 0xeb8efdf2b25ab3a0,
    offlineSyncTag = 0x77966de1dc1083ad,
    capabilitiesTag = 0x9c02af3253c07fb2,
    keyDurationTag = 0x47acf6a418cd091a,
    offlineKeyTag = 0x6375d9727060218c,
    hdcpInformationTag = 0x2e52f1530d8ddb4a,
    securityLevelTag = 0x644cb1dac0313250,
    supportedKeyFormatTag = 0x8d8e84fa6cc35eb7,
    securityLevelReportTag = 0xb18ee16ea50f6c02,
    deviceInfoTag = 0xd43fc6abc596aae7,
    deviceIdentityTag = 0x94c17cd676c69b59,
    kdlVersionReportTag = 0x70eca6573388e329,
    sessionKeyVersionUsedTag = 0x42ca089e8e9fa924,
    sessionKeyR1V3Tag = 0x697af6213858562f,
    R2V3Tag = 0xdb30b89dcb5834b3,
    vmDeviceInfoTag = 0x756440e240499f70,
}

/// Content Type used for KSMKeyPayload structure
pub enum KSMKeyPayloadContentType {
    unknown = 0,
    video = 1,
    audio = 3,
}

/// FairPlay Streaming Key Duration Type
pub enum FPSKeyDurationType {
    none = 0,
    lease = 0x1a4bde7e,
    rental = 0x3dfe45a0,
    leaseAndRental = 0x27b59bde,
    persistence = 0x3df2d9fb,
    persistenceAndDuration = 0x18f06048,
}

/// FairPlay Streaming HDCP Requirement Type
#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum FPSHDCPRequirement {
    hdcpNotRequired = 0xef72894ca7895b78u64,
    hdcpType0 = 0x40791ac78bd5c571u64,
    hdcpType1 = 0x285a0863bba8e1d3u64,
}

/// FairPlay Streaming Device Playback State
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum FPSDevicePlaybackState {
    firstPlaybackCKRequired = 0xf4dee5a2,
    currentlyPlayingCKRequired = 0x4f834330,
    currentlyPlayingCKNotRequired = 0xa5d6739e,
}

/// FairPlay Streaming Apple Device Type
#[repr(u64)]
pub enum FPSAppleDeviceType {
    mac = 0x358c41b1ec78f599u64,
    tv = 0xc1500767c86c1faeu64,
    iOS = 0x8551fd5e31f479b3u64,
    watch = 0x5da86ac0c57155dcu64,
}

/// FairPlay Streaming Device Class
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum FPSDeviceClass {
    #[default]
    unknown = 0,

    // Apple Devices
    appleLivingRoom = 1,
    appleMobile = 2,
    appleDesktop = 3,
    appleSpacial = 4,
    appleWearable = 5,
    appleUnknown = 127,

    // Partner Devices
    partnerLivingRoom = 128,
    partnerUnknown = 255,
}

impl From::<u32> for FPSDeviceClass{
    fn from(value: u32) -> Self {
        match value {
            1 => FPSDeviceClass::appleLivingRoom,
            2 => FPSDeviceClass::appleMobile, 
            3 => FPSDeviceClass::appleDesktop, 
            4 => FPSDeviceClass::appleSpacial, 
            5 => FPSDeviceClass::appleWearable, 
            127 => FPSDeviceClass::appleUnknown,
            128 => FPSDeviceClass::partnerLivingRoom,
            255 => FPSDeviceClass::partnerUnknown,
            _ => FPSDeviceClass::unknown
        }
    }
}

// For "session key version used" TLLV (kLSKDSessionKeyVersionUsedTag)
pub enum SessionKey {
    generic = 0x182b0bb9f37383d1,
    video = 0x2a69d25f4b94c7c,
}

pub enum CKCVersion {
    one = 1,
    two = 2,
}

pub enum KeyPayloadSessionKeyToUse{
    generic = 1,
    video = 2,
}

pub enum KeyPayloadR1KeyToUse {
    generic = 1,
    video = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum EncryptionScheme {
    #[default]
    unknown,
    cbcs,
    cbc_ts,
    cbc1,
    cenc_v1,
    cenc_v2
}

impl From::<&str> for EncryptionScheme {
    fn from(value: &str) -> Self {
        match value {
            "cbcs" => EncryptionScheme::cbcs,
            "cbc-ts" => EncryptionScheme::cbc_ts,
            "cbc1" => EncryptionScheme::cbc1,
            "cenc-v1" => EncryptionScheme::cenc_v1,
            "cenc-v2" => EncryptionScheme::cenc_v2,
            _ => EncryptionScheme::unknown
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FPSCertificateStructs {
    certBundle(CertificateBundle),
    legacyCert(LegacyCertificate)
}
