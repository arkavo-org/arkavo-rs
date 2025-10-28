//
// base_fps_structures.rs: Contains the structure definitions for the Base class.
//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use serde::Deserialize;
use serde::Serialize;

use crate::base::base_constants;
use crate::base::base_constants::EncryptionScheme;
use crate::base::base_constants::FPSCertificateStructs;
use crate::base::base_constants::FPSHDCPRequirement;
use crate::base::base_constants::FPS_V1_HU_SZ;
use crate::base::structures::base_server_structures::FPSDeviceIdentity;
use crate::base::structures::base_server_structures::FPSDeviceInfo;
use crate::base::structures::base_server_structures::FPSOfflineSyncData;
use crate::base::structures::base_server_structures::FPSServerMediaPlaybackState;
use super::base_server_structures::VMDeviceInfo;
use crate::extension_structures;
use crate::validate::FPSStatus;
use std::fmt::Debug;

/// Base container where common code is implemented.
pub struct Base {}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub enum FPSOperationType {
    #[default]
    createCKC,      // Generate CKC containing FairPlay license
    getClientInfo,  // Only return client device information from the license request
}

/// Information about all operations in a request.
///
/// Contains a vector of FPSOperation. This is necessary if receiving multiple requests in the same JSON.
#[derive(Debug, Default)]
pub struct FPSOperations {
    pub operationsPtr: Vec<FPSOperation>,
}

/// Information about a single operation.
///
/// This is the basic structure of a FairPlay Streaming key request after the JSON has been parsed.
#[derive(Debug, Default, Clone)]
pub struct FPSOperation {
    pub operationType: FPSOperationType,
    pub id: u64,
    pub spc: Vec<u8>,

    /// True when input SPC is a SyncSPC with check-in
    pub isCheckIn: bool,

    /// Asset information for asset provided in the input
    pub assetInfo: AssetInfo,

    // Extension
    pub extension: extension_structures::FPSOperationExtension,
}

/// Protection requirements related to a particular asset.
#[derive(Debug, Clone)]
pub struct AssetInfo {
    pub id: String,             // The asset identifier
    pub key: Vec<u8>,           // Content encryption key
    pub iv: Vec<u8>,            // Content encryption iv
    pub isCKProvided: bool,     // true if key and iv are valid

    pub hdcpReq: u64,           // one of the FPSHDCPRequirement enums. Using type u64 so we can test with invalid values.

    // Expirations
    pub leaseDuration: u32,     // Lease duration in seconds. Starts at SPC creation time.
    pub rentalDuration: u32,    // Rental duration in seconds. Starts at asset download time.
    pub playbackDuration: u32,  // Playback duration in seconds. Starts at asset first playback time.

    // Offline HLS parameters
    pub licenseType: u32,               // streaming vs offline license
    pub streamId: Option<Vec<u8>>,      // unique Id of each HLS sub-stream
    pub titleId: Option<Vec<u8>>,       // Id of a title (program). Same for all HLS substreams of a give title.

    // The encryption scheme used to encrypt the content
    pub encryptionScheme: EncryptionScheme,

    // Extension
    pub extension: extension_structures::AssetInfoExtension,
}

impl Default for AssetInfo {
    fn default() -> AssetInfo {
        AssetInfo {
            id: String::default(),
            isCKProvided: false,
            key: vec![0; base_constants::AES128_KEY_SZ],
            iv: vec![0; base_constants::AES128_IV_SZ],
            leaseDuration: 0,
            rentalDuration: 0,
            playbackDuration: 0,
            hdcpReq: FPSHDCPRequirement::hdcpNotRequired as u64,

            licenseType: 0,
            streamId: None,
            titleId: None,

            encryptionScheme: Default::default(),

            extension: Default::default(),
        }
    }
}

/// Return data for a single operation (expected to be returned in the output JSON).
#[derive(Debug)]
pub struct FPSResult {
    pub operationType: FPSOperationType,
    pub id: u64,
    pub status: FPSStatus,
    pub hu: Vec<u8>,
    pub ckc: Vec<u8>,

    // Per-asset information
    pub resultAssetInfo: FPSResultAssetInfo,

    pub streamingIndicator: u64,
    pub transactionId: u64,

    pub capabilities: Vec<u8>,
    pub supportedSecurityLevel: Option<u64>,
    pub clientKextDenyListVersion: u32,

    pub isCheckIn: bool,

    // Sync TLLV
    pub offlineSyncData: FPSOfflineSyncData,

    // Device Identity Data
    pub deviceIdentity: FPSDeviceIdentity,
    pub deviceInfo: FPSDeviceInfo,

    // Virtual Machine device information (if playing on a VM)
    pub vmDeviceInfo: Option<VMDeviceInfo>,

    // Extension (only for information not related to an individual asset)
    pub extension: extension_structures::FPSResultExtension,
}

impl Default for FPSResult {
    fn default() -> FPSResult {
        FPSResult {
            operationType: FPSOperationType::default(),
            id: 0,
            status: FPSStatus::noErr,
            hu: vec![0; FPS_V1_HU_SZ],
            ckc: Vec::new(),

            resultAssetInfo: FPSResultAssetInfo::default(),

            streamingIndicator: 0,
            transactionId: 0,

            capabilities: Default::default(),
            supportedSecurityLevel: None,
            clientKextDenyListVersion: 0,

            isCheckIn: false,
            offlineSyncData: Default::default(),

            deviceIdentity: Default::default(),
            deviceInfo: Default::default(),

            vmDeviceInfo: None,

            extension: Default::default(),
        }
    }
}

/// Asset-specific information for assets in the FPSResult structure
#[derive(Debug, Clone, Default)]
pub struct FPSResultAssetInfo {
    pub assetId: String,
    pub playInfo: FPSServerMediaPlaybackState,

    // Extension
    pub extension: extension_structures::FPSResultAssetInfoExtension,
}

/// Return data for all operations in a request.
///
/// Contains a vector of FPSResult. This is necessary if multiple requests are sent at once (much like FPSOperations).
#[derive(Debug, Default)]
pub struct FPSResults {
    pub resultPtr: Vec<FPSResult>,

    // Extension
    pub extension: extension_structures::FPSResultsExtension,
}

#[derive(Debug, Default)]
pub struct FPSResultsWrapper {
    pub results: FPSResults
}

/// Structure used to call C library function `PartnerKSMCreateKeyPayload`.
///
/// All members are 64B size (u64 or pointer) for easier compatibility.
#[derive(Debug)]
#[repr(C)]
pub struct KSMKeyPayload {
    pub version: u64,                       // in: version of the structure. Currently supported version is 1
    pub contentKey: *const u8,              // in: content key
    pub contentKeyLength: u64,              // in: only 16 byte long keys accepted at the moment
    pub contentIV: *const u8,               // in: content IV
    pub contentIVLength: u64,               // in: must be 16 bytes
    pub contentType: u64,                   // in: one of KSMKeyPayloadContentType enums
    pub SK_R1: *const u8,                   // in: content of FPSTLLVTagValue::sessionKeyR1Tag (0x3d1a10b8bffac2ec) TLLV
    pub SK_R1Length: u64,                   // in: size of SK_R1 data
    pub R2: *const u8,                      // in: content of FPSTLLVTagValue::r2Tag (0x71b5595ac1521133) TLLV
    pub R2Length: u64,                      // in: size of R2 data
    pub R1Integrity: *const u8,             // in: content of FPSTLLVTagValue::sessionKeyR1IntegrityTag (0xb349d4809e910687) TLLV
    pub R1IntegrityLength: u64,             // in: size of R1 integrity data
    pub supportedKeyFormats: *const u64,    // in: either delivered in FPSTLLVTagValue::supportedKeyFormatTag (0x8d8e84fa6cc35eb7) or set to 16 byte key (FPSKeyFormatTag::buf16Byte) for older devices
    pub numberOfSupportedKeyFormats: u64,   // in: number of key formats in supportedKeyFormats array
    pub cryptoVersionUsed: u64,             // in: delivered in FPSTLLVTagValue::protocolVersionUsedTag (0x5d81bcbcc7f61703) TLLV
    pub provisioningData: *const u8,        // in: server Provisioning Data generated by WWDR
    pub provisioningDataLength: u64,        // in: size of the Provisioning Data
    pub certHash: *const u8,                // in: server certificate hash delivered in SPC header
    pub certHashLength: u64,                // in: size of the certificate hash
    pub clientHU: *const u8,                // out: client HU. Memory allocated by caller. Allocated buffer size should be passed in clientHULength
    pub clientHULength: u64,                // in/out: in: buffer size allocated for clientHU. out: actual HU size returned
    pub contentKeyTLLVTag: u64,             // out: Content Key TLLV tag to send to the client device
    pub contentKeyTLLVPayload: *mut u8,     // out: payload of Content Key TLLV. Memory allocated by caller. Allocated buffer size should be passed in contentKeyTLLVPayloadLength
    pub contentKeyTLLVPayloadLength: u64,   // in/out: in: buffer size allocated for contentKeyTLLVPayload. out: actual content key TLLV payload size returned
    pub R1: *mut u8,                        // out: R1 data. Memory allocated by caller. Allocated buffer size should be passed in R1Length
    pub R1Length: u64,                      // in/out: in: buffer size allocated for R1. out: actual R1 size returned
    pub SK_R1Video: *mut u8,                // in: content of kFPSServerTagSessionKeyR1Video (0x697af6213858562f) TLLV
    pub SK_R1VideoLength : u64,             // in: size of SK_R1_Video data
    pub R2Video: *mut u8,                   // in: content of kFPSServerTagR2Video (0xdb30b89dcb5834b3) TLLV
    pub R2VideoLength: u64,                 // in: size of R2Video data
    pub sessionKeyToUse: u64,               // in/out: use generic session key or video session key. SKDCreateKeyPayload() would return which key was actually used. See SKDKeyPayloadSessionKeyToUse enum
    pub R1KeyToUse: u64,                    // out: indicates which R1 key was returned to use for CKC encryption. See KSKDeyPayloadR1KeyToUse enum
}


/// Structure used to read in Certificates, private keys, and provisioning data
#[derive(Debug, Default, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CertificateBundle {
    #[serde(rename = "certificate")]
    pub certBundle: String,
    #[serde(rename = "1024-private-key")]
    pub pkey1024: String,
    #[serde(rename = "2048-private-key")]
    pub pkey2048: String,
    #[serde(rename = "provisioning-data")]
    pub provisioningData: String
}

/// Legacy structure used for 1024-bit certificate and ASk
#[derive(Debug, Default, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct LegacyCertificate {
    #[serde(rename = "certificate")]
    pub legacyCert: String,
    #[serde(rename = "1024-private-key")]
    pub pkey1024: String,
    pub ask: String
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CertificateList {
    pub certificates: Vec<FPSCertificateStructs>
}
