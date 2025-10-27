//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants;
use crate::base::base_constants::{FPSKeyDurationType, FPSTLLVTagValue};
use crate::base::parse_json::parse_certificates::CERT_MAP;
use crate::base::structures::base_fps_structures::{
    AssetInfo, FPSOperation, FPSOperationType, FPSOperations, FPSResult, FPSResults,
};
use crate::base::structures::base_server_structures::{
    FPSServerCtx, FPSServerSPCContainer, FPSServerTLLV,
};
use crate::extension::extension_constants::{self, ContentType, DEFAULT_FPS_CERT_PATH};
use crate::extension::structures::extension_structures::SDKExtension;
use crate::extension_structures::FPSOperationExtension;
use crate::validate::{FPSStatus, Result};
use crate::Base;
use crate::{fpsLogError, requireAction, returnErrorStatus};
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use rand::Rng;
use serde_jsonrc::{Map, Value};
use std::io::Write;

////////////////////////////////////////////////////////////////////////////////
// Utility Functions
////////////////////////////////////////////////////////////////////////////////

/// Initializes custom log output formatting. Change the format here to match
/// whatever log formatting works best for your tools.
pub fn logInitCustom(_extension: Option<&FPSOperationExtension>) {
    let env = env_logger::Env::new()
        .filter_or("RUST_LOG", "trace")
        .write_style("RUST_LOG_STYLE");

    // Example configuration of log::Debug!() style prints:
    env_logger::Builder::from_env(env)
        .format(move |buf, record| writeln!(buf, "[DEBUG] {}", record.args()))
        .try_init()
        .unwrap_or(());
    // or match the fpsLogError!() style prints:
    // env_logger::Builder::from_env(env)
    //     .format(move |buf, record| {
    //         writeln!(
    //             buf,
    //             "timestamp=\"{}\",FP_TOOLN=\"{}\",FP_TOOLV=\"{}\",FP_PID=\"{}\",FP_FL=\"{}\",FP_LN=\"{}\",{}",
    //             chrono::Utc::now().format("%Y-%m-%d %T,%3f"),
    //             env!("CARGO_PKG_NAME"),
    //             env!("CARGO_PKG_VERSION"),
    //             std::process::id(),
    //             record.file().unwrap_or("unknown file"),
    //             record.line().unwrap_or(0),
    //             record.args()
    //             )
    //     })
    // .init();
    // or use default format:
    // env_logger::Builder::from_env(env).try_init().unwrap_or(());

    // Example configuration of fpsLogError!() style prints:
    crate::logging::LOG_FORMAT.with(|a| {
        let _ = a.replace(Box::new(|line, file| {
            format!(
                "timestamp=\"{}\",FP_TOOLN=\"{}\",FP_TOOLV=\"{}\",FP_PID=\"{}\",FP_FL=\"{}\",FP_LN=\"{}\"",
                chrono::Local::now().format("%Y-%m-%d %T,%3f"),
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
                std::process::id(),
                file,
                line,
            )
        }));
    });
}

/// Fills buffer with random numbers
pub fn genRandom(out: &mut [u8], length: usize) {
    let mut rng = rand::thread_rng();
    rng.fill(&mut out[0..length]);
}

////////////////////////////////////////////////////////////////////////////////
// Input Parsing and Verification Functions
////////////////////////////////////////////////////////////////////////////////

/// Performs any custom input json top-level parsing operations
pub fn parseOperationsCustom(json: &Value, root: &mut Map<String, Value>) -> Result<()> {
    if let Some(rootObj) = json[extension_constants::FAIRPLAY_STREAMING_REQUEST_STR].as_object() {
        *root = rootObj.clone();
    } else {
        returnErrorStatus!(FPSStatus::paramErr);
    }
    Ok(())
}

/// Performs custom parsing of account info JSON input.
///
/// Use this function to handle any values outside of what the Base code parses
/// for json input `offline-hls`.
pub fn parseOfflineHLSCustom(
    _ckcObj: &serde_jsonrc::Map<String, Value>,
    _assetInfo: &mut AssetInfo,
) -> Result<()> {
    Ok(())
}

/// Performs custom verification of account info JSON input.
pub fn verifyOfflineHLSCustom(_assetInfo: &mut AssetInfo) -> Result<()> {
    Ok(())
}

/// Performs custom parsing of `hdcp-type` JSON input.
///
/// Use this function to handle any values outside of what the Base code parses.
pub fn parseHDCPTypeCustom(_hdcpType: i32) -> Result<u64> {
    // Base code already handled all known values. Treat unknown values as an error.
    Err(FPSStatus::paramErr)
}

/// Performs parsing of any custom fields within the `asset-info` object of the input JSON
pub fn parseAssetInfoCustom(assetInfoObj: &Value, assetInfo: &mut AssetInfo) -> Result<()> {
    // Parse "content-type" from input json
    if let Some(contentType) = assetInfoObj[extension_constants::CONTENT_TYPE_STR].as_str() {
        match contentType {
            extension_constants::CONTENT_TYPE_UHD_STR => {
                assetInfo.extension.contentType = ContentType::uhd;
            }
            extension_constants::CONTENT_TYPE_HD_STR => {
                assetInfo.extension.contentType = ContentType::hd;
            }
            extension_constants::CONTENT_TYPE_SD_STR => {
                assetInfo.extension.contentType = ContentType::sd;
            }
            extension_constants::CONTENT_TYPE_AUDIO_STR => {
                assetInfo.extension.contentType = ContentType::audio;
            }
            _ => {
                assetInfo.extension.contentType = ContentType::unknown;
            }
        }
    } else {
        assetInfo.extension.contentType = ContentType::unknown;
    }

    Ok(())
}

/// Performs parsing of any custom fields within the operation object of the input JSON
pub fn parseOperationCustom(
    _fpsOperation: &mut FPSOperation,
    _obj: &Value,
    _root: &mut &Map<String, Value>,
) -> Result<()> {
    Ok(())
}

/// Performs any remaining parsing of the top level input JSON after FPSOperation structure has been filled
pub fn processOperationsCustom(
    _json: &Value,
    _fpsOperations: &FPSOperations,
    _fpsResults: &mut FPSResults,
) -> Result<()> {
    Ok(())
}

/// Decrypts `spcContainer.aesWrappedKey` into `aesKey`.
///
/// Uses partner-specific private key for the RSA decyrption.
pub fn decryptKeyRSACustom(
    spcContainer: &mut FPSServerSPCContainer,
    aesKey: &mut Vec<u8>,
) -> Result<()> {
    let aesWrappedKeySize = spcContainer.aesWrappedKeySize;
    let aesWrappedKey: &Vec<u8> = &spcContainer.aesWrappedKey;

    // Sanity check inputs
    requireAction!(!aesWrappedKey.is_empty(), return Err(FPSStatus::paramErr));
    let rsa = SDKExtension::getPrivateKey(spcContainer)?;

    *aesKey = vec![0_u8; rsa.size() as usize];

    if aesWrappedKeySize == base_constants::FPS_V1_WRAPPED_KEY_SZ {
        if rsa
            .private_decrypt(aesWrappedKey, aesKey, openssl::rsa::Padding::PKCS1_OAEP)
            .is_err()
        {
            // If decryption failed, it is likely the data was encrypted for another key.
            fpsLogError!(FPSStatus::invalidCertificateErr, "RSA Decryption Failed");
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }
    } else if aesWrappedKeySize == base_constants::FPS_V2_WRAPPED_KEY_SZ {
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();

        let mut decrypter = openssl::encrypt::Decrypter::new(&pkey).unwrap();

        decrypter
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
            .unwrap();
        decrypter
            .set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())
            .unwrap();
        decrypter
            .set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())
            .unwrap();

        // Get the length of the output buffer
        let bufferLen = decrypter.decrypt_len(aesWrappedKey).unwrap();
        let mut decoded = vec![0u8; bufferLen];

        // Decrypt the data
        if decrypter.decrypt(aesWrappedKey, &mut decoded).is_err() {
            // If decryption failed, it is likely the data was encrypted for another key.
            fpsLogError!(FPSStatus::invalidCertificateErr, "RSA Decryption Failed");
            returnErrorStatus!(FPSStatus::invalidCertificateErr);
        }

        *aesKey = decoded.to_vec();
    }

    Ok(())
}

/// Performs any custom steps needed directly after SPC decryption
pub fn decryptSPCDataCustom(_spc: &[u8], _spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
    Ok(())
}

/// Performs parsing of any TLLVs not handled in Base
pub fn parseTLLVCustom(_tllv: &FPSServerTLLV, _value: &mut FPSServerSPCContainer) -> Result<()> {
    Ok(())
}

/// Performs any custom validation after all TLLVs have been parsed.
pub fn validateTLLVsCustom(_spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
    Ok(())
}

/// Performs parsing of any capabilities flags not handled in Base
pub fn checkSupportedFeaturesCustom(_serverCtx: &mut FPSServerCtx) -> Result<()> {
    Ok(())
}

/// Performs extension-specific checks of the request, including checking
/// that the request meets business rules.
pub fn validateRequestCustom(
    fpsOperation: &mut FPSOperation,
    serverCtx: &mut FPSServerCtx,
) -> Result<()> {
    if fpsOperation.operationType == FPSOperationType::createCKC {
        // Check that business rules are satisfied
        SDKExtension::checkBusinessRules(
            fpsOperation.isCheckIn,
            &fpsOperation.assetInfo,
            serverCtx,
        )?;
    }

    Ok(())
}

/// Lookup asset information from database
///
/// If asset information is not provided as part of the JSON input, now is the time
/// to use the Asset ID found inside the SPC (serverCtx.spcContainer.spcData.spcAssetInfo.id)
/// to query your database and fill in fpsOperation.assetInfo.
pub fn queryDatabaseCustom(
    _fpsOperation: &mut FPSOperation,
    _serverCtx: &FPSServerCtx,
) -> Result<()> {
    /*
    // Query database using serverCtx.spcContainer.spcData.spcAssetInfo.id to fill in assetInfo structure.
    fpsOperation.assetInfo.id = serverCtx.spcContainer.spcData.spcAssetInfo.id;
    fpsOperation.assetInfo.key =
    fpsOperation.assetInfo.iv =
    fpsOperation.assetInfo.isCKProvided =
    fpsOperation.assetInfo.hdcpReq =
    fpsOperation.assetInfo.encryptionScheme =
    fpsOperation.assetInfo.extension.contentType =
    ...
    */

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// Output Creation Functions
////////////////////////////////////////////////////////////////////////////////

/// Populates `serverCtx.ckcContainer` and `fpsResult` structure with any custom fields that will be returned to the caller
pub fn populateResultsCustom(
    _serverCtx: &mut FPSServerCtx,
    _operation: &FPSOperation,
    _result: &mut FPSResult,
) -> Result<()> {
    Ok(())
}

/// Adds Content Key payload TLLV and related data to the CKC container
pub fn createContentKeyPayloadCustom(
    operation: &FPSOperation,
    serverCtx: &mut FPSServerCtx,
    fpsResult: &mut FPSResult,
) -> Result<()> {
    SDKExtension::createContentKeyPayloadCustomImpl(&operation.assetInfo, serverCtx)?;

    // Player HU (returned from the call to KSMCreateKeyPayload)
    fpsResult.hu = serverCtx.spcContainer.spcData.hu.to_owned();

    Ok(())
}

/// Fills any custom data in the CKC container
pub fn fillCKCContainerCustom(_serverCtx: &mut FPSServerCtx) -> Result<()> {
    Ok(())
}

/// Populates securityLevelTag Tag
///
/// The base code does not add this tag to the CKC by default. It is up to the extension to add it here.
pub fn populateTagSecurityLevelCustom(serverCtx: &mut FPSServerCtx) -> Result<()> {
    SDKExtension::populateTagSecurityLevel(serverCtx)
}

/// Populates any custom TLLVs
///
/// One of the TLLVs indicating license expiration should be populated here (if required),
/// because it is not done in Base.
pub fn populateTagsCustom(serverCtx: &mut FPSServerCtx) -> Result<()> {
    // Construct and serialize either offline key tag or key duration tag
    let keyType: u32 = serverCtx
        .ckcContainer
        .ckcData
        .ckcAssetInfo
        .keyDuration
        .keyType;

    if serverCtx
        .spcContainer
        .spcData
        .spcDataParser
        .parsedTagValues
        .contains(&(FPSTLLVTagValue::mediaPlaybackStateTag as u64))
        && (keyType != FPSKeyDurationType::none as u32)
    {
        if ((keyType == FPSKeyDurationType::persistenceAndDuration as u32)
            || (keyType == FPSKeyDurationType::persistence as u32))
            && serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsOfflineKeyTLLV
        {
            Base::populateTagServerOfflineKey(serverCtx)?;
        } else {
            Base::populateTagServerKeyDuration(serverCtx)?;
        }
    }

    Ok(())
}

/// Populates Content ID for Offline Key TLLV V1
pub fn offlineKeyTagPopulateContentIDCustom(
    _serverCtx: &mut FPSServerCtx,
    offlineKeyTLLV: &mut Vec<u8>,
) -> Result<()> {
    // Just add 16B of zeros
    offlineKeyTLLV.append(&mut vec![0; 16]);

    Ok(())
}

/// Adds any custom items to `FPSResult` after CKC has been generated
pub fn finalizeResultsCustom(_serverCtx: &FPSServerCtx, _fpsResult: &mut FPSResult) -> Result<()> {
    Ok(())
}

/// Adds any custom fields to the 'create-ckc' object of the output JSON
pub fn serializeCreateCKCNodeCustom(
    _result: &FPSResult,
    _ckcNode: &mut Map<String, Value>,
) -> Result<()> {
    Ok(())
}

/// Packages `ckcNode` into final JSON output (required).
pub fn serializeResultsCustom(
    _fpsResults: &FPSResults,
    ckcNode: Vec<Value>,
    jsonResults: &mut Map<String, Value>,
) -> Result<()> {
    let mut root = Map::new();

    root.insert(
        base_constants::CREATE_CKC_STR.to_string(),
        Value::Array(ckcNode),
    );

    // Add into top level response object
    jsonResults.insert(
        extension_constants::FAIRPLAY_STREAMING_RESPONSE_STR.to_string(),
        Value::Object(root),
    );

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// Credentials Functions
////////////////////////////////////////////////////////////////////////////////
pub fn getDefaultCertPath() -> String {
    return DEFAULT_FPS_CERT_PATH.to_string();
}

impl SDKExtension {
    /// Returns private key associated with either 1024 or 2048-bit certificate
    fn getPrivateKey(spcContainer: &FPSServerSPCContainer) -> Result<Rsa<Private>> {
        let certificate_map = match CERT_MAP.get() {
            Some(s) => s,
            None => {
                fpsLogError!(
                    FPSStatus::invalidCertificateErr,
                    "Failed to get certificate hash map"
                );
                returnErrorStatus!(FPSStatus::invalidCertificateErr);
            }
        };
        let certHash = hex::encode(&spcContainer.certificateHash);
        let certInfo = match certificate_map.get(&certHash) {
            Some(s) => s,
            None => {
                fpsLogError!(
                    FPSStatus::invalidCertificateErr,
                    "Certificate hash not found"
                );
                returnErrorStatus!(FPSStatus::invalidCertificateErr);
            }
        };

        Ok(certInfo.privateKey.clone())
    }

    /// Returns provisioning data
    pub fn getProvisioningData(spcContainer: &FPSServerSPCContainer) -> Result<Vec<u8>> {
        let certificate_map = match CERT_MAP.get() {
            Some(s) => s,
            None => {
                fpsLogError!(
                    FPSStatus::invalidCertificateErr,
                    "Failed to get certificate hash map"
                );
                returnErrorStatus!(FPSStatus::invalidCertificateErr);
            }
        };
        let certHash = hex::encode(&spcContainer.certificateHash);
        let certInfo = match certificate_map.get(&certHash) {
            Some(s) => s,
            None => {
                fpsLogError!(
                    FPSStatus::invalidCertificateErr,
                    "Certificate hash not found"
                );
                returnErrorStatus!(FPSStatus::invalidCertificateErr);
            }
        };
        Ok(certInfo.provisioningData.clone())
    }
}
