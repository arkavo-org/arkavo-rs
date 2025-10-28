//
// base_parse_json_core.rs : Defines the mandatory functions inherited from the Core trait for the Base class.
//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants;
use crate::base::base_constants::EncryptionScheme;
use crate::base::base_constants::FPSLicenseType;
use crate::base::base_constants::AES128_IV_SZ;
use crate::base::base_constants::AES128_KEY_SZ;
use crate::base::structures::base_fps_structures::AssetInfo;
use crate::base::structures::base_fps_structures::FPSOperation;
use crate::base::structures::base_fps_structures::FPSOperationType;
use crate::base::structures::base_fps_structures::FPSResult;
use crate::base::structures::base_fps_structures::FPSResultsWrapper;
use crate::base::structures::base_fps_structures::{Base, FPSOperations};
use crate::fpsLogError;
use crate::returnErrorStatus;
use crate::validate::{FPSStatus, Result};
use crate::Extension;
use base64::engine::general_purpose;
use base64::Engine;
use serde_jsonrc::{Map, Value};
use std::fs::File;
extern crate hex;
use crate::base::base_constants::FPSHDCPRequirement;

impl Base {
    pub fn parseRootFromJson(file: File) -> Value {
        // Initialize generic logging with no extra information from json.
        // This will be called again later to add new information after json parsing.
        Extension::logInitCustom(None);

        serde_jsonrc::from_reader(file).expect("error while reading")
    }

    pub fn parseRootFromString(string: &str) -> Value {
        Extension::logInitCustom(None);

        serde_jsonrc::from_str(string).expect("error while reading")
    }

    /// Parses the initial parameters in the root of the JSON (id, create-ckc array, etc.)
    fn parseOperations(json: &Value, fpsOperations: &mut FPSOperations) -> Result<()> {
        // Get root object from JSON
        let mut root: Map<String, Value> = Default::default();

        Extension::parseOperationsCustom(json, &mut root)?;

        if root.contains_key(base_constants::CREATE_CKC_STR) {
            if let Some(create_ckc_obj_array) = root[base_constants::CREATE_CKC_STR].as_array() {
                // Parse create-ckc object array
                for ckc_obj in create_ckc_obj_array.iter() {
                    Base::parseOperation(FPSOperationType::createCKC, ckc_obj, fpsOperations, &mut &root)?;
                }
            } else {
                returnErrorStatus!(FPSStatus::paramErr);
            }
        } else if root.contains_key(base_constants::GET_CLIENT_INFO_STR) {
            if let Some(get_client_info_obj_array) = root[base_constants::GET_CLIENT_INFO_STR].as_array() {
                // Parse get-client-info object array
                for get_client_info_obj in get_client_info_obj_array.iter() {
                    Base::parseOperation(FPSOperationType::getClientInfo, get_client_info_obj, fpsOperations, &mut &root)?;
                }
            } else {
                returnErrorStatus!(FPSStatus::paramErr);
            }
        } else {
            returnErrorStatus!(FPSStatus::paramErr);
        }

        Ok(())
    }

    /// Parses the values in a single object.
    fn parseOperation(
        operationType: FPSOperationType,
        obj: &Value,
        fpsOperations: &mut FPSOperations,
        root: &mut &Map<String, Value>,
    ) -> Result<()> {
        let mut status: Result<()> = Ok(());

        let mut operation: FPSOperation = FPSOperation {operationType,  ..Default::default()};

        // ID - optional, defaults to 0
        if let Some(id) = obj[base_constants::ID_STR].as_u64() {
            operation.id = id;
        } else if let Some(id) = obj[base_constants::ID_STR].as_str() {
            // Try again as a string instead
            operation.id = id.parse::<u64>().unwrap_or(0);
        } else {
            operation.id = 0;
        }

        // SPC - required
        if let Some(spc) = obj[base_constants::SPC_STR].as_str() {
            let base64Request = spc.to_string();
            if let Err(e) = general_purpose::STANDARD.decode_vec(base64Request, &mut operation.spc) {
                fpsLogError!(FPSStatus::parserErr, "Error decoding base64 SPC: {}", e);
                status = Err(FPSStatus::parserErr);
            }
        } else {
            fpsLogError!(FPSStatus::paramErr, "SPC not found");
            status = Err(FPSStatus::paramErr);
        }

        if operation.operationType == FPSOperationType::createCKC {
            // Check-in - optional
            if let Some(check) = obj[base_constants::CHECK_IN_STR].as_bool() {
                operation.isCheckIn = check;
            }

            // asset-info - optional
            if let Some(assetInfoObjArray) = obj[base_constants::ASSET_INFO_STR].as_array() {
                if assetInfoObjArray.len() == 1 {
                    let mut assetInfo: AssetInfo = AssetInfo::default();
                    Base::parseAssetInfo(&assetInfoObjArray[0], &mut assetInfo)?;
                    operation.assetInfo = assetInfo;
                } else {
                    // We currently only expect one entry
                    fpsLogError!(FPSStatus::paramErr, "Unexpected multiple asset-info entries");
                    status = Err(FPSStatus::paramErr);
                }
            }
        }

        // Custom handling (if needed)
        if let Err(e) = Extension::parseOperationCustom(&mut operation, obj, root) {
            fpsLogError!(e, "parseOperationCustom failed");
            status = Err(e);
        }

        fpsOperations.operationsPtr.push(operation);

        status
    }

    /// Parses the values in a single asset-info object.
    pub fn parseAssetInfo(assetInfoObj: &Value, assetInfo: &mut AssetInfo) -> Result<()> {
        let mut status: Result<()> = Ok(());

        // Keep track if all CK parameters provided (CK, IV)
        assetInfo.isCKProvided = true;

        // content-key - optional for lease renewals
        if let Some(mut contentKey) = assetInfoObj[base_constants::CONTENT_KEY_STR].as_str() {
            // Remove any initial "0x"
            if contentKey.starts_with("0x") {
                (_, contentKey) = contentKey.split_at(2);
            }

            if !contentKey.is_empty() && contentKey != "0" {
                if let Ok(key) = hex::decode(contentKey) {
                    assetInfo.key = key;
                } else {
                    // Try again with an extra 0 in the front
                    fpsLogError!(
                        FPSStatus::paramErr,
                        "Warning! content key invalid length: \"{}\"",
                        contentKey
                    );
                    let mut tmp = contentKey.to_string();
                    tmp.insert(0, '0');
                    if let Ok(key) = hex::decode(tmp) {
                        assetInfo.key = key;
                    } else {
                        fpsLogError!(FPSStatus::paramErr, "unable to decode content key: \"{}\"", contentKey);
                        status = Err(FPSStatus::paramErr);
                    }
                }
            }
            assetInfo.key.resize(AES128_KEY_SZ, 0);
        } else {
            assetInfo.isCKProvided = false;
        }

        // content-iv - optional for lease renewals
        if let Some(mut contentIV) = assetInfoObj[base_constants::CONTENT_IV_STR].as_str() {
            // Remove any initial "0x"
            if contentIV.starts_with("0x") {
                (_, contentIV) = contentIV.split_at(2);
            }

            if !contentIV.is_empty() && contentIV != "0" {
                if let Ok(iv) = hex::decode(contentIV) {
                    assetInfo.iv = iv;
                } else {
                    // Try again with an extra 0 in the front
                    fpsLogError!(
                        FPSStatus::paramErr,
                        "Warning! content IV invalid length: \"{}\"",
                        contentIV
                    );
                    let mut tmp = contentIV.to_string();
                    tmp.insert(0, '0');
                    if let Ok(iv) = hex::decode(tmp) {
                        assetInfo.iv = iv;
                    } else {
                        fpsLogError!(FPSStatus::paramErr, "unable to decode content iv: \"{}\"", contentIV);
                        status = Err(FPSStatus::paramErr);
                    }
                }
            }
            assetInfo.iv.resize(AES128_IV_SZ, 0);
        } else {
            assetInfo.isCKProvided = false;
        }

        // lease-duration - optional
        if let Some(leaseDuration) = assetInfoObj[base_constants::LEASE_DURATION_STR].as_u64() {
            assetInfo.leaseDuration = leaseDuration as u32;
            if assetInfo.leaseDuration == 0 {
                assetInfo.leaseDuration = base_constants::NO_LEASE_DURATION;
            }
        } else {
            assetInfo.leaseDuration = base_constants::NO_LEASE_DURATION;
        }

        // offline-hls object - only present for persistent licenses
        if let Some(offlineHlsObject) = assetInfoObj[base_constants::OFFLINE_HLS_STR].as_object() {
            assetInfo.licenseType = FPSLicenseType::offlineHLS as u32;
            if let Err(e) = Base::parseOfflineHLS(offlineHlsObject, assetInfo) {
                fpsLogError!(e, "parseOfflineHLS failed");
                status = Err(e);
            }
        }

        // HDCP Requirement - optional
        // Support parsing as either an integer or string
        if let Some(hdcpType) = assetInfoObj[base_constants::HDCP_TYPE_STR].as_i64() {
            if let Err(e) = Base::parseHDCPType(hdcpType as i32, assetInfo) {
                fpsLogError!(e, "Error parsing HDCP type: {}", hdcpType);
                status = Err(e);
            }
        } else if let Some(hdcpTypeString) = assetInfoObj[base_constants::HDCP_TYPE_STR].as_str() {
            // If the string is not an integer, default to an invalid value (-2)
            let hdcpType = hdcpTypeString.parse::<i32>().unwrap_or(-2);

            if let Err(e) = Base::parseHDCPType(hdcpType, assetInfo) {
                fpsLogError!(e, "Error parsing HDCP type: {}", hdcpTypeString);
                status = Err(e);
            }
        } else {
            log::debug!("Warning! HDCP Type not provided, defaulting to Type 0");
            assetInfo.hdcpReq = FPSHDCPRequirement::hdcpType0 as u64;
        }

        // encryption-scheme - optional
        assetInfo.encryptionScheme = EncryptionScheme::default();

        if let Some(encryptionScheme) = assetInfoObj[base_constants::ENCRYPTION_SCHEME].as_str() {
            assetInfo.encryptionScheme = EncryptionScheme::from(encryptionScheme);
        }

        // Custom handling (if needed)
        if let Err(e) = Extension::parseAssetInfoCustom(assetInfoObj, assetInfo) {
            fpsLogError!(e, "parseAssetInfoCustom failed");
            status = Err(e);
        }

        status
    }

    /// Main function that parses input JSON and generates output JSON
    pub fn processOperations(json: Value) -> FPSResultsWrapper {
        let mut status;
        let mut fpsOperations: FPSOperations = Default::default();
        let mut fpsResultsWrapper: FPSResultsWrapper = FPSResultsWrapper::default();

        // Parse json and put results into operation
        status = Base::parseOperations(&json, &mut fpsOperations);

        if let Err(e) = Extension::processOperationsCustom(&json, &fpsOperations, &mut fpsResultsWrapper.results) {
            fpsLogError!(e, "processOperationsCustom failed");
            status = Err(e);
        }

        if status.is_ok() {
            for fpsOperation in &mut fpsOperations.operationsPtr {
                let mut fpsResult: FPSResult = FPSResult::default();

                fpsResult.operationType = fpsOperation.operationType;

                // Process operations only if parseOperations() call succeeded (as indicated by status)
                fpsResult.status = match Base::createResults(fpsOperation, &mut fpsResult) {
                    Ok(_) => FPSStatus::noErr,
                    Err(e) => e,
                };

                fpsResultsWrapper.results.resultPtr.push(fpsResult);
            }
        } else {
            let fpsResult: FPSResult = FPSResult {status: status.unwrap_err(), ..Default::default()};
            fpsResultsWrapper.results.resultPtr.push(fpsResult);
        }

        fpsResultsWrapper
    }
}
