//
// serialize.rs : Defines serialization functions required to output data
//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//
use super::extension_constants;
use crate::base::structures::base_fps_structures::FPSResultsWrapper;
use crate::base::structures::base_fps_structures::{FPSOperationType, FPSResult, FPSResults};
use crate::base::Utils::FPSServerUtils::readBigEndianU64;
use crate::base_constants::*;
use crate::extension::extension_constants::FPSSecurityLevel;
use crate::validate::FPSStatus;
use base64::engine::general_purpose;
use base64::Engine;
use hex::ToHex;
use serde::ser::SerializeMap;
use serde::ser::SerializeStruct;
use serde::Serialize;
use serde_jsonrc::Map;

impl Serialize for FPSResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        // ID
        map.serialize_entry(ID_STR, &self.id)?;

        // Status
        map.serialize_entry(STATUS_STR, &self.status)?;

        if self.status == FPSStatus::noErr {
            // Asset ID
            map.serialize_entry(ASSET_ID_STR, &self.resultAssetInfo.assetId)?;

            // Playback State
            let mut playbackStateMap = Map::new();
            playbackStateMap.insert(
                CREATION_DATE_STR.to_string(),
                self.resultAssetInfo.playInfo.date.into(),
            );
            playbackStateMap.insert(
                STATE_STR.to_string(),
                self.resultAssetInfo.playInfo.playbackState.into(),
            );
            playbackStateMap.insert(
                SESSION_ID_STR.to_string(),
                self.resultAssetInfo.playInfo.playbackId.into(),
            );
            map.serialize_entry(PLAYBACK_STATE_STR, &playbackStateMap)?;

            // Player HU
            let hu: String = self.hu.encode_hex_upper();
            map.serialize_entry(HU_STR, &hu)?;

            // Streaming indicator
            map.serialize_entry(STREAMING_INDICATOR_STR, &self.streamingIndicator)?;

            // Transaction ID
            map.serialize_entry(TRANSACTION_ID_STR, &self.transactionId)?;

            // Security Level
            match self.supportedSecurityLevel {
                x if x == Some(FPSSecurityLevel::main as u64) => {
                    map.serialize_entry(SECURITY_LEVEL_STR, &MAIN_STR)?;
                }
                x if x == Some(FPSSecurityLevel::baseline as u64) => {
                    map.serialize_entry(SECURITY_LEVEL_STR, &BASELINE_STR)?;
                }
                _ => {
                    // Unknown value. Serialize as a hex string instead.
                    let securityLevelHex: String =
                        format!("{:016X}", self.supportedSecurityLevel.unwrap_or_default());
                    map.serialize_entry(SECURITY_LEVEL_STR, &securityLevelHex)?;
                }
            }

            // KDL Version
            map.serialize_entry(KDL_VERSION_STR, &self.clientKextDenyListVersion)?;

            // Capabilities Bits
            let mut capabilitiesMap = Map::new();

            let capabilitiesLowBits = readBigEndianU64(&self.capabilities, 8).unwrap_or_default();
            capabilitiesMap.insert(
                HDCP_STR.to_string(),
                (capabilitiesLowBits & FPS_CAPABILITY_HDCP_TYPE1_ENFORCEMENT_SUPPORTED != 0).into(),
            );
            capabilitiesMap.insert(
                OFFLINE_KEY_STR.to_string(),
                (capabilitiesLowBits & FPS_CAPABILITY_OFFLINE_KEY_SUPPORTED != 0).into(),
            );
            capabilitiesMap.insert(
                SECURE_INVALIDATION_STR.to_string(),
                (capabilitiesLowBits & FPS_CAPABILITY_CHECK_IN_SUPPORTED != 0).into(),
            );
            capabilitiesMap.insert(
                OFFLINE_KEY_2_STR.to_string(),
                (capabilitiesLowBits & FPS_CAPABILITY_OFFLINE_KEY_V2_SUPPORTED != 0).into(),
            );
            capabilitiesMap.insert(
                SECURITY_LEVEL_BASELINE_STR.to_string(),
                (capabilitiesLowBits & FPS_CAPABILITY_SECURITY_LEVEL_BASELINE_SUPPORTED != 0)
                    .into(),
            );
            capabilitiesMap.insert(
                SECURITY_LEVEL_MAIN_STR.to_string(),
                (capabilitiesLowBits & FPS_CAPABILITY_SECURITY_LEVEL_MAIN_SUPPORTED != 0).into(),
            );
            map.serialize_entry(CAPABILITIES_STR, &capabilitiesMap)?;

            // Device Identity
            if self.deviceIdentity.isDeviceIdentitySet {
                let mut deviceIdentityMap = Map::new();

                // FPDI Version
                deviceIdentityMap.insert(
                    FPDI_VERSION_STR.to_string(),
                    self.deviceIdentity.fpdiVersion.into(),
                );

                // Device Class
                deviceIdentityMap.insert(
                    DEVICE_CLASS_STR.to_string(),
                    self.deviceIdentity.deviceClass.into(),
                );

                // Vendor Hash
                let vendorHash: String = self.deviceIdentity.vendorHash.encode_hex_upper();
                deviceIdentityMap.insert(VENDOR_HASH_STR.to_string(), vendorHash.into());

                // Product Hash
                let productHash: String = self.deviceIdentity.productHash.encode_hex_upper();
                deviceIdentityMap.insert(PRODUCT_HASH_STR.to_string(), productHash.into());

                // FPS version in REE
                let fpsReeVersion = format!("{:08X}", self.deviceIdentity.fpVersionREE);
                deviceIdentityMap.insert(FPS_REE_VERSION_STR.to_string(), fpsReeVersion.into());

                // FPS version in TEE
                let fpsTeeVersion = format!("{:08X}", self.deviceIdentity.fpVersionTEE);
                deviceIdentityMap.insert(FPS_TEE_VERSION_STR.to_string(), fpsTeeVersion.into());

                // OS Version
                let osVersion = format!("{:08X}", self.deviceIdentity.osVersion);
                deviceIdentityMap.insert(OS_VERSION_STR.to_string(), osVersion.into());

                map.serialize_entry(DEVICE_IDENTITY_STR, &deviceIdentityMap)?;
            }

            // Device Info
            if self.deviceInfo.isDeviceInfoSet {
                let mut deviceInfoMap = Map::new();

                // Device Type
                let deviceType = format!("{:016X}", self.deviceInfo.deviceType);
                deviceInfoMap.insert(DEVICE_TYPE_STR.to_string(), deviceType.into());

                // OS Version
                let osVersion = format!("{:08X}", self.deviceIdentity.osVersion);
                deviceInfoMap.insert(OS_VERSION_STR.to_string(), osVersion.into());

                map.serialize_entry(DEVICE_INFO_STR, &deviceInfoMap)?;
            }

            // VM Device Info
            if let Some(vmDeviceInfo) = self.vmDeviceInfo.as_ref() {
                let mut vmDeviceInfoMap = Map::new();

                // Print Host VM Information
                vmDeviceInfoMap.insert(
                    HOST_DEVICE_CLASS_STR.to_string(),
                    (vmDeviceInfo.hostDeviceClass as u32).into(),
                );
                let hostOSVersion = format!("{:08X}", vmDeviceInfo.hostOSVersion);
                vmDeviceInfoMap.insert(HOST_OS_VERSION_STR.to_string(), hostOSVersion.into());
                vmDeviceInfoMap.insert(
                    HOST_VM_PROTOCOL_VERSION.to_string(),
                    vmDeviceInfo.hostVMProtocolVersion.into(),
                );

                // Print Guest VM Information
                vmDeviceInfoMap.insert(
                    GUEST_DEVICE_CLASS_STR.to_string(),
                    (vmDeviceInfo.guestDeviceClass as u32).into(),
                );
                let guestOSVersion = format!("{:08X}", vmDeviceInfo.guestOSVersion);
                vmDeviceInfoMap.insert(GUEST_OS_VERSION_STR.to_string(), guestOSVersion.into());
                vmDeviceInfoMap.insert(
                    GUEST_VM_PROTOCOL_VERSION.to_string(),
                    vmDeviceInfo.guestVMProtocolVersion.into(),
                );

                map.serialize_entry(VM_DEVICE_INFO_STR, &vmDeviceInfoMap)?;
            }

            // Offline Sync Data
            if self.offlineSyncData.version > 0 {
                let mut offlineSyncMap = Map::new();

                // Version
                offlineSyncMap.insert(VERSION_STR.to_string(), self.offlineSyncData.version.into());

                // Duration to Expiry
                offlineSyncMap.insert(
                    DURATION_TO_EXPIRY_STR.to_string(),
                    self.offlineSyncData.durationToRentalExpiry.into(),
                );

                if self.offlineSyncData.version >= 2 {
                    // Server Challenge
                    offlineSyncMap.insert(
                        SERVER_CHALLENGE_STR.to_string(),
                        self.offlineSyncData.syncServerChallenge.into(),
                    );

                    // Flags
                    let mut flagsMap = Map::new();
                    flagsMap.insert(
                        REPORT_STR.to_string(),
                        (self.offlineSyncData.syncFlags & KD_SYNC_SPC_FLAG_REPORT != 0).into(),
                    );
                    flagsMap.insert(
                        SECURE_INVALIDATION_STR.to_string(),
                        (self.offlineSyncData.syncFlags & KD_SYNC_SPC_FLAG_SECURE_INVALIDATION
                            != 0)
                            .into(),
                    );
                    flagsMap.insert(
                        SECURE_INVALIDATION_ALL_STR.to_string(),
                        (self.offlineSyncData.syncFlags & KD_SYNC_SPC_FLAG_SECURE_INVALIDATION_ALL
                            != 0)
                            .into(),
                    );
                    flagsMap.insert(
                        TITLE_ID_VALID_STR.to_string(),
                        (self.offlineSyncData.syncFlags & KD_SYNC_SPC_FLAG_TITLEID_VALID != 0)
                            .into(),
                    );
                    flagsMap.insert(
                        SUCCESS_STR.to_string(),
                        (self.offlineSyncData.syncFlags & KD_SYNC_SPC_FLAG_SUCCESS != 0).into(),
                    );
                    flagsMap.insert(
                        OBJ_NOT_FOUND_STR.to_string(),
                        (self.offlineSyncData.syncFlags & KD_SYNC_SPC_FLAG_OBJ_NOT_FOUND != 0)
                            .into(),
                    );
                    flagsMap.insert(
                        OBJ_EXPIRED_STR.to_string(),
                        (self.offlineSyncData.syncFlags & KD_SYNC_SPC_FLAG_OBJ_EXPIRED != 0).into(),
                    );
                    offlineSyncMap.insert(FLAGS_STR.to_string(), flagsMap.into());

                    // Title ID
                    if (self.offlineSyncData.syncFlags & KD_SYNC_SPC_FLAG_TITLEID_VALID) != 0 {
                        let hextTitleId: String =
                            self.offlineSyncData.syncTitleId.encode_hex_upper();
                        offlineSyncMap.insert(TITLE_ID_STR.to_string(), hextTitleId.into());
                    } else {
                        offlineSyncMap.insert(TITLE_ID_STR.to_string(), "".into());
                    }

                    // Records Invalidated
                    offlineSyncMap.insert(
                        RECORDS_INVALIDATED_STR.to_string(),
                        self.offlineSyncData.recordsDeleted.into(),
                    );

                    // Array of Invalidated Stream IDs
                    let mut streamIDs: Vec<String> = Vec::new();
                    if self.offlineSyncData.recordsDeleted > 0
                        && !self.offlineSyncData.deletedStreamIDs.is_empty()
                    {
                        for i in 0..self.offlineSyncData.recordsDeleted {
                            let index = i * FPS_OFFLINE_CONTENTID_LENGTH;
                            let hexContentID = self.offlineSyncData.deletedStreamIDs
                                [index..(index + FPS_OFFLINE_CONTENTID_LENGTH)]
                                .to_vec()
                                .encode_hex_upper();
                            streamIDs.push(hexContentID);
                        }
                    }
                    offlineSyncMap.insert(INVALIDATED_STREAM_IDS_STR.to_string(), streamIDs.into());
                }

                map.serialize_entry(OFFLINE_SYNC_STR, &offlineSyncMap)?;
            }

            if self.operationType == FPSOperationType::createCKC
                && !self.isCheckIn
                && !self.ckc.is_empty()
            {
                //CKC
                map.serialize_entry(CKC_STR, &general_purpose::STANDARD.encode(&self.ckc))?;
            }
        }

        map.end()
    }
}

impl Serialize for FPSResults {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let structLen = 1;
        let mut structSerializer = serializer.serialize_struct(
            extension_constants::FAIRPLAY_STREAMING_RESPONSE_STR,
            structLen,
        )?;

        if !self.resultPtr.is_empty()
            && self.resultPtr.first().unwrap().operationType == FPSOperationType::getClientInfo
        {
            structSerializer.serialize_field(GET_CLIENT_INFO_STR, &self.resultPtr)?;
        } else {
            structSerializer.serialize_field(CREATE_CKC_STR, &self.resultPtr)?;
        }

        structSerializer.end()
    }
}

impl Serialize for FPSResultsWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut structSerializer = serializer.serialize_struct("result-wrapper", 1)?;

        structSerializer.serialize_field(
            extension_constants::FAIRPLAY_STREAMING_RESPONSE_STR,
            &self.results,
        )?;

        structSerializer.end()
    }
}
