//
// base_parse_json_helper.rs : Defines additional functions required by the Base class.
//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants;
use crate::base::base_constants::FPSHDCPRequirement;
use crate::base::structures::base_fps_structures::AssetInfo;
use crate::base::structures::base_fps_structures::Base;
use crate::validate::Result;
use crate::Extension;
use serde_jsonrc::Value;

impl Base {
    /// Assigns HDCP requirement based on input integer.
    /// -1 = HDCP not required
    ///  0 = HDCP Type 0
    ///  1 = HDCP Type 1
    pub fn parseHDCPType(hdcpType: i32, assetInfo: &mut AssetInfo) -> Result<()> {
        if hdcpType == -1 {
            assetInfo.hdcpReq = FPSHDCPRequirement::hdcpNotRequired as u64;
        } else if hdcpType == 0 {
            assetInfo.hdcpReq = FPSHDCPRequirement::hdcpType0 as u64;
        } else if hdcpType == 1 {
            assetInfo.hdcpReq = FPSHDCPRequirement::hdcpType1 as u64;
        } else {
            // Unknown value. Check if extension wants to handle it.
            assetInfo.hdcpReq = Extension::parseHDCPTypeCustom(hdcpType)?;
        }
        Ok(())
    }

    /// Parses values from `offline-hls` JSON object.
    pub fn parseOfflineHLS(
        ckcObj: &serde_jsonrc::Map<std::string::String, Value>,
        assetInfo: &mut AssetInfo,
    ) -> Result<()> {
        // content-id aka stream-id - optional
        if ckcObj.contains_key(base_constants::STREAM_ID_STR) {
            if let Some(streamId) = ckcObj.get(base_constants::STREAM_ID_STR).unwrap().as_str() {
                if !streamId.is_empty() {
                    assetInfo.streamId = Some(hex::decode(streamId).unwrap());
                }
            }
        }

        // title-id - optional
        if ckcObj.contains_key(base_constants::TITLE_ID_STR) {
            if let Some(titleId) = ckcObj.get(base_constants::TITLE_ID_STR).unwrap().as_str() {
                if !titleId.is_empty() {
                    assetInfo.titleId = Some(hex::decode(titleId).unwrap());
                }
            }
        }

        // rental-duration - optional
        // Support parsing as either an integer or string
        if ckcObj.contains_key(base_constants::RENTAL_DURATION_STR) {
            if let Some(rentalDuration) = ckcObj.get(base_constants::RENTAL_DURATION_STR).unwrap().as_u64() {
                assetInfo.rentalDuration = rentalDuration as u32;
            } else if let Some(rentalDuration) = ckcObj.get(base_constants::RENTAL_DURATION_STR).unwrap().as_str() {
                assetInfo.rentalDuration = rentalDuration.parse::<u32>().unwrap_or(0);
            }
        }

        // playback-duration - optional
        // Support parsing as either an integer or string
        if ckcObj.contains_key(base_constants::PLAYBACK_DURATION_STR) {
            if let Some(playbackDuration) = ckcObj.get(base_constants::PLAYBACK_DURATION_STR).unwrap().as_u64() {
                assetInfo.playbackDuration = playbackDuration as u32;
            } else if let Some(playbackDuration) = ckcObj.get(base_constants::PLAYBACK_DURATION_STR).unwrap().as_str() {
                assetInfo.playbackDuration = playbackDuration.parse::<u32>().unwrap_or(0);
            }
        }

        Extension::parseOfflineHLSCustom(ckcObj, assetInfo)?;

        Base::verifyOfflineHLS(assetInfo)
    }
}
