//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::FPSServerTLLV;
use crate::base::Utils::FPSServerUtils::{readBigEndianU32, readBigEndianU64};
use crate::validate::FPSStatus;
use crate::validate::Result;
use crate::{fpsLogError, returnErrorStatus};

impl Base {
    pub fn parseTagSecurityLevelReport(
        tllv: &FPSServerTLLV,
        supportedSecurityLevel: &mut Option<u64>,
        clientKextDenyListVersion: &mut u32,
    ) -> Result<()> {
        if tllv.value.len() == base_constants::FPS_ENCRYPTED_SECURITY_LEVEL_REPORT_TLLV_SIZE {
            return Ok(()); // This is encrypted security level TLLV. Just ignore it for now
        }

        // 4B Version
        let tllvVersion = readBigEndianU32(&tllv.value, 0)?;

        // Ignore the TLLV when version is not set to 1
        if tllvVersion == 1 {
            // 4B Reserved
            let reserved = readBigEndianU32(&tllv.value, 4)?;

            if reserved != 0 {
                fpsLogError!(
                    FPSStatus::paramErr,
                    "Invalid reserved field in Security Level Report TLLV"
                );
                returnErrorStatus!(FPSStatus::paramErr);
            }

            // 8B Security Level
            let sl = readBigEndianU64(&tllv.value, 8)?;
            log::debug!("Client Security Level: 0x{:x}", sl);
            *supportedSecurityLevel = Some(sl);

            // 4B Kext Deny List Version
            // Do not overwrite if KDL verison was delivered in it's own TLLV
            if *clientKextDenyListVersion == 0 {
                *clientKextDenyListVersion = readBigEndianU32(&tllv.value, 16)?;
            }
        }

        Ok(())
    }
}
