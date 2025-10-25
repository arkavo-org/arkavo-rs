//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use std::mem::size_of;

use crate::base::base_constants::FPS_TLLV_TAG_SZ;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerSPCContainer, FPSServerSPCData, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::readBigEndianU64;
use crate::validate::{FPSStatus, Result};
use crate::{fpsLogError, requireAction, returnErrorStatus};

impl Base {
    pub fn parseTagReturnRequest(tllv: &FPSServerTLLV, spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        // Check that size is a multiple of the tag field size
        requireAction!(
            (tllv.value.len() % FPS_TLLV_TAG_SZ == 0),
            return Err(FPSStatus::parserErr)
        );

        spcContainer.spcData.returnRequest.value = tllv.value.clone();

        Ok(())
    }

    pub fn extractReturnTags(spcData: &mut FPSServerSPCData) -> Result<()> {
        let mut offset: usize = 0;

        let returnRequest = &spcData.returnRequest;

        requireAction!(
            !spcData.spcDataParser.TLLVs.is_empty(),
            return Err(FPSStatus::parserErr)
        );

        // Iterate on list of TLLVs and extract the tags to be returned based on the returnRequest TLLV
        while offset < returnRequest.value.len() {
            let mut tagAdded: bool = false;

            // Read the requested tag value
            let tag = readBigEndianU64(&returnRequest.value, offset)?;
            offset += size_of::<u64>();

            // Check if tag was already added
            for tllv in &spcData.returnTLLVs {
                if tag == tllv.tag {
                    tagAdded = true;
                    break;
                }
            }

            if tagAdded {
                // Don't add tag twice
                continue;
            }

            // Find tag in the list of incoming TLLVs from the SPC
            for tllv in &spcData.spcDataParser.TLLVs {
                if tag == tllv.tag {
                    spcData.returnTLLVs.push(tllv.clone());
                    tagAdded = true;
                    break;
                }
            }

            // A tag from the SPC data that is to be returned in the CKC was not found in the SPC!
            if !tagAdded {
                fpsLogError!(
                    FPSStatus::missingRequiredTagErr,
                    "Return tag missing from SPC 0x{:x}",
                    tag
                );
                returnErrorStatus!(FPSStatus::missingRequiredTagErr);
            }
        }

        Ok(())
    }
}
