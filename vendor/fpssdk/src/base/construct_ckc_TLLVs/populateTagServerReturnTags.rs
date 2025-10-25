//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerCtx, FPSServerSPCData};
use crate::validate::Result;

impl Base {
    pub fn populateTagServerReturnTags(serverCtx: &mut FPSServerCtx) -> Result<()> {
        let spcData: &FPSServerSPCData = &serverCtx.spcContainer.spcData;

        // Loop through the return tags and serialize them
        for tllv in &spcData.returnTLLVs {
            // Return the TLLV data as sent by the client
            Base::serializeTLLV(tllv.tag, &tllv.value, &mut serverCtx.ckcContainer)?;
        }

        Ok(())
    }
}
