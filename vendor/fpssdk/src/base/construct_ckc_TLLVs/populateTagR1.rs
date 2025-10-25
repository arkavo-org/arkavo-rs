//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use crate::base::base_constants::FPSTLLVTagValue;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::FPSServerCtx;
use crate::validate::Result;

impl Base {
    pub fn populateTagR1(serverCtx: &mut FPSServerCtx) -> Result<()> {
        Base::serializeTLLV(
            FPSTLLVTagValue::r1Tag as u64,
            &serverCtx.ckcContainer.ckcData.r1.to_owned(),
            &mut serverCtx.ckcContainer,
        )
    }
}
