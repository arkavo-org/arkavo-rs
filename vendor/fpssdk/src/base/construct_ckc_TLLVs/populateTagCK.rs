//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::FPSServerCtx;
use crate::validate::Result;

impl Base {
    pub fn populateTagCK(tag: u64, serverCtx: &mut FPSServerCtx) -> Result<()> {
        Base::serializeTLLV(
            tag,
            &serverCtx.ckcContainer.ckcData.ckcAssetInfo.contentKeyTLLVPayload.to_owned(),
            &mut serverCtx.ckcContainer,
        )
    }
}
