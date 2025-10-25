//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::AES128_BLOCK_SIZE;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerCKCContainer, FPSServerCtx};
use crate::base::Utils::FPSServerUtils::VectorHelperUtils;
use crate::validate::Result;
use crate::Extension;

impl Base {
    /// Populates TLLVs in the CKC.
    pub fn populateCKCTLLVs(serverCtx: &mut FPSServerCtx) -> Result<()> {
        // Populate common TLLVs
        Base::populateTagCK(serverCtx.ckcContainer.ckcData.ckcAssetInfo.contentKeyTLLVTag, serverCtx)?;
        Base::populateTagR1(serverCtx)?;
        Base::populateTagServerReturnTags(serverCtx)?;
        Base::populateTagSessionKeyVersionUsed(serverCtx)?;
        Base::populateTagServerHDCPInformation(serverCtx)?;

        // Populate TLLVs that have custom implementation
        Extension::populateTagSecurityLevelCustom(serverCtx)?;
        Extension::populateTagsCustom(serverCtx)?;

        Ok(())
    }

    /// Serializes a single TLLV (tag, total length, value length, and value)
    /// onto `ckcContainer.ckcDataPtr`.
    ///
    /// Adds random bytes of padding to the end, so that total length is a
    /// multiple of `AES128_BLOCK_SIZE`.
    pub fn serializeTLLV(tag: u64, value: &Vec<u8>, ckcContainer: &mut FPSServerCKCContainer) -> Result<()> {
        let valueSize = value.len();

        // Determine minimum padding size to complete a block
        let mut paddingSize = 0;

        if valueSize % AES128_BLOCK_SIZE != 0 {
            paddingSize += AES128_BLOCK_SIZE - (valueSize % AES128_BLOCK_SIZE);
        }

        // Add 0 to 3 random extra blocks of padding
        let mut extraPaddingBlocks: [u8; 1] = [0];
        Extension::genRandom(&mut extraPaddingBlocks, 1);
        paddingSize += AES128_BLOCK_SIZE * (extraPaddingBlocks[0] % 4) as usize;

        // Create random padding array
        let mut padding: Vec<u8> = vec![0; paddingSize];
        Extension::genRandom(&mut padding, paddingSize);

        // Debug prints
        log::debug!("Adding TLLV Tag -- 0x{:x}", tag);
        log::debug!("    Block Length: 0x{:x}", valueSize + paddingSize);
        log::debug!("    Value Length: 0x{:x}", valueSize);
        log::debug!("    Value: 0x{}", hex::encode(value));

        // Write TLLV Tag
        ckcContainer.ckcDataPtr.appendBigEndianU64(tag);

        // Write Total Length and Value Length
        ckcContainer
            .ckcDataPtr
            .appendBigEndianU32((valueSize + paddingSize) as u32);
        ckcContainer.ckcDataPtr.appendBigEndianU32(valueSize as u32);

        // Write Value
        if valueSize > 0 {
            ckcContainer.ckcDataPtr.extend(value);
        }

        // Write Padding
        if paddingSize > 0 {
            ckcContainer.ckcDataPtr.append(&mut padding);
        }

        Ok(())
    }
}
