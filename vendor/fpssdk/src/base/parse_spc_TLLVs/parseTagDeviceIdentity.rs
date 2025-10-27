//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::{FPS_PRODUCT_HASH_SIZE, FPS_VENDOR_HASH_SIZE};
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSDeviceIdentity, FPSServerTLLV};
use crate::base::Utils::FPSServerUtils::{readBigEndianU32, readBytes};
use crate::validate::Result;

impl Base {
    pub fn parseTagDeviceIdentity(
        tllv: &FPSServerTLLV,
        deviceIdentity: &mut FPSDeviceIdentity,
    ) -> Result<()> {
        // 4B FPDI Version
        deviceIdentity.fpdiVersion = readBigEndianU32(&tllv.value, 0)?;

        // 4B Device Class (value is one of FPSDeviceClass)
        deviceIdentity.deviceClass = readBigEndianU32(&tllv.value, 4)?;

        // 8B Vendor Hash
        deviceIdentity.vendorHash = readBytes(&tllv.value, 8, FPS_VENDOR_HASH_SIZE)?;

        // 8B Product Hash
        deviceIdentity.productHash = readBytes(&tllv.value, 16, FPS_PRODUCT_HASH_SIZE)?;

        // 4B FPS REE/userland Version
        deviceIdentity.fpVersionREE = readBigEndianU32(&tllv.value, 24)?;

        // 4B FPS TEE/kernel Version
        deviceIdentity.fpVersionTEE = readBigEndianU32(&tllv.value, 28)?;

        // 4B OS Version (Apple devices only)
        deviceIdentity.osVersion = readBigEndianU32(&tllv.value, 32)?;

        deviceIdentity.isDeviceIdentitySet = true;

        Ok(())
    }
}
