//
// Copyright © 2025 Apple Inc. All rights reserved.
//

use crate::base::structures::base_server_structures::{
    FPSServerSPCContainer, FPSServerTLLV, VMDeviceInfo,
};
use crate::base::Utils::FPSServerUtils::readBigEndianU32;
use crate::validate::Result;
use crate::Base;

impl Base {
    pub fn parseTagVMDeviceInformation(
        tllv: &FPSServerTLLV,
        spcContainer: &mut FPSServerSPCContainer,
    ) -> Result<()> {
        let mut offset = 0;
        let tllvVersion = readBigEndianU32(&tllv.value, offset)?;
        offset += 4;

        if tllvVersion == 1 {
            let mut vmDeviceInfo: VMDeviceInfo = VMDeviceInfo::default();

            // 4B Host Device Class
            vmDeviceInfo.hostDeviceClass = readBigEndianU32(&tllv.value, offset)?.into();
            offset += 4;

            // 4B Host OS Version
            vmDeviceInfo.hostOSVersion = readBigEndianU32(&tllv.value, offset)?;
            offset += 4;

            // 4B Host VM Protocol Version
            vmDeviceInfo.hostVMProtocolVersion = readBigEndianU32(&tllv.value, offset)?;
            offset += 4;

            // 4B Guest Device Class
            vmDeviceInfo.guestDeviceClass = readBigEndianU32(&tllv.value, offset)?.into();
            offset += 4;

            // 4B Guest OS Version
            vmDeviceInfo.guestOSVersion = readBigEndianU32(&tllv.value, offset)?;
            offset += 4;

            // 4B Guest VM Protocol Version
            vmDeviceInfo.guestVMProtocolVersion = readBigEndianU32(&tllv.value, offset)?;

            spcContainer.spcData.vmDeviceInfo = Some(vmDeviceInfo);
        } else {
            spcContainer.spcData.vmDeviceInfo = None;
        }

        Ok(())
    }
}
