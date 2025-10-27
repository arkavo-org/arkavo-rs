//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use std::mem::size_of;

use aes::Aes128;
use cipher::KeyInit;
use cmac::{Cmac, Mac};

use crate::base::base_constants;
use crate::base::base_constants::{AESEncryptionCipher, AESEncryptionMode, SPCVersion};
use crate::base::base_constants::{
    FPS_TLLV_TAG_SZ, FPS_TLLV_TOTAL_LENGTH_SZ, FPS_TLLV_VALUE_LENGTH_SZ,
};
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_fps_structures::FPSOperation;
use crate::base::structures::base_server_structures::{
    FPSServerCtx, FPSServerSPCContainer, FPSServerTLLV,
};
use crate::base::Utils::FPSServerUtils::{readBigEndianU32, readBigEndianU64, readBytes};
use crate::requireAction;
use crate::validate::{FPSStatus, Result};
use crate::Extension;

impl Base {
    /// Parses, decrypts, and validates received SPC.
    pub fn parseSPC(fpsOperation: &FPSOperation, serverCtx: &mut FPSServerCtx) -> Result<()> {
        // Parse SPC container
        Base::parseSPCContainer(&fpsOperation.spc, &mut serverCtx.spcContainer)?;

        // Decrypt SPC Data
        Base::decryptSPCData(&fpsOperation.spc, &mut serverCtx.spcContainer)?;

        // Parse SPC data
        Base::parseSPCData(&mut serverCtx.spcContainer)?;

        // Create set of flags of client supported features (lease, rental, persistence, etc)
        Base::checkSupportedFeatures(serverCtx)
    }

    /// Parses fields in SPC other than the encrypted payload
    pub fn parseSPCContainer(spc: &[u8], spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        let mut offset = 0;

        // 4B Version
        spcContainer.version = readBigEndianU32(spc, offset)?;
        offset += size_of::<u32>();

        // 4B Reserved
        spcContainer.reservedValue = readBigEndianU32(spc, offset)?;
        offset += size_of::<u32>();

        if spcContainer.version == SPCVersion::v3 as u32 {
            Base::parseSPCV3Header(spc, &mut offset, spcContainer)?;
        } else {
            requireAction!(
                (spcContainer.version == SPCVersion::v1 as u32)
                    || (spcContainer.version == SPCVersion::v2 as u32),
                return Err(FPSStatus::spcVersionErr)
            );

            // 16B SPC Data IV
            spcContainer.aesKeyIV = readBytes(spc, offset, base_constants::AES128_IV_SZ)?;
            offset += base_constants::AES128_IV_SZ;

            // AES Wrapped Key (size depends on version)
            if spcContainer.version == SPCVersion::v2 as u32 {
                spcContainer.aesWrappedKeySize = base_constants::FPS_V2_WRAPPED_KEY_SZ;
            } else {
                spcContainer.aesWrappedKeySize = base_constants::FPS_V1_WRAPPED_KEY_SZ;
            }

            spcContainer.aesWrappedKey = readBytes(spc, offset, spcContainer.aesWrappedKeySize)?;
            offset += spcContainer.aesWrappedKeySize;

            // 20B Certificate Hash
            // This is where we should check the certificateHash and fail if it is not what is expected.
            // Also, this is where the private RSA key would be selected if more than one was provisioned.
            spcContainer.certificateHash = readBytes(spc, offset, base_constants::FPS_V1_HASH_SZ)?;
            offset += base_constants::FPS_V1_HASH_SZ;

            // 4B SPC Size
            spcContainer.spcDataSize = readBigEndianU32(spc, offset)? as usize;
            offset += size_of::<u32>();

            spcContainer.spcDataOffset = offset;

            requireAction!(
                (spcContainer.spcDataSize + spcContainer.spcDataOffset)
                    >= spcContainer.spcDataOffset,
                return Err(FPSStatus::paramErr)
            );
            requireAction!(
                ((spcContainer.spcDataSize + spcContainer.spcDataOffset) <= spc.len()),
                return Err(FPSStatus::paramErr)
            );
        }

        Ok(())
    }

    // Parse SPC v3 Header
    pub fn parseSPCV3Header(
        spc: &[u8],
        offset: &mut usize,
        spcContainer: &mut FPSServerSPCContainer,
    ) -> Result<()> {
        let mut localOffset: usize = *offset;
        /* SPC v3 Format:
         * header: 8 bytes (version on 4 bytes + reserved on 4 bytes) : this is already parsed at this point
         * transport version UUID: 16 bytes
         * symmetric master key encrypted using certificate public key: 256 bytes
         * public key UUID aka certificate hash: 32 bytes
         * encrypted TLLV’s length: 16 bytes
         * encrypted TLLV’s: variable multiple of 16 bytes
         * transport level integrity tag: 16 bytes
         */

        // protocol version UUID
        spcContainer.protocolVersionUUID =
            readBytes(spc, localOffset, base_constants::AES128_IV_SZ)?;
        localOffset += base_constants::AES128_IV_SZ;

        if spcContainer.protocolVersionUUID != base_constants::V3_PROTOCOL_VERSION_UUID {
            log::debug!(
                "Invalid protocol version UUID {:?}",
                spcContainer.protocolVersionUUID
            );
            return Err(FPSStatus::versionErr);
        }

        // encrypted master key
        spcContainer.aesWrappedKeySize = base_constants::FPS_V2_WRAPPED_KEY_SZ;

        spcContainer.aesWrappedKey = readBytes(spc, localOffset, spcContainer.aesWrappedKeySize)?;
        localOffset += spcContainer.aesWrappedKeySize;

        // certificate hash
        // read sha256 digest
        spcContainer.certificateHash256 =
            readBytes(spc, localOffset, base_constants::FPS_V3_HASH_SZ)?;
        localOffset += base_constants::FPS_V3_HASH_SZ;

        // For simplicity, lets find matching sha1 hash for known set of sha256 cert hashes.
        // We build a full table at init time (using provided cert): | sha1 | sha256 | private key to use |
        // For libfpscrypto functions, sha1 must be used to find the corresponding provisioning data
        // For SPC v1/v2, sha1 should be used to find corresponding private key
        // For SPC v3, sha256 should be used to find corresponding private key
        Base::matchSha1withSha256(spcContainer)?;

        // Move local offset by 12 to adjust for padding
        localOffset += 12;

        // encrypted TLLVs length
        spcContainer.spcDataSize = readBigEndianU32(spc, localOffset)? as usize;
        localOffset += 4;

        spcContainer.spcDataOffset = localOffset;
        *offset = localOffset;

        requireAction!(
            (spcContainer.spcDataSize + spcContainer.spcDataOffset) >= spcContainer.spcDataOffset,
            return Err(FPSStatus::paramErr)
        );
        requireAction!(
            ((spcContainer.spcDataSize + spcContainer.spcDataOffset) <= spc.len()),
            return Err(FPSStatus::paramErr)
        );

        Ok(())
    }

    pub fn getEncryptionKeyAndIV(
        spcContainer: &mut FPSServerSPCContainer,
        masterKey: &Vec<u8>,
        encryptionKey: &mut Vec<u8>,
    ) -> Result<()> {
        // Compute Encryption IV
        Base::encryptDecryptWithAES(
            base_constants::V3_PROTOCOL_ENCRYPTION_IV_SEED,
            &masterKey,
            &[],
            AESEncryptionMode::aesEncrypt,
            AESEncryptionCipher::aesECB,
            &mut spcContainer.aesKeyIV,
        )?;

        // Compute Encryption Key
        Base::encryptDecryptWithAES(
            base_constants::V3_PROTOCOL_ENCRYPTION_KEY_SEED,
            &masterKey,
            &[],
            AESEncryptionMode::aesEncrypt,
            AESEncryptionCipher::aesECB,
            encryptionKey,
        )
    }

    pub fn verifySPCIntegrity(
        spcContainer: &mut FPSServerSPCContainer,
        spc: &[u8],
        masterKey: &Vec<u8>,
    ) -> Result<()> {
        // Verify Integrity
        let mut localIntegrityKey: Vec<u8> = Vec::new();

        Base::encryptDecryptWithAES(
            base_constants::V3_PROTOCOL_INTEGRITY_KEY_SEED,
            &masterKey,
            &[],
            AESEncryptionMode::aesEncrypt,
            AESEncryptionCipher::aesECB,
            &mut localIntegrityKey,
        )?;

        // Integrity tag is computed over the concatenated RSA encrypted AES key, Certificate Hash, length of TLLVs and the encrypted TLLV's,
        // with the integrity key as the key and using CMAC mode

        let mut integrityBuffer: Vec<u8> = Vec::new();

        // AES Key
        integrityBuffer.extend(spcContainer.aesWrappedKey.clone());

        // Certificate Hash
        integrityBuffer.extend(spcContainer.certificateHash256.clone());

        // TTLV Length
        // Add padding to make it 16 bytes
        integrityBuffer.extend(vec![0; 8]);
        integrityBuffer.extend(&spcContainer.spcDataSize.to_be_bytes());

        // Encrypted TLLVs
        let spcBuffer = spc
            [spcContainer.spcDataOffset..(spcContainer.spcDataOffset + spcContainer.spcDataSize)]
            .to_vec();
        integrityBuffer.extend(spcBuffer);

        // Parse tag from SPC to compare
        let integrityTagOffset = spcContainer.spcDataOffset + spcContainer.spcDataSize;
        let integrityTag_parsed =
            readBytes(spc, integrityTagOffset, base_constants::AES128_KEY_SZ)?;

        // Verify CMAC
        let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(&localIntegrityKey).unwrap();
        Mac::update(&mut mac, &integrityBuffer);
        let integrity_parsed_tag: &cipher::generic_array::GenericArray<u8, cipher::typenum::U16> =
            cipher::generic_array::GenericArray::from_slice(&integrityTag_parsed);

        if let Err(_) = mac.verify(&integrity_parsed_tag) {
            log::debug!("Integrity verification failed for SPC");
            return Err(FPSStatus::integrityErr);
        }

        Ok(())
    }

    /// Decrypts the encrypted SPC payload
    ///
    /// Using the provisioned RSA private key, decrypt the RSA public encrypted AES key.
    /// This AES key is the one used to encrypt the SPC data (aka SPCK, Fig 2-2 of specification).
    pub fn decryptSPCData(spc: &[u8], spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        requireAction!(!spc.is_empty(), return Err(FPSStatus::paramErr));

        let mut localKey: Vec<u8> = Vec::new();

        // Decrypt the encrypted AES key using the RSA private key
        Extension::decryptKeyRSACustom(spcContainer, &mut localKey)?;
        localKey.truncate(base_constants::AES128_KEY_SZ);

        if spcContainer.version == SPCVersion::v3 as u32 {
            let masterKey: Vec<u8> = localKey.clone();
            Base::getEncryptionKeyAndIV(spcContainer, &masterKey, &mut localKey)?;
            Base::verifySPCIntegrity(spcContainer, spc, &masterKey)?;
        }

        // Decrypt the encrypted SPC payload using the decrypted AES key
        Base::encryptDecryptWithAES(
            &spc[spcContainer.spcDataOffset..],
            &localKey,
            &spcContainer.aesKeyIV,
            AESEncryptionMode::aesDecrypt,
            AESEncryptionCipher::aesCBC,
            &mut spcContainer.spcDecryptedData,
        )?;

        // Custom handling (if needed)
        Extension::decryptSPCDataCustom(spc, spcContainer)
    }

    /// Parses all TLLVs inside the SPC data.
    pub fn parseSPCData(spcContainer: &mut FPSServerSPCContainer) -> Result<()> {
        spcContainer.spcData.spcDataParser.TLLVs = Default::default();

        // Initialization of playInfo
        spcContainer.spcData.spcAssetInfo.playInfo.date = 0;
        spcContainer.spcData.spcAssetInfo.playInfo.playbackState = 0;
        spcContainer.spcData.spcAssetInfo.playInfo.playbackId = 0;

        // Parse each TLLV
        while spcContainer.spcData.spcDataParser.currentOffset < spcContainer.spcDataSize {
            let mut tllv: FPSServerTLLV = Default::default();

            // Read in the next TLLV (this moves the parser to the next TLLV on success)
            Base::readNextTLLV(
                &spcContainer.spcDecryptedData,
                spcContainer.spcDataSize,
                &mut spcContainer.spcData.spcDataParser.currentOffset,
                &mut tllv,
            )?;

            if let Err(e) = Base::parseTLLV(&tllv, spcContainer) {
                log::debug!("Error {} while parsing TLLV tag 0x{:x}", e, tllv.tag);
                return Err(e);
            }

            // Save the TLLV for later because we may need to return it.
            spcContainer.spcData.spcDataParser.TLLVs.push(tllv);
        }

        // Now that we have all the TLLVs, extract the ones specified by the return request tag
        Base::extractReturnTags(&mut spcContainer.spcData)?;

        // Make sure we received all required TLLVs
        Base::validateTLLVs(spcContainer)
    }

    /// Reads the next TLLV from the SPC into `tllv`.
    pub fn readNextTLLV(
        dataToParse: &[u8],
        dataToParseSize: usize,
        currentOffset: &mut usize,
        tllv: &mut FPSServerTLLV,
    ) -> Result<()> {
        requireAction!(!dataToParse.is_empty(), return Err(FPSStatus::paramErr));
        requireAction!(
            dataToParseSize
                >= (FPS_TLLV_TAG_SZ + FPS_TLLV_TOTAL_LENGTH_SZ + FPS_TLLV_VALUE_LENGTH_SZ),
            return Err(FPSStatus::paramErr)
        );

        // 8B Tag value
        let tag = readBigEndianU64(dataToParse, *currentOffset)?;
        *currentOffset += size_of::<u64>();

        // 4B Total Size (value length + padding length)
        let totalSize = readBigEndianU32(dataToParse, *currentOffset)? as usize;
        *currentOffset += size_of::<u32>();

        // Verify total size
        requireAction!(
            (*currentOffset + totalSize + FPS_TLLV_VALUE_LENGTH_SZ) >= *currentOffset,
            return Err(FPSStatus::paramErr)
        );
        requireAction!(
            (*currentOffset + totalSize + FPS_TLLV_VALUE_LENGTH_SZ) <= dataToParseSize,
            return Err(FPSStatus::paramErr)
        );

        // Read the size of the value (L2)
        let valueSize = readBigEndianU32(dataToParse, *currentOffset)? as usize;
        *currentOffset += size_of::<u32>();

        // Verify value size
        requireAction!(valueSize <= totalSize, return Err(FPSStatus::paramErr));
        requireAction!(
            (*currentOffset + valueSize) >= *currentOffset,
            return Err(FPSStatus::paramErr)
        );
        requireAction!(
            (*currentOffset + valueSize) <= dataToParseSize,
            return Err(FPSStatus::paramErr)
        );

        tllv.tag = tag;

        // Copy the value into the returned tllv
        tllv.value = dataToParse[*currentOffset..(*currentOffset + valueSize)].to_vec();

        // Set the offset to the next TLLV
        *currentOffset += totalSize;

        Ok(())
    }

    /// Sets `serverCtx.spcContainer.spcData.clientFeatures` flags based on SPC data
    ///
    /// This is done after parsing of the Capabilities TLLV so that any custom
    /// handling knows what the client capabilities are.
    pub fn checkSupportedFeatures(serverCtx: &mut FPSServerCtx) -> Result<()> {
        // Defaults
        serverCtx
            .spcContainer
            .spcData
            .clientFeatures
            .supportsOfflineKeyTLLV = false;
        serverCtx
            .spcContainer
            .spcData
            .clientFeatures
            .supportsOfflineKeyTLLVV2 = false;
        serverCtx
            .spcContainer
            .spcData
            .clientFeatures
            .supportsSecurityLevelBaseline = false;
        serverCtx
            .spcContainer
            .spcData
            .clientFeatures
            .supportsSecurityLevelMain = false;
        serverCtx
            .spcContainer
            .spcData
            .clientFeatures
            .supportsHDCPTypeOne = false;
        serverCtx
            .spcContainer
            .spcData
            .clientFeatures
            .supportsDualExpiry = false;
        serverCtx
            .spcContainer
            .spcData
            .clientFeatures
            .supportsCheckIn = false;

        // In case we did not receive client capabilities, fill with zeros
        serverCtx
            .spcContainer
            .spcData
            .clientCapabilities
            .resize(base_constants::FPS_CAPABILITIES_FLAGS_LENGTH, 0);

        let capabilitiesLVbits =
            readBigEndianU64(&serverCtx.spcContainer.spcData.clientCapabilities, 8)?;

        if (capabilitiesLVbits & base_constants::FPS_CAPABILITY_OFFLINE_KEY_V2_SUPPORTED) != 0 {
            serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsOfflineKeyTLLVV2 = true;
            serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsOfflineKeyTLLV = true;
        }
        if (capabilitiesLVbits & base_constants::FPS_CAPABILITY_SECURITY_LEVEL_BASELINE_SUPPORTED)
            != 0
        {
            serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsSecurityLevelBaseline = true;
        }
        if (capabilitiesLVbits & base_constants::FPS_CAPABILITY_SECURITY_LEVEL_MAIN_SUPPORTED) != 0
        {
            serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsSecurityLevelMain = true;
        }
        if (capabilitiesLVbits & base_constants::FPS_CAPABILITY_HDCP_TYPE1_ENFORCEMENT_SUPPORTED)
            != 0
        {
            serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsHDCPTypeOne = true;
        }
        if (capabilitiesLVbits & base_constants::FPS_CAPABILITY_OFFLINE_KEY_SUPPORTED) != 0 {
            serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsDualExpiry = true;
        }
        if (capabilitiesLVbits & base_constants::FPS_CAPABILITY_CHECK_IN_SUPPORTED) != 0 {
            serverCtx
                .spcContainer
                .spcData
                .clientFeatures
                .supportsCheckIn = true;
        }

        // Custom handling (if needed)
        Extension::checkSupportedFeaturesCustom(serverCtx)
    }
}
