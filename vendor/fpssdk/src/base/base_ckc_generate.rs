//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use std::env;

use crate::base::base_constants::AESEncryptionCipher;
use crate::base::base_constants::AESEncryptionMode;

use crate::base::base_constants::AES128_IV_SZ;
use crate::base::structures::base_fps_structures::Base;
use crate::base::structures::base_server_structures::{FPSServerCKCContainer, FPSServerCtx};
use crate::base::Utils::FPSServerUtils::VectorHelperUtils;
use crate::requireAction;
use crate::validate::{FPSStatus, Result};
use crate::Extension;
use openssl::symm::{Cipher, Crypter, Mode};

use super::base_constants;

impl Base {
    ///base version of log init that is externally visible
    pub fn logInit() {
        Extension::logInitCustom(None);
    }

    /// Serializes and encrypts the TLLVs into a CKC container
    pub fn generateCKC(serverCtx: &mut FPSServerCtx) -> Result<()> {
        // Generate the CKC container (AR) IV
        Extension::genRandom(&mut serverCtx.ckcContainer.aesKeyIV, 16);

        // Prepare the CKC container
        Extension::fillCKCContainerCustom(serverCtx)?;

        // Populate CKC TLLVs
        Base::populateCKCTLLVs(serverCtx)?;

        let mut key: Vec<u8> = Vec::with_capacity(16);
        // Derive encryption key from anti replay seed and R1
        Base::deriveAntiReplayKey(
            &serverCtx.spcContainer.spcData.antiReplay,
            &serverCtx.ckcContainer.ckcData.r1,
            &mut key,
        )?;

        // Encrypt the CKC data using the anti replay key
        Base::encryptCKCData(&mut serverCtx.ckcContainer, &key)?;

        // Serialize the CKC container
        Base::serializeCKCContainer(&mut serverCtx.ckcContainer)?;

        Ok(())
    }

    /// Derives anti-replay key used to encrypt the CKC
    pub fn deriveAntiReplayKey(arSeed: &[u8], R1: &Vec<u8>, ek: &mut Vec<u8>) -> Result<()> {
        requireAction!(!arSeed.is_empty(), return Err(FPSStatus::paramErr));
        requireAction!(!R1.is_empty(), return Err(FPSStatus::paramErr));

        // log::debug!("R1: 0x{}", hex::encode(R1));

        let mut sha1 = openssl::sha::Sha1::new();
        sha1.update(R1.as_slice());
        let hashOfR1 = sha1.finish();

        // log::debug!("hashOfR1: 0x{}", hex::encode(hashOfR1));
        // log::debug!("arSeed: 0x{}", hex::encode(arSeed));

        let cipher = Cipher::aes_128_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &hashOfR1[..16], None).unwrap();
        let mut ciphertext = vec![0_u8; arSeed.len() + cipher.block_size()];

        let _encryptionResult = crypter.update(arSeed, &mut ciphertext);

        // Only return the first 16B
        *ek = ciphertext[..16].to_vec();

        // log::debug!("AntiReplay Key: 0x{}", hex::encode(ek));

        Ok(())
    }

    /// Encrypts CKC data
    pub fn encryptCKCData(ckcContainer: &mut FPSServerCKCContainer, key: &[u8]) -> Result<()> {
        let mut tempCKC: Vec<u8> = Vec::new();

        Base::encryptDecryptWithAES(
            ckcContainer.ckcDataPtr.as_slice(),
            key,
            &ckcContainer.aesKeyIV,
            AESEncryptionMode::aesEncrypt,
            AESEncryptionCipher::aesCBC,
            &mut tempCKC,
        )?;

        // Replace original data with the encrypted version
        ckcContainer.ckcDataPtr = tempCKC;

        Ok(())
    }

    /// Serialize CKC container with version, IV, data size, and payload
    pub fn serializeCKCContainer(ckcContainer: &mut FPSServerCKCContainer) -> Result<()> {
        let mut localCKC: Vec<u8> = Vec::new();

        // 4B Version
        localCKC.appendBigEndianU32(ckcContainer.version);

        // 4B Reserved
        let mut reserved: u32 = 0;
        Base::reportServerInformation(&mut reserved)?;
        localCKC.appendBigEndianU32(reserved);

        // 16B IV
        requireAction!(
            ckcContainer.aesKeyIV.len() == AES128_IV_SZ,
            return Err(FPSStatus::paramErr)
        );
        localCKC.extend(&ckcContainer.aesKeyIV);

        // CKC Data size
        localCKC.appendBigEndianU32(ckcContainer.ckcDataPtr.len() as u32);

        // CKC Data
        localCKC.extend(&ckcContainer.ckcDataPtr);

        ckcContainer.ckc = localCKC;

        Ok(())
    }

    pub fn reportServerInformation(reserved: &mut u32) -> Result<()> {
        let mut reserved_bits: u32 = 0;

        // Platform information
        let arch = env::consts::ARCH;

        let platform = match arch {
            "x86_64" => 1,
            "aarch64" => 2,
            _ => 0,
        };

        // Language (Swift = 1, Rust = 2)
        let language: u32 = 2;

        // Project version
        let major: u32 = base_constants::FPS_SDK_MAJOR_VERSION;
        let minor: u32 = base_constants::FPS_SDK_MINOR_VERSION;

        reserved_bits |= major; // 7 bits

        reserved_bits <<= 4;
        reserved_bits |= minor; // 4 bits

        reserved_bits <<= 2;
        reserved_bits |= language; // 2 bits

        reserved_bits <<= 3;
        reserved_bits |= platform; // 3 bits

        *reserved = reserved_bits;
        Ok(())
    }
}
