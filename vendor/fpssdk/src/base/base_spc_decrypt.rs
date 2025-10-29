//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::base::base_constants::{self, AES128_BLOCK_SIZE, AES128_IV_SZ, AES128_KEY_SZ};
use crate::base::base_constants::{AESEncryptionCipher, AESEncryptionMode};
use crate::base::structures::base_fps_structures::Base;
use crate::requireAction;
use crate::validate::{FPSStatus, Result};
use openssl::symm::{Cipher, Crypter, Mode};

impl Base {
    /// Encrypt or decrypt input using AES
    ///
    /// Supports both ECB and CBC modes.
    pub fn encryptDecryptWithAES(
        input: &[u8],
        key: &[u8],
        iv: &[u8],
        opMode: base_constants::AESEncryptionMode,
        opCipher: base_constants::AESEncryptionCipher,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        let cipher;

        let mode = match opMode {
            AESEncryptionMode::aesEncrypt => Mode::Encrypt,
            AESEncryptionMode::aesDecrypt => Mode::Decrypt
        };

        match opCipher {
            AESEncryptionCipher::aesCBC => {
                cipher = Cipher::aes_128_cbc();

                requireAction!(!input.is_empty(), return Err(FPSStatus::paramErr));
                requireAction!(input.len() % AES128_BLOCK_SIZE == 0, return Err(FPSStatus::paramErr));
                requireAction!(key.len() == AES128_KEY_SZ, return Err(FPSStatus::paramErr));
                requireAction!(iv.len() == AES128_IV_SZ, return Err(FPSStatus::paramErr));
            }
            AESEncryptionCipher::aesECB => {
                cipher = Cipher::aes_128_ecb();

                requireAction!(input.len() == AES128_BLOCK_SIZE, return Err(FPSStatus::paramErr));
                requireAction!(key.len() == AES128_KEY_SZ, return Err(FPSStatus::paramErr));
                // IV can be empty
            }
        }

        // Using Crypter instead of decrypt/encrypt because openssl uses PKCS#7 padding by default,
        // and our input doesn't contain PKCS#7 padding, so we have to set padding to false.
        let mut crypter = Crypter::new(cipher, mode, key, Some(iv)).unwrap();
        crypter.pad(false);

        // OpenSSL function requires the output buffer to have at least one block size extra space
        output.resize(input.len() + cipher.block_size(), 0);

        let resultingSize = crypter.update(input, output).unwrap();

        output.truncate(resultingSize);

        Ok(())
    }
}
