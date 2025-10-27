//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::requireAction;
use crate::validate::{FPSStatus, Result};
use crate::Extension;
use byteorder::{BigEndian, ByteOrder};
use std::mem::size_of;

/// Read bytess from input with given offset and length.
///
/// Returns error if offset + length overflows.
/// Returns error if input is not large enough.
pub fn readBytes(input: &[u8], offset: usize, numberOfBytesToRead: usize) -> Result<Vec<u8>> {
    // Check for integer overflow
    requireAction!(
        offset <= (offset + numberOfBytesToRead),
        return Err(FPSStatus::paramErr)
    );

    // Check that input is large enough
    requireAction!(
        (offset + numberOfBytesToRead) <= input.len(),
        return Err(FPSStatus::paramErr)
    );

    let output = Vec::from_iter(
        input[offset..(offset + numberOfBytesToRead)]
            .iter()
            .cloned(),
    );

    Ok(output)
}

// Using these functions instead of BigEndian::read_uXX directly so that we
// check the input buffer contains enough space to perform the read.

/// Reads 8-byte value from input. Returns error if input is not large enough.
pub fn readU8(input: &[u8], offset: usize) -> Result<u8> {
    requireAction!(
        input.len() >= offset + size_of::<u8>(),
        return Err(FPSStatus::paramErr)
    );

    let output = input[offset];

    Ok(output)
}

/// Reads 16-byte big-endian value from input. Returns error if input is not large enough.
pub fn readBigEndianU16(input: &[u8], offset: usize) -> Result<u16> {
    requireAction!(
        input.len() >= offset + size_of::<u16>(),
        return Err(FPSStatus::paramErr)
    );

    let output = BigEndian::read_u16(&input[offset..(offset + size_of::<u16>())]);

    Ok(output)
}

/// Reads 32-byte big-endian value from input. Returns error if input is not large enough.
pub fn readBigEndianU32(input: &[u8], offset: usize) -> Result<u32> {
    requireAction!(
        input.len() >= offset + size_of::<u32>(),
        return Err(FPSStatus::paramErr)
    );

    let output = BigEndian::read_u32(&input[offset..(offset + size_of::<u32>())]);

    Ok(output)
}

/// Reads 64-byte big-endian value from input. Returns error if input is not large enough.
pub fn readBigEndianU64(input: &[u8], offset: usize) -> Result<u64> {
    requireAction!(
        input.len() >= offset + size_of::<u64>(),
        return Err(FPSStatus::paramErr)
    );

    let output = BigEndian::read_u64(&input[offset..(offset + size_of::<u64>())]);

    Ok(output)
}

pub trait VectorHelperUtils {
    /// Appends buffer with a u32 in big endian
    fn appendBigEndianU32(&mut self, value: u32);

    /// Appends buffer with a u64 in big endian
    fn appendBigEndianU64(&mut self, value: u64);

    /// Appends buffer with random bytes
    fn appendRandomBytes(&mut self, length: usize);
}

impl VectorHelperUtils for Vec<u8> {
    /// Appends buffer with a u32 in big endian
    fn appendBigEndianU32(&mut self, value: u32) {
        self.extend(value.to_be_bytes())

        // Alternative option:
        // let mut tempVec: Vec<u8> = vec![0; size_of::<u32>()];:
        // BigEndian::write_u32(&mut tempVec, value);:
        // self.append(&mut tempVec);
    }

    /// Appends buffer with a u64 in big endian
    fn appendBigEndianU64(&mut self, value: u64) {
        self.extend(value.to_be_bytes())

        // Alternative option:
        // let mut tempVec: Vec<u8> = vec![0; size_of::<u64>()];
        // BigEndian::write_u64(&mut tempVec, value);
        // self.append(&mut tempVec);
    }

    /// Appends buffer with random bytes
    fn appendRandomBytes(&mut self, length: usize) {
        let mut tempVec: Vec<u8> = vec![0; length];

        Extension::genRandom(&mut tempVec, length);

        self.append(&mut tempVec);
    }
}
