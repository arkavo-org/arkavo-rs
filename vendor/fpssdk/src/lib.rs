//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//
#![allow(nonstandard_style, unused_variables, unused_assignments, dead_code, unused_mut, unreachable_code, const_item_mutation, deprecated, clippy::all)]

use std::env;
use crate::base::structures::base_fps_structures::Base;
use crate::base::base_constants;
use crate::extension::extension_constants;
use crate::validate::{FPSStatus, FPSStatus::noErr};
use std::ffi::{c_char, CStr, CString};
use std::sync::Once;
pub mod base;
pub mod logging;
pub mod extension;

use crate::extension::structures::extension_structures::SDKExtension;
use crate::extension::structures::extension_structures;
use crate::extension::extension as Extension; // Using uppercase to avoid conflict with folder name
use crate::extension::validate as validate;

static INIT: Once = Once::new();

/// Processes the operations specified in the input json.
///
/// The returned json must be disposed of with `fpsDisposeResponse`.
///
/// FPSStatus fpsProcessOperations(const char *in_json, Int in_json_size, char **out_json, Int *out_json_size)
#[no_mangle]
pub extern "C" fn fpsProcessOperations(
    in_json: *const c_char,
    _in_json_size: usize,
    out_json: *mut *mut c_char,
    out_json_size: &mut usize,
) -> FPSStatus {
    requireAction!(!in_json.is_null(), return FPSStatus::paramErr);
    requireAction!(!out_json.is_null(), return FPSStatus::paramErr);

    INIT.call_once(|| {
        Base::logInit();
        if let Err(e) = Base::readCertificates() {
            fpsLogError!(e, "readCertificates call failed");
        }
    });

    // Need to return a usize because you cannot set out_json_size within the closure and still have
    // it be able to catch the unwind
    let result = std::panic::catch_unwind(|| -> usize {

        let s = unsafe { CStr::from_ptr(in_json).to_string_lossy().into_owned() };
        let s = s.as_str();

        let root = Base::parseRootFromString(s);

        let output = Base::processOperations(root);

        let out_string = serde_jsonrc::to_string(&output).unwrap();

        unsafe {
            *out_json = CString::new(out_string.as_str()).unwrap().into_raw();
        }

        let out_json_size = out_string.len() + 1; // +1 because CString::new adds a null terminator

        out_json_size
    });

    if result.is_err() {
        // Manually create and return a fixed json indicating failure.
        let json_fail = serde_jsonrc::json!({ extension_constants::FAIRPLAY_STREAMING_RESPONSE_STR: { base_constants::CREATE_CKC_STR :[{base_constants::ID_STR :1,base_constants::STATUS_STR:FPSStatus::internalErr as i32}]}});
        let json_fail_str = json_fail.to_string();
        unsafe {
            *out_json = CString::new(json_fail_str.as_str()).unwrap().into_raw();
        }
        *out_json_size = json_fail_str.len();
        let s = unsafe {
            CStr::from_ptr(in_json).to_string_lossy().into_owned()
        };
        let s = s.as_str();
        fpsLogError!(FPSStatus::internalErr, "fpssdk panic: {:?}, panic input: {}", result.unwrap_err(), s);
        FPSStatus::internalErr
    } else {
        let size = result.unwrap();
        *out_json_size = size;
        FPSStatus::noErr
    }
}

/// Disposes of the output json created by a call to `fpsProcessOperations`.
///
/// FPSStatus fpsDisposeResponse(char *out_pay_load, int out_pay_load_sz)
#[no_mangle]
pub extern "C" fn fpsDisposeResponse(json: *mut c_char, json_sz: usize) -> FPSStatus {
    requireAction!(!json.is_null(), return FPSStatus::paramErr);

    unsafe {
        let _ = CString::from_raw(json);
    }
    noErr
}

/// Returns the version as a C-style character string.
///
/// The returned json must be disposed of with `fpsDisposeVersion`.
///
/// FPSStatus fpsGetVersion(char **out_version)
#[no_mangle]
pub extern "C" fn fpsGetVersion(out_version: *mut *mut c_char) -> FPSStatus {
    requireAction!(!out_version.is_null(), return FPSStatus::paramErr);

    let version = CString::new(env!("CARGO_PKG_VERSION"));

    unsafe { *out_version = version.unwrap().into_raw();}
    noErr
}

/// Disposes of the version string created by a call to `fpsGetVersion`.
///
/// FPSStatus fpsDisposeVersion(char *version)
#[no_mangle]
pub extern "C" fn fpsDisposeVersion(version: *mut c_char) -> FPSStatus{
    requireAction!(!version.is_null(), return FPSStatus::paramErr);

    unsafe {
        let _ = CString::from_raw(version);
    }
    noErr
}

