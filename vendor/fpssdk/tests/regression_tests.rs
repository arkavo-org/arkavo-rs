//
// Copyright © 2024-2025 Apple Inc. All rights reserved.
//

use fpssdk::fpsProcessOperations;
use serde_jsonrc::{from_str, Value};
use std::ffi::{c_char, CString};
use std::fs;

/// Loop through all files in directory Test_Inputs and verifies the returned status is 0.
#[test]
fn regression_tests() -> () {
    let test_dirs = fs::read_dir("../Test_Inputs").unwrap();
    for dir in test_dirs {
        let test_files = fs::read_dir(dir.unwrap().path()).unwrap();
        for case in test_files {
            std::env::set_var("RUST_LOG", "error");

            let file_path = case.unwrap().path();
            let file_name = file_path.file_name().unwrap().to_owned();
            if file_path.is_dir() {
                continue;
            }

            let json_as_string = fs::read_to_string(file_path).expect("File not found: input");
            let len = json_as_string.len();
            let result: String;

            unsafe {
                let json = CString::new(json_as_string).unwrap().into_raw();
                let mut out_json: *mut c_char = std::ptr::null_mut();
                let mut out_json_len: usize = 0;

                fpsProcessOperations(json, len, &mut out_json, &mut out_json_len);
                let cstring = CString::from_raw(out_json);

                result = cstring.into_string().unwrap();
                assert!(!result.is_empty());
            }

            let result_json: Value = from_str(&result).expect("Failed to load result JSON");
            let root_obj = result_json["fairplay-streaming-response"]
                .as_object()
                .unwrap();
            if let Some(obj) = root_obj.get("create-ckc") {
                if let Some(ckc_obj) = obj.as_array() {
                    let status = ckc_obj[0]["status"].as_i64().unwrap();
                    assert_eq!(status, 0, "test failed on file: {:?}", file_name);
                } else {
                    assert!(false, "create-ckc object has the wrong type");
                }
            } else if let Some(obj) = root_obj.get("get-client-info") {
                if let Some(get_client_info_obj) = obj.as_array() {
                    let status = get_client_info_obj[0]["status"].as_i64().unwrap();
                    assert_eq!(status, 0, "test failed on file: {:?}", file_name);
                } else {
                    assert!(false, "get-client-info object has the wrong type");
                }
            } else {
                assert!(false, "test failed on file: {:?}", file_name);
            }
        }
    }
}
