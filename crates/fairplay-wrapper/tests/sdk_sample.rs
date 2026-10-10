//! Runs the real libfpscrypto against Apple's sample SPC and test credentials.
//!
//! Gated on `FPS_SDK_KSM_DIR`, the SDK's `Development/Key_Server_Module`
//! directory (holds `Test_Inputs/` and `credentials/`); skipped when unset.
//! Set `FPS_SDK_CKC_OUT` to also write the CKC (base64) for `parse_fps`.

use base64::Engine;
use fairplay_wrapper::{FairPlayKeyServer, SpcRequest};
use std::path::PathBuf;

#[test]
fn sample_spc_yields_ckc_with_asset_info_request() {
    let Ok(ksm) = std::env::var("FPS_SDK_KSM_DIR") else {
        eprintln!("FPS_SDK_KSM_DIR unset; skipping");
        return;
    };
    let ksm = PathBuf::from(ksm);
    let sample = std::fs::read_to_string(ksm.join("Test_Inputs/iOS/spc_ios_hd_lease_2048.json"))
        .expect("sample input");
    let sample: serde_json::Value = serde_json::from_str(&sample).unwrap();
    let item = &sample["fairplay-streaming-request"]["create-ckc"][0];
    let info = &item["asset-info"][0];
    let spc = base64::engine::general_purpose::STANDARD
        .decode(item["spc"].as_str().unwrap())
        .unwrap();

    let server = FairPlayKeyServer::new(ksm.join("credentials")).expect("credentials");
    let response = server
        .process_spc(SpcRequest {
            content_id: "sample".into(),
            spc_data: spc,
            asset_id: "sample".into(),
            content_key: hex::decode(info["content-key"].as_str().unwrap()).unwrap(),
            content_iv: hex::decode(info["content-iv"].as_str().unwrap()).unwrap(),
            lease_duration_secs: Some(3600),
        })
        .expect("CKC");
    assert!(!response.ckc_data.is_empty());

    if let Ok(out) = std::env::var("FPS_SDK_CKC_OUT") {
        std::fs::write(
            out,
            base64::engine::general_purpose::STANDARD.encode(&response.ckc_data),
        )
        .unwrap();
    }
}
