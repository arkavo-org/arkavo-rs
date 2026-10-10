//! Runs the real libfpscrypto against Apple's sample SPCs and test credentials.
//!
//! Gated on `FPS_SDK_KSM_DIR`, the SDK's `Development/Key_Server_Module`
//! directory (holds `Test_Inputs/` and `credentials/`); skipped when unset.
//! Set `FPS_SDK_CKC_OUT` to also write the uhd CKC (base64) for `parse_fps`.

use base64::Engine;
use fairplay_wrapper::{CkcResponse, ContentType, FairPlayKeyServer, SpcRequest};
use std::path::PathBuf;

/// A CKC for Apple's sample `name`, with its key and IV, issued as
/// `content_type` with HDCP Type 1. None when `FPS_SDK_KSM_DIR` is unset.
fn issue_sample(name: &str, content_type: ContentType) -> Option<CkcResponse> {
    let Ok(ksm) = std::env::var("FPS_SDK_KSM_DIR") else {
        eprintln!("FPS_SDK_KSM_DIR unset; skipping");
        return None;
    };
    let ksm = PathBuf::from(ksm);
    let sample =
        std::fs::read_to_string(ksm.join("Test_Inputs/iOS").join(name)).expect("sample input");
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
            content_type,
            lease_duration_secs: Some(3600),
        })
        .expect("CKC");
    Some(response)
}

#[test]
fn sample_spc_yields_ckc_with_asset_info_request() {
    let Some(response) = issue_sample("spc_ios_uhd_lease_2048.json", ContentType::Uhd) else {
        return;
    };
    assert!(!response.ckc_data.is_empty());

    if let Ok(out) = std::env::var("FPS_SDK_CKC_OUT") {
        std::fs::write(
            out,
            base64::engine::general_purpose::STANDARD.encode(&response.ckc_data),
        )
        .unwrap();
    }
}

/// ADR-0055 issues audio as `audio` with HDCP Type 1. Apple's own sample
/// asks for `hdcp-type` -1, so this proves the SDK accepts our terms.
#[test]
fn audio_sample_spc_yields_ckc_as_audio_with_hdcp_type_1() {
    let Some(response) = issue_sample("spc_ios_audio_lease_2048.json", ContentType::Audio) else {
        return;
    };
    assert!(!response.ckc_data.is_empty());
}
