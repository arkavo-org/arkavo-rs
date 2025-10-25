//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use std::env;

fn main() {
    // Must use environment variables instead of #[cfg(...)] in build.rs
    // https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    // Get absolute path to prebuilt directory (relative to this crate's root)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let prebuilt_dir = format!("{}/prebuilt", manifest_dir);

    // Set RPATH so executable can find the library in the prebuilt folder
    if os == "macos" {
        let lib_path = format!("{}/macos", prebuilt_dir);
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_path);
        println!("cargo:rustc-link-search={}", lib_path);
    } else {
        let lib_path = format!("{}/{}-unknown-linux-gnu", prebuilt_dir, arch);
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_path);
        println!("cargo:rustc-link-search={}", lib_path);
    }

    // Link to libfpscrypto
    //
    // Notes:
    // 1) The cargo:rustc-link-lib options is only passed to the library target of the package,
    // unless there is no library target, in which case it is passed to all targets. This is done
    // because all other targets have an implicit dependency on the library target, and the given
    // library to link should only be included once.
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-lib
    println!("cargo:rustc-link-lib=dylib=fpscrypto");
}
