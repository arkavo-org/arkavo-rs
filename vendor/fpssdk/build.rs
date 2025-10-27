//
// Copyright © 2023-2024 Apple Inc. All rights reserved.
//

use std::env;
use std::path::{Path, PathBuf};

fn find_library_path(os: &str, arch: &str, manifest_dir: &str) -> Option<PathBuf> {
    // Priority 1: FPSSDK_LIB_PATH environment variable
    if let Ok(custom_path) = env::var("FPSSDK_LIB_PATH") {
        let path = PathBuf::from(&custom_path);
        if path.exists() {
            println!(
                "cargo:warning=Using FairPlay SDK from FPSSDK_LIB_PATH: {}",
                custom_path
            );
            return Some(path);
        }
        println!(
            "cargo:warning=FPSSDK_LIB_PATH set but directory not found: {}",
            custom_path
        );
    }

    // Priority 2: Check prebuilt directory (for backwards compatibility)
    let prebuilt_dir = format!("{}/prebuilt", manifest_dir);
    let platform_dir = if os == "macos" {
        format!("{}/macos", prebuilt_dir)
    } else {
        format!("{}/{}-unknown-linux-gnu", prebuilt_dir, arch)
    };

    let lib_name = if os == "macos" {
        "libfpscrypto.dylib"
    } else {
        "libfpscrypto.so"
    };

    let prebuilt_lib = Path::new(&platform_dir).join(lib_name);
    if prebuilt_lib.exists() {
        println!(
            "cargo:warning=Using FairPlay SDK from prebuilt directory: {}",
            platform_dir
        );
        return Some(PathBuf::from(platform_dir));
    }

    // Priority 3: Check common system locations
    let system_paths = if os == "macos" {
        vec!["/usr/local/lib", "/opt/homebrew/lib", "/opt/local/lib"]
    } else {
        vec!["/usr/local/lib", "/usr/lib"]
    };

    for sys_path in system_paths {
        let lib_path = Path::new(sys_path).join(lib_name);
        if lib_path.exists() {
            println!(
                "cargo:warning=Using FairPlay SDK from system path: {}",
                sys_path
            );
            return Some(PathBuf::from(sys_path));
        }
    }

    None
}

fn main() {
    // Must use environment variables instead of #[cfg(...)] in build.rs
    // https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Find libfpscrypto library
    match find_library_path(&os, &arch, &manifest_dir) {
        Some(lib_path) => {
            let lib_path_str = lib_path.to_string_lossy();

            // Set RPATH so executable can find the library at runtime
            if os == "macos" {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_path_str);
            } else {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_path_str);
            }

            println!("cargo:rustc-link-search={}", lib_path_str);
        }
        None => {
            eprintln!("\n\n==========================================================");
            eprintln!("ERROR: Apple FairPlay SDK library (libfpscrypto) not found!");
            eprintln!("==========================================================");
            eprintln!(
                "\nThe FairPlay SDK binaries are required to build with --features fairplay."
            );
            eprintln!("\nTo install:");
            eprintln!("  1. Download FairPlay Streaming Server SDK from Apple Developer Portal");
            eprintln!("  2. Extract to vendor/FairPlay_Streaming_Server_SDK_26/");
            eprintln!("  3. Copy binaries:");
            eprintln!("     macOS:   cp vendor/FairPlay_*/Development/lib/macos/libfpscrypto.dylib /usr/local/lib/");
            eprintln!("     Linux:   cp vendor/FairPlay_*/Development/lib/linux/libfpscrypto.so /usr/local/lib/");
            eprintln!("\nAlternatively, set FPSSDK_LIB_PATH environment variable:");
            eprintln!("  export FPSSDK_LIB_PATH=/path/to/lib/directory");
            eprintln!("\nOr use LIBRARY_PATH for temporary builds:");
            eprintln!("  LIBRARY_PATH=/path/to/lib cargo build --features fairplay");
            eprintln!("==========================================================\n\n");

            panic!("FairPlay SDK library not found. See error message above for installation instructions.");
        }
    }

    // Link to libfpscrypto
    //
    // Notes:
    // 1) The cargo:rustc-link-lib option is only passed to the library target of the package,
    // unless there is no library target, in which case it is passed to all targets. This is done
    // because all other targets have an implicit dependency on the library target, and the given
    // library to link should only be included once.
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-lib
    println!("cargo:rustc-link-lib=dylib=fpscrypto");
}
