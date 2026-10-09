//! Test-only fixtures, generated at run time by `fixtures/gen_fixtures.sh`
//! (openssl CLI, independent of arks code). Nothing here is committed.

use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

pub struct Fixtures {
    pub key_pem: String,
    pub manifest_allowed: String,
    pub binding_hex: String,
    pub binding_raw_json: String,
}

pub fn fixtures() -> &'static Fixtures {
    static F: OnceLock<Fixtures> = OnceLock::new();
    F.get_or_init(generate)
}

fn generate() -> Fixtures {
    let dir = std::env::temp_dir().join(format!("arks-fixtures-{}", uuid::Uuid::new_v4()));
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules/license/fixtures/gen_fixtures.sh");
    let out = Command::new("bash")
        .arg(&script)
        .arg(&dir)
        .output()
        .expect("failed to run bash for gen_fixtures.sh");
    if !out.status.success() {
        panic!(
            "gen_fixtures.sh failed: {}{}\nhint: needs OpenSSL 3 on PATH or OPENSSL=...",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
    }
    let read =
        |n: &str| std::fs::read_to_string(dir.join(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
    let f = Fixtures {
        key_pem: read("test_kas_rsa_private.pem"),
        manifest_allowed: read("manifest_allowed.json"),
        binding_hex: read("binding_hex.txt"),
        binding_raw_json: read("binding_raw_json.txt"),
    };
    let _ = std::fs::remove_dir_all(&dir);
    f
}
