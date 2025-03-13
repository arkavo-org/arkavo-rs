use std::env;

// Test-only version of load_config
fn test_load_config() -> ServerSettings {
    let default_bucket = "default-bucket".to_string();
    
    ServerSettings {
        port: env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080),
        tls_enabled: env::var("TLS_CERT_PATH").is_ok(),
        tls_cert_path: env::var("TLS_CERT_PATH").unwrap_or_else(|_| "./fullchain.pem".to_string()),
        tls_key_path: env::var("TLS_KEY_PATH").unwrap_or_else(|_| "./privkey.pem".to_string()),
        kas_key_path: env::var("KAS_KEY_PATH").unwrap_or_else(|_| "./recipient_private_key.pem".to_string()),
        enable_timing_logs: env::var("ENABLE_TIMING_LOGS")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false),
        nats_url: env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string()),
        nats_subject: env::var("NATS_SUBJECT").unwrap_or_else(|_| "nanotdf.messages".to_string()),
        redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
        s3_bucket: env::var("S3_BUCKET").unwrap_or_else(|_| default_bucket),
    }
}

#[derive(Debug, PartialEq)]
struct ServerSettings {
    port: u16,
    tls_enabled: bool,
    tls_cert_path: String,
    tls_key_path: String,
    kas_key_path: String,
    enable_timing_logs: bool,
    nats_url: String,
    nats_subject: String,
    redis_url: String,
    s3_bucket: String,
}

#[test]
fn test_server_settings_with_s3_bucket() {
    // Save original environment variable
    let original_s3_bucket = env::var("S3_BUCKET").ok();
    
    // Test with environment variable
    env::set_var("S3_BUCKET", "env-test-bucket");
    let settings = test_load_config();
    assert_eq!(settings.s3_bucket, "env-test-bucket");
    
    // Test without environment variable (should use default)
    env::remove_var("S3_BUCKET");
    let settings = test_load_config();
    assert_eq!(settings.s3_bucket, "default-bucket");
    
    // Restore original environment variable
    if let Some(val) = original_s3_bucket {
        env::set_var("S3_BUCKET", val);
    }
}