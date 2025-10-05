extern crate nanotdf;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3 as s3;
use aws_sdk_s3::primitives::ByteStream;
use s3::Client as S3Client;
use std::env;
use std::error::Error;
use tokio::io::AsyncReadExt;

const TEST_BUCKET: &str = "test-integration-bucket";
const TEST_KEY: &str = "test-integration-key";
const TEST_CONTENT: &str = "This is test content for S3 integration tests";

// This test requires real AWS credentials to be set in environment variables:
// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, and TEST_S3_BUCKET
// It's skipped by default to avoid requiring credentials for regular test runs
#[tokio::test]
async fn test_s3_integration() -> Result<(), Box<dyn Error>> {
    // Check if we have AWS credentials and a test bucket configured
    let access_key = env::var("AWS_ACCESS_KEY_ID").ok();
    let secret_key = env::var("AWS_SECRET_ACCESS_KEY").ok();
    let region_str = env::var("AWS_REGION").ok();
    let bucket = env::var("TEST_S3_BUCKET").unwrap_or_else(|_| TEST_BUCKET.to_string());

    if access_key.is_none() || secret_key.is_none() || region_str.is_none() {
        eprintln!("Skipping S3 integration test: AWS credentials not set");
        return Ok(());
    }

    // Initialize S3 client with the region from env
    // Check if we're using LocalStack (in CI environment)
    let endpoint_url = env::var("AWS_ENDPOINT_URL").ok();

    let config_builder = aws_config::from_env();

    // If we're running with LocalStack, configure the endpoint URL
    let config = if let Some(endpoint) = endpoint_url {
        println!("Using custom endpoint: {}", endpoint);
        config_builder.endpoint_url(endpoint).load().await
    } else {
        config_builder.load().await
    };
    let s3_client = S3Client::new(&config);

    // Test uploading an object
    let upload_result = s3_client
        .put_object()
        .bucket(&bucket)
        .key(TEST_KEY)
        .body(ByteStream::from(TEST_CONTENT.as_bytes().to_vec()))
        .send()
        .await;

    assert!(
        upload_result.is_ok(),
        "Failed to upload object to S3: {:?}",
        upload_result.err()
    );
    println!("Successfully uploaded test object to S3");

    // Test downloading the object
    let get_result = s3_client
        .get_object()
        .bucket(&bucket)
        .key(TEST_KEY)
        .send()
        .await;

    assert!(
        get_result.is_ok(),
        "Failed to get object from S3: {:?}",
        get_result.err()
    );

    // Read and verify the object content
    let response = get_result.unwrap();
    let mut body = Vec::new();
    response
        .body
        .into_async_read()
        .read_to_end(&mut body)
        .await?;

    let content = String::from_utf8(body)?;
    assert_eq!(
        content, TEST_CONTENT,
        "Retrieved content doesn't match expected content"
    );
    println!("Successfully verified downloaded content from S3");

    // Test deleting the object
    let delete_result = s3_client
        .delete_object()
        .bucket(&bucket)
        .key(TEST_KEY)
        .send()
        .await;

    assert!(
        delete_result.is_ok(),
        "Failed to delete object from S3: {:?}",
        delete_result.err()
    );
    println!("Successfully deleted test object from S3");

    Ok(())
}
