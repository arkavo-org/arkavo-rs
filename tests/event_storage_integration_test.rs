extern crate nanotdf;
use aws_sdk_s3 as s3;
use aws_sdk_s3::primitives::ByteStream;
use std::env;
use std::error::Error;
use tokio::io::AsyncReadExt;

// This test verifies that we can store and retrieve objects from S3
// It can run with real AWS credentials or with LocalStack in CI
#[tokio::test]
async fn test_event_storage_integration() -> Result<(), Box<dyn Error>> {
    // Check if we have AWS credentials and test bucket configured
    let access_key = env::var("AWS_ACCESS_KEY_ID").ok();
    let secret_key = env::var("AWS_SECRET_ACCESS_KEY").ok();
    let region = env::var("AWS_REGION").ok();
    let bucket = env::var("TEST_S3_BUCKET").ok();
    let endpoint_url = env::var("AWS_ENDPOINT_URL").ok();

    if access_key.is_none() || secret_key.is_none() || region.is_none() || bucket.is_none() {
        eprintln!("Skipping integration test: AWS credentials or TEST_S3_BUCKET not set");
        return Ok(());
    }

    // Initialize S3 client with the region from env
    let config = aws_config::from_env().load().await;

    // Build S3 client with LocalStack-specific configuration if needed
    let s3_client = if let Some(endpoint) = endpoint_url {
        println!("Using custom endpoint: {}", endpoint);
        let s3_config = s3::config::Builder::from(&config)
            .endpoint_url(endpoint)
            .force_path_style(true)  // Required for LocalStack
            .build();
        s3::Client::from_conf(s3_config)
    } else {
        s3::Client::new(&config)
    };

    // Set up test data
    let test_key = "test-event-storage-key";
    let test_content = b"This is test event data for S3 integration tests";
    let bucket_name = bucket.unwrap();

    // Test: Upload an object to S3 (simulating event storage)
    println!("Testing S3 event storage by uploading test object...");
    let upload_result = s3_client
        .put_object()
        .bucket(&bucket_name)
        .key(test_key)
        .body(ByteStream::from(test_content.to_vec()))
        .send()
        .await;

    assert!(
        upload_result.is_ok(),
        "Failed to upload test event to S3: {:?}",
        upload_result.err()
    );
    println!("Successfully uploaded test event data to S3");

    // Test: Verify the object exists and has the correct content
    let get_result = s3_client
        .get_object()
        .bucket(&bucket_name)
        .key(test_key)
        .send()
        .await;

    assert!(
        get_result.is_ok(),
        "Failed to get test event from S3: {:?}",
        get_result.err()
    );

    // Read event data
    let response = get_result.unwrap();
    let mut body = Vec::new();
    response
        .body
        .into_async_read()
        .read_to_end(&mut body)
        .await?;

    // Verify content matches what we uploaded
    assert_eq!(
        body, test_content,
        "Retrieved event data doesn't match what was stored"
    );
    println!("Successfully verified event data integrity in S3");

    // Clean up: Delete the test object
    let delete_result = s3_client
        .delete_object()
        .bucket(&bucket_name)
        .key(test_key)
        .send()
        .await;

    assert!(
        delete_result.is_ok(),
        "Failed to delete test event from S3: {:?}",
        delete_result.err()
    );
    println!("Successfully cleaned up test event data from S3");

    println!("Event storage integration test completed successfully");
    Ok(())
}
