//! One AWS SDK configuration for the process (credentials chain, region), shared by
//! the KMS signer and moderation's DynamoDB client (arkavo-rs#111).

use aws_config::SdkConfig;
use tokio::sync::OnceCell;

static SHARED: OnceCell<SdkConfig> = OnceCell::const_new();

/// The environment's AWS configuration, loaded on first use.
pub async fn shared_config() -> &'static SdkConfig {
    SHARED.get_or_init(aws_config::load_from_env).await
}

/// The region of a KMS key ARN (`arn:<partition>:kms:<region>:<account>:key/<id>`),
/// or None for a bare key id or alias, which use the ambient region.
pub fn arn_region(key_id: &str) -> Option<&str> {
    let mut parts = key_id.splitn(6, ':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("arn"), Some(_), Some("kms"), Some(region)) if !region.is_empty() => Some(region),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_comes_from_a_kms_arn_only() {
        assert_eq!(
            arn_region(
                "arn:aws:kms:us-east-1:976193232136:key/a62ca186-61d6-490b-a1a1-9e22420c4783"
            ),
            Some("us-east-1")
        );
        assert_eq!(
            arn_region("arn:aws-us-gov:kms:us-gov-west-1:1:key/x"),
            Some("us-gov-west-1")
        );
        assert_eq!(arn_region("a62ca186-61d6-490b-a1a1-9e22420c4783"), None);
        assert_eq!(arn_region("alias/arkavo-c2pa"), None);
        assert_eq!(arn_region("arn:aws:s3:us-east-1:1:bucket"), None);
        assert_eq!(arn_region("arn:aws:kms::1:key/x"), None);
    }
}
