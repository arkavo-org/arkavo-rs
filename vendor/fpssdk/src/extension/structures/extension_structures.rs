//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

use crate::extension::extension_constants::ContentType;
use crate::extension::extension_constants::FPSSecurityLevel;
use std::fmt::Debug;

#[derive(Debug, Clone, Default)]
pub struct SDKExtension {
}

#[derive(Debug, Clone, Default)]
pub struct FPSOperationExtension {
}

#[derive(Debug, Clone, Default)]
pub struct AssetInfoExtension {
    pub contentType: ContentType,
}

#[derive(Debug, Clone, Default)]
pub struct ServerCtxExtension {
}

#[derive(Debug, Clone, Default)]
pub struct FPSResultsExtension {
}

#[derive(Debug, Clone, Default)]
pub struct FPSResultExtension {
}

#[derive(Debug, Clone, Default)]
pub struct FPSResultAssetInfoExtension {
}

#[derive(Debug, Clone, Default)]
pub struct SPCDataExtension {
}

#[derive(Debug, Clone, Default)]
pub struct SPCAssetInfoExtension {
}

#[derive(Debug, Clone, Default)]
pub struct CKCDataExtension {
}

#[derive(Debug, Clone, Default)]
pub struct CKCAssetInfoExtension {
    pub requiredSecurityLevel: FPSSecurityLevel,
}

#[derive(Debug, Clone, Default)]
pub struct SPCContainerExtension {
}

#[derive(Debug, Clone, Default)]
pub struct ClientFeaturesExtension {
}

#[derive(Debug, Clone, Default)]
pub struct KeyDurationExtension {
}
