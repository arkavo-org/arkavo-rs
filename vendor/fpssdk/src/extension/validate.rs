//
// Copyright © 2023-2025 Apple Inc. All rights reserved.
//

/// Checks the `condition`. If false, logs failure and performs `action`.
#[macro_export]
macro_rules! requireAction {
    ($condition: expr, $action: expr) => {
        if !$condition {
            log::debug!(
                "❌ Assertion failure: {} [{}:{}]",
                stringify!($condition),
                file!(),
                line!()
            );
            // We don't have an error code. Use -1 so that it shows up if we filter out 0.
            $crate::fpsLogError!(-1, "Assertion failure: {}", stringify!($condition));
            $action;
        }
    };
}

/// Logs and returns error status.
#[macro_export]
macro_rules! returnErrorStatus {
    ($err: expr) => {
        log::debug!("❌ Returning error: {:?} ({}) [{}:{}]", $err, $err, file!(), line!());
        return Err($err);
    };
}

pub type Result<T> = std::result::Result<T, FPSStatus>;

/// Error codes used by FairPlay Streaming.
#[repr(C)] // This type is used as a return from unsafe functions
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FPSStatus {
    noErr = 0,
    spcVersionErr = -42580,
    parserErr = -42581,
    missingRequiredTagErr = -42583,
    paramErr = -42585,
    memoryErr = -42586,
    integrityErr = -42589,
    versionErr = -42590,
    dupTagErr = -42591,
    internalErr = -42601,
    clientSecurityLevelErr = -42604,
    invalidCertificateErr = -42605,
    notImplementedErr = -42612,
}

impl std::fmt::Display for FPSStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as i32)
    }
}

impl serde::Serialize for FPSStatus {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
       serializer.serialize_i32(*self as i32) 
    }
}

impl std::convert::TryFrom<i64> for FPSStatus {
    type Error = FPSStatus;
    fn try_from(value: i64) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(FPSStatus::noErr),
            -42580 => Ok(FPSStatus::spcVersionErr),
            -42581 => Ok(FPSStatus::paramErr),
            -42583 => Ok(FPSStatus::missingRequiredTagErr),
            -42585 => Ok(FPSStatus::paramErr),
            -42586 => Ok(FPSStatus::memoryErr),
            -42590 => Ok(FPSStatus::versionErr),
            -42591 => Ok(FPSStatus::dupTagErr),
            -42601 => Ok(FPSStatus::internalErr),
            -42604 => Ok(FPSStatus::clientSecurityLevelErr),
            -42605 => Ok(FPSStatus::invalidCertificateErr),
            -42612 => Ok(FPSStatus::notImplementedErr),
            _ => Err(FPSStatus::parserErr)
        }
    }
}

impl std::convert::TryFrom<i32> for FPSStatus {
    type Error = FPSStatus;
    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
       FPSStatus::try_from(i64::from(value)) 
    }
}
