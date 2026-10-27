//! Strict boolean settings: a value that isn't clearly true or false stops
//! startup instead of silently taking a default.

/// Reads `name`: unset is `false`; a set value must be one of true/false/1/0/yes/no
/// (any case, surrounding space ignored). A non-UTF-8 value is an error, not unset.
pub fn from_env(name: &str) -> Result<bool, String> {
    match std::env::var(name) {
        Ok(value) => parse(name, Some(&value)),
        Err(std::env::VarError::NotPresent) => parse(name, None),
        Err(std::env::VarError::NotUnicode(value)) => {
            Err(format!("{} must be true or false, got {:?}", name, value))
        }
    }
}

/// Parses a boolean setting: absent is `false`; an explicit value must be one of
/// true/false/1/0/yes/no (any case, surrounding space ignored)
pub fn parse(name: &str, value: Option<&str>) -> Result<bool, String> {
    let Some(value) = value else {
        return Ok(false);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("{} must be true or false, got {:?}", name, value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gating flags (C2PA_REQUIRE_ENTITLEMENT, TLS_ALLOW_TLS12) must stop startup on a
    /// value that isn't clearly true or false (arkavo-rs#120).
    #[test]
    fn parsing_fails_closed() {
        assert_eq!(parse("F", None), Ok(false));
        for on in ["true", "TRUE", " True ", "1", "yes"] {
            assert_eq!(parse("F", Some(on)), Ok(true), "{:?}", on);
        }
        for off in ["false", "FALSE", "0", "no", " false"] {
            assert_eq!(parse("F", Some(off)), Ok(false), "{:?}", off);
        }
        for bad in ["", "on", "enabled", "tru"] {
            let err = parse("C2PA_REQUIRE_ENTITLEMENT", Some(bad)).unwrap_err();
            assert!(err.contains("C2PA_REQUIRE_ENTITLEMENT"), "{}", err);
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_value_is_an_error_not_unset() {
        use std::os::unix::ffi::OsStrExt;
        const NAME: &str = "ARKS_ENV_FLAG_TEST_NON_UTF8";
        assert_eq!(from_env(NAME), Ok(false));
        std::env::set_var(NAME, std::ffi::OsStr::from_bytes(b"tr\xffue"));
        let result = from_env(NAME);
        std::env::remove_var(NAME);
        assert!(result.unwrap_err().contains(NAME));
    }
}
