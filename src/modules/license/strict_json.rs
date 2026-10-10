//! Duplicate-key detection for JSON. `serde_json::Value` keeps the last of
//! repeated object keys without saying so, while the viewer refuses them
//! (arkavo-ios ADR-0055 §7 step 1), so a profile v2 manifest and its policy
//! are checked here before anything is read from them.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;

/// True when `bytes` is one JSON value in which no object repeats a key,
/// compared after unescaping. False for anything that is not JSON.
#[cfg_attr(not(test), allow(dead_code))] // Task 2 adds the first caller.
pub fn has_unique_keys(bytes: &[u8]) -> bool {
    serde_json::from_slice::<UniqueKeys>(bytes).is_ok()
}

/// Deserializes any JSON value, failing on a repeated key at any depth.
#[cfg_attr(not(test), allow(dead_code))]
struct UniqueKeys;

impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueKeysVisitor)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
struct UniqueKeysVisitor;

impl<'de> Visitor<'de> for UniqueKeysVisitor {
    type Value = UniqueKeys;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_unit<E: de::Error>(self) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<UniqueKeys, A::Error> {
        while seq.next_element::<UniqueKeys>()?.is_some() {}
        Ok(UniqueKeys)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<UniqueKeys, A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("duplicate key"));
            }
            map.next_value::<UniqueKeys>()?;
        }
        Ok(UniqueKeys)
    }
}

#[cfg(test)]
mod tests {
    use super::has_unique_keys;

    #[test]
    fn json_without_repeated_keys_passes() {
        for ok in [
            r#"{}"#,
            r#"{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}"#,
            r#"[1,"x",null,true,2.5,-3]"#,
            r#""s""#,
        ] {
            assert!(has_unique_keys(ok.as_bytes()), "{ok}");
        }
    }

    #[test]
    fn a_repeated_key_at_any_depth_is_refused() {
        for bad in [
            r#"{"a":1,"a":1}"#,
            r#"{"a":1,"b":{"c":1,"c":2}}"#,
            r#"[{"x":[{"k":1,"k":2}]}]"#,
            // The same key once unescaped.
            r#"{"uuid":"a","uuid":"b"}"#,
        ] {
            assert!(!has_unique_keys(bad.as_bytes()), "{bad}");
        }
    }

    #[test]
    fn anything_but_one_json_value_is_refused() {
        for bad in ["", "nope", "{", r#"{"a":1} {"b":2}"#] {
            assert!(!has_unique_keys(bad.as_bytes()), "{bad}");
        }
    }
}
