#![cfg_attr(not(feature = "std"), no_std, no_main)]
#![allow(unexpected_cfgs)]
#[ink::contract]
mod timestamp_validator {
    use scale::{Decode, Encode};

    #[ink(storage)]
    pub struct TimestampValidator {}

    impl Default for TimestampValidator {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TimestampValidator {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        #[ink(message)]
        pub fn is_timestamp_valid(&self, timestamp: u64, start: u64, end: u64) -> bool {
            // Check if timestamp is within range (inclusive)
            timestamp >= start && timestamp <= end
        }

        #[ink(message)]
        pub fn validate_with_error(&self, timestamp: u64, start: u64, end: u64) -> Result<(), Error> {
            if timestamp < start {
                return Err(Error::TooEarly);
            }
            if timestamp > end {
                return Err(Error::TooLate);
            }
            Ok(())
        }
    }

    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        TooEarly,
        TooLate,
    }
}

#[cfg(test)]
mod tests {
    use crate::timestamp_validator::{Error, TimestampValidator};

    #[ink::test]
    fn test_timestamp_validation() {
        let validator = TimestampValidator::new();

        // Test valid timestamp
        assert!(validator.is_timestamp_valid(100, 50, 150));

        // Test boundary conditions
        assert!(validator.is_timestamp_valid(50, 50, 150)); // Start boundary
        assert!(validator.is_timestamp_valid(150, 50, 150)); // End boundary

        // Test invalid timestamps
        assert!(!validator.is_timestamp_valid(49, 50, 150)); // Before start
        assert!(!validator.is_timestamp_valid(151, 50, 150)); // After end
    }

    #[ink::test]
    fn test_validate_with_error() {
        let validator = TimestampValidator::new();

        // Test valid timestamp
        assert_eq!(validator.validate_with_error(100, 50, 150), Ok(()));

        // Test invalid timestamps
        assert_eq!(validator.validate_with_error(49, 50, 150), Err(Error::TooEarly));
        assert_eq!(validator.validate_with_error(151, 50, 150), Err(Error::TooLate));
    }
}