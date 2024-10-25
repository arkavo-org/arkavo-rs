#![allow(unexpected_cfgs)]
#[ink::contract]
pub mod content_rating {
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum RatingLevel {
        Unused = 0,
        None = 1,
        Mild = 2,
        Moderate = 3,
        Severe = 4,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Rating {
        pub violent: RatingLevel,
        pub sexual: RatingLevel,
        pub profane: RatingLevel,
        pub substance: RatingLevel,
        pub hate: RatingLevel,
        pub harm: RatingLevel,
        pub mature: RatingLevel,
        pub bully: RatingLevel,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum AgeLevel {
        Kids,   // Under 13
        Teens,  // 13 to 17
        Adults, // 18 and above
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        ViolentContentTooHigh,
        SexualContentNotAllowed,
        ProfaneContentNotAllowed,
        SubstanceContentNotAllowed,
        HateContentNotAllowed,
        HarmContentNotAllowed,
        MatureContentNotAllowed,
        BullyingContentNotAllowed,
    }

    #[ink(storage)]
    #[derive(Default)]
    pub struct ContentRating {
        // Contract storage (empty for this case)
    }

    impl ContentRating {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        #[ink(message)]
        pub fn validate_content(&self, age_level: AgeLevel, rating: Rating) -> Result<(), Error> {
            match age_level {
                AgeLevel::Kids => self.validate_kids_content(&rating),
                AgeLevel::Teens => self.validate_teens_content(&rating),
                AgeLevel::Adults => Ok(()), // Everything is allowed for adults
            }
        }

        fn validate_kids_content(&self, rating: &Rating) -> Result<(), Error> {
            // For kids, only mild violence is allowed, everything else must be none
            if !matches!(rating.violent, RatingLevel::None | RatingLevel::Mild) {
                return Err(Error::ViolentContentTooHigh);
            }
            if !matches!(rating.sexual, RatingLevel::None) {
                return Err(Error::SexualContentNotAllowed);
            }
            if !matches!(rating.profane, RatingLevel::None) {
                return Err(Error::ProfaneContentNotAllowed);
            }
            if !matches!(rating.substance, RatingLevel::None) {
                return Err(Error::SubstanceContentNotAllowed);
            }
            if !matches!(rating.hate, RatingLevel::None) {
                return Err(Error::HateContentNotAllowed);
            }
            if !matches!(rating.harm, RatingLevel::None) {
                return Err(Error::HarmContentNotAllowed);
            }
            if !matches!(rating.mature, RatingLevel::None) {
                return Err(Error::MatureContentNotAllowed);
            }
            if !matches!(rating.bully, RatingLevel::None) {
                return Err(Error::BullyingContentNotAllowed);
            }
            Ok(())
        }

        fn validate_teens_content(&self, rating: &Rating) -> Result<(), Error> {
            // For teens, certain content must be none, others can be up to mild
            if matches!(rating.violent, RatingLevel::Moderate | RatingLevel::Severe) {
                return Err(Error::ViolentContentTooHigh);
            }
            if matches!(rating.sexual, RatingLevel::Moderate | RatingLevel::Severe) {
                return Err(Error::SexualContentNotAllowed);
            }
            if matches!(rating.profane, RatingLevel::Moderate | RatingLevel::Severe) {
                return Err(Error::ProfaneContentNotAllowed);
            }
            // These must be none for teens
            if !matches!(rating.substance, RatingLevel::None) {
                return Err(Error::SubstanceContentNotAllowed);
            }
            if !matches!(rating.hate, RatingLevel::None) {
                return Err(Error::HateContentNotAllowed);
            }
            if !matches!(rating.harm, RatingLevel::None) {
                return Err(Error::HarmContentNotAllowed);
            }
            if matches!(rating.mature, RatingLevel::Moderate | RatingLevel::Severe) {
                return Err(Error::MatureContentNotAllowed);
            }
            if !matches!(rating.bully, RatingLevel::None) {
                return Err(Error::BullyingContentNotAllowed);
            }
            Ok(())
        }

        #[ink(message)]
        pub fn check_content(&self, age_level: AgeLevel, rating: Rating) -> bool {
            self.validate_content(age_level, rating).is_ok()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn kids_content_validation_works() {
            let contract = ContentRating::new();

            // Valid kids content
            let valid_kids_rating = Rating {
                violent: RatingLevel::Mild,
                sexual: RatingLevel::None,
                profane: RatingLevel::None,
                substance: RatingLevel::None,
                hate: RatingLevel::None,
                harm: RatingLevel::None,
                mature: RatingLevel::None,
                bully: RatingLevel::None,
            };
            assert!(contract.check_content(AgeLevel::Kids, valid_kids_rating));

            // Invalid kids content (too violent)
            let invalid_kids_rating = Rating {
                violent: RatingLevel::Moderate,
                sexual: RatingLevel::None,
                profane: RatingLevel::None,
                substance: RatingLevel::None,
                hate: RatingLevel::None,
                harm: RatingLevel::None,
                mature: RatingLevel::None,
                bully: RatingLevel::None,
            };
            assert!(!contract.check_content(AgeLevel::Kids, invalid_kids_rating));
        }

        #[ink::test]
        fn teens_content_validation_works() {
            let contract = ContentRating::new();

            // Valid teens content
            let valid_teens_rating = Rating {
                violent: RatingLevel::Mild,
                sexual: RatingLevel::Mild,
                profane: RatingLevel::Mild,
                substance: RatingLevel::None,
                hate: RatingLevel::None,
                harm: RatingLevel::None,
                mature: RatingLevel::Mild,
                bully: RatingLevel::None,
            };
            assert!(contract.check_content(AgeLevel::Teens, valid_teens_rating));

            // Invalid teens content (substance use)
            let invalid_teens_rating = Rating {
                violent: RatingLevel::Mild,
                sexual: RatingLevel::Mild,
                profane: RatingLevel::Mild,
                substance: RatingLevel::Mild,
                hate: RatingLevel::None,
                harm: RatingLevel::None,
                mature: RatingLevel::Mild,
                bully: RatingLevel::None,
            };
            assert!(!contract.check_content(AgeLevel::Teens, invalid_teens_rating));
        }

        #[ink::test]
        fn adult_content_validation_works() {
            let contract = ContentRating::new();

            // All content levels are valid for adults
            let adult_rating = Rating {
                violent: RatingLevel::Severe,
                sexual: RatingLevel::Severe,
                profane: RatingLevel::Severe,
                substance: RatingLevel::Severe,
                hate: RatingLevel::Severe,
                harm: RatingLevel::Severe,
                mature: RatingLevel::Severe,
                bully: RatingLevel::Severe,
            };
            assert!(contract.check_content(AgeLevel::Adults, adult_rating));
        }
    }
}
