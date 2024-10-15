#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod geo_fence_contract {
    use ink::storage::Mapping;
    use ink::storage::traits::StorageLayout;
    use scale::{Decode, Encode};

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    #[derive(StorageLayout)]
    pub struct Coordinate3D {
        pub latitude: i64,
        pub longitude: i64,
        pub altitude: i64,
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    #[derive(StorageLayout)]
    pub struct Geofence3D {
        pub min_latitude: i64,
        pub max_latitude: i64,
        pub min_longitude: i64,
        pub max_longitude: i64,
        pub min_altitude: i64,
        pub max_altitude: i64,
    }

    #[ink(storage)]
    pub struct GeoFenceContract {
        geofences: Mapping<u32, Geofence3D>,
        geofence_count: u32,
    }

    impl Default for GeoFenceContract {
             fn default() -> Self {
        Self::new()
        }
    }
    
    impl GeoFenceContract {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                geofences: Mapping::default(),
                geofence_count: 0,
            }
        }

        #[ink(message)]
        pub fn add_geofence(&mut self, geofence: Geofence3D) -> u32 {
            let id = self.geofence_count;
            self.geofences.insert(id, &geofence);
            self.geofence_count += 1;
            id
        }

        #[ink(message)]
        pub fn is_within_geofence(
            &self,
            geofence_id: u32,
            coordinate: Coordinate3D,
        ) -> bool {
            if let Some(geofence) = self.geofences.get(geofence_id) {
                coordinate.latitude >= geofence.min_latitude
                    && coordinate.latitude <= geofence.max_latitude
                    && coordinate.longitude >= geofence.min_longitude
                    && coordinate.longitude <= geofence.max_longitude
                    && coordinate.altitude >= geofence.min_altitude
                    && coordinate.altitude <= geofence.max_altitude
            } else {
                false
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn test_within_geofence() {
            let mut contract = GeoFenceContract::new();
            let geofence = Geofence3D {
                min_latitude: -10_000_000,
                max_latitude: 10_000_000,
                min_longitude: -20_000_000,
                max_longitude: 20_000_000,
                min_altitude: 0,
                max_altitude: 100_000_000,
            };
            let geofence_id = contract.add_geofence(geofence);

            assert!(contract.is_within_geofence(geofence_id, Coordinate3D {
                latitude: 0,
                longitude: 0,
                altitude: 50_000_000,
            }));

            assert!(!contract.is_within_geofence(geofence_id, Coordinate3D {
                latitude: -15_000_000,
                longitude: 0,
                altitude: 50_000_000,
            }));
        }
    }
}