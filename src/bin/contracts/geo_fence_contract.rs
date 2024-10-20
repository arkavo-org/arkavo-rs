#![allow(unexpected_cfgs)]
#[ink::contract]
pub mod geo_fence_contract {
    use scale::{Decode, Encode};

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Coordinate3D {
        pub latitude: i64,
        pub longitude: i64,
        pub altitude: i64,
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Geofence3D {
        pub min_latitude: i64,
        pub max_latitude: i64,
        pub min_longitude: i64,
        pub max_longitude: i64,
        pub min_altitude: i64,
        pub max_altitude: i64,
    }

    #[ink(storage)]
    pub struct GeoFenceContract {}

    impl GeoFenceContract {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        #[ink(message)]
        pub fn is_within_geofence(
            &self,
            geofence: Geofence3D,
            coordinate: Coordinate3D,
        ) -> bool {
            coordinate.latitude >= geofence.min_latitude
                && coordinate.latitude <= geofence.max_latitude
                && coordinate.longitude >= geofence.min_longitude
                && coordinate.longitude <= geofence.max_longitude
                && coordinate.altitude >= geofence.min_altitude
                && coordinate.altitude <= geofence.max_altitude
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn test_within_geofence() {
            let contract = GeoFenceContract::new();
            let geofence = Geofence3D {
                min_latitude: -10_000_000,
                max_latitude: 10_000_000,
                min_longitude: -20_000_000,
                max_longitude: 20_000_000,
                min_altitude: 0,
                max_altitude: 100_000_000,
            };

            assert!(contract.is_within_geofence(geofence, Coordinate3D {
                latitude: 0,
                longitude: 0,
                altitude: 50_000_000,
            }));

            assert!(!contract.is_within_geofence(geofence, Coordinate3D {
                latitude: -15_000_000,
                longitude: 0,
                altitude: 50_000_000,
            }));
        }

        #[ink::test]
        fn test_within_20ft_cube() {
            let contract = GeoFenceContract::new();
            let geofence = Geofence3D {
                min_latitude: 0,
                max_latitude: 610, // Approximately 20 feet in latitude (scaled by 10^5)
                min_longitude: 0,
                max_longitude: 610, // Approximately 20 feet in longitude (scaled by 10^5)
                min_altitude: 0,
                max_altitude: 610, // 20 feet in altitude (scaled by 10^2)
            };

            assert!(contract.is_within_geofence(geofence, Coordinate3D {
                latitude: 300,
                longitude: 300,
                altitude: 300,
            })); // Inside the cube

            assert!(!contract.is_within_geofence(geofence, Coordinate3D {
                latitude: 1000,
                longitude: 300,
                altitude: 300,
            })); // Outside latitude

            assert!(!contract.is_within_geofence(geofence, Coordinate3D {
                latitude: 300,
                longitude: 1000,
                altitude: 300,
            })); // Outside longitude

            assert!(!contract.is_within_geofence(geofence, Coordinate3D {
                latitude: 300,
                longitude: 300,
                altitude: 1000,
            })); // Outside altitude
        }
    }
}