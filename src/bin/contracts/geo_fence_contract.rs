#![allow(unexpected_cfgs)]
#![allow(dead_code)] // Ink contract generated functions
#[ink::contract]
pub mod geo_fence_contract {
    use scale::{Decode, Encode};

    #[derive(Debug, PartialEq, Clone, Copy, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Coordinate3D {
        pub latitude: f64,
        pub longitude: f64,
        pub altitude: f64,
    }

    #[derive(Debug, PartialEq, Clone, Copy, Decode, Encode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Geofence3D {
        pub min_latitude: f64,
        pub max_latitude: f64,
        pub min_longitude: f64,
        pub max_longitude: f64,
        pub min_altitude: f64,
        pub max_altitude: f64,
    }

    #[ink(storage)]
    pub struct GeoFenceContract {}

    impl Default for GeoFenceContract {
        fn default() -> Self {
            Self::new()
        }
    }

    impl GeoFenceContract {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        #[ink(message)]
        pub fn is_within_geofence(&self, geofence: Geofence3D, coordinate: Coordinate3D) -> bool {
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
                min_latitude: -10.0,
                max_latitude: 10.0,
                min_longitude: -20.0,
                max_longitude: 20.0,
                min_altitude: 0.0,
                max_altitude: 100_000.0,
            };

            assert!(contract.is_within_geofence(
                geofence,
                Coordinate3D {
                    latitude: 0.0,
                    longitude: 0.0,
                    altitude: 50_000.0,
                }
            ));

            assert!(!contract.is_within_geofence(
                geofence,
                Coordinate3D {
                    latitude: -15.0,
                    longitude: 0.0,
                    altitude: 50_000.0,
                }
            ));
        }

        #[ink::test]
        fn test_within_20ft_cube() {
            let contract = GeoFenceContract::new();
            let geofence = Geofence3D {
                min_latitude: 0.0,
                max_latitude: 0.00061, // Approximately 20 feet in latitude
                min_longitude: 0.0,
                max_longitude: 0.00061, // Approximately 20 feet in longitude
                min_altitude: 0.0,
                max_altitude: 6.1, // 20 feet in altitude
            };

            assert!(contract.is_within_geofence(
                geofence,
                Coordinate3D {
                    latitude: 0.0003,
                    longitude: 0.0003,
                    altitude: 3.0,
                }
            )); // Inside the cube

            assert!(!contract.is_within_geofence(
                geofence,
                Coordinate3D {
                    latitude: 0.001,
                    longitude: 0.0003,
                    altitude: 3.0,
                }
            )); // Outside latitude

            assert!(!contract.is_within_geofence(
                geofence,
                Coordinate3D {
                    latitude: 0.0003,
                    longitude: 0.001,
                    altitude: 3.0,
                }
            )); // Outside longitude

            assert!(!contract.is_within_geofence(
                geofence,
                Coordinate3D {
                    latitude: 0.0003,
                    longitude: 0.0003,
                    altitude: 10.0,
                }
            )); // Outside altitude
        }
    }
}
