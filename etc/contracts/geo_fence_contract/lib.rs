#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod geo_fence_contract {
    use parity_scale_codec::{Decode, Encode};
    use scale_info::TypeInfo;

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode, TypeInfo)]
    pub struct Coordinate3D {
        pub latitude: FixedPoint,
        pub longitude: FixedPoint,
        pub altitude: FixedPoint,
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode, TypeInfo)]
    pub struct Geofence3D {
        pub min_latitude: FixedPoint,
        pub max_latitude: FixedPoint,
        pub min_longitude: FixedPoint,
        pub max_longitude: FixedPoint,
        pub min_altitude: FixedPoint,
        pub max_altitude: FixedPoint,
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Decode, Encode, TypeInfo)]
    pub struct FixedPoint(pub i64);

    impl FixedPoint {
        pub fn new(value: f64) -> Self {
            FixedPoint((value * 1_000_000.0) as i64) // Scale f64 to fixed point representation
        }

        pub fn to_f64(self) -> f64 {
            self.0 as f64 / 1_000_000.0
        }
    }

    #[ink(storage)]
    pub struct GeoFenceContract {
        value: bool,
    }

    impl GeoFenceContract {
        #[ink(constructor)]
        pub fn new(init_value: bool) -> Self {
            Self { value: init_value }
        }

        #[ink(constructor)]
        pub fn default() -> Self {
            Self::new(Default::default())
        }

        #[ink(message)]
        pub fn is_within_geofence(
            &self,
            geofence: Geofence3D,
            latitude: FixedPoint,
            longitude: FixedPoint,
            altitude: FixedPoint,
        ) -> bool {
            latitude.0 >= geofence.min_latitude.0 && latitude.0 <= geofence.max_latitude.0 &&
                longitude.0 >= geofence.min_longitude.0 && longitude.0 <= geofence.max_longitude.0 &&
                altitude.0 >= geofence.min_altitude.0 && altitude.0 <= geofence.max_altitude.0
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn test_within_geofence() {
            let contract = GeoFenceContract::new(false);
            let geofence = Geofence3D {
                min_latitude: FixedPoint::new(-10.0),
                max_latitude: FixedPoint::new(10.0),
                min_longitude: FixedPoint::new(-20.0),
                max_longitude: FixedPoint::new(20.0),
                min_altitude: FixedPoint::new(0.0),
                max_altitude: FixedPoint::new(100.0),
            };
            assert!(contract.is_within_geofence(geofence, FixedPoint::new(0.0), FixedPoint::new(0.0), FixedPoint::new(50.0)));
            assert!(!contract.is_within_geofence(geofence, FixedPoint::new(-15.0), FixedPoint::new(0.0), FixedPoint::new(50.0)));
            assert!(!contract.is_within_geofence(geofence, FixedPoint::new(0.0), FixedPoint::new(-25.0), FixedPoint::new(50.0)));
            assert!(!contract.is_within_geofence(geofence, FixedPoint::new(0.0), FixedPoint::new(0.0), FixedPoint::new(150.0)));
        }

        #[ink::test]
        fn test_within_20ft_cube() {
            let contract = GeoFenceContract::new(false);
            let geofence = Geofence3D {
                min_latitude: FixedPoint::new(0.0),
                max_latitude: FixedPoint::new(0.0061), // Approximately 20 feet in latitude
                min_longitude: FixedPoint::new(0.0),
                max_longitude: FixedPoint::new(0.0061), // Approximately 20 feet in longitude
                min_altitude: FixedPoint::new(0.0),
                max_altitude: FixedPoint::new(6.096), // 20 feet in altitude
            };
            assert!(contract.is_within_geofence(geofence, FixedPoint::new(0.003), FixedPoint::new(0.003), FixedPoint::new(3.0))); // Inside the cube
            assert!(!contract.is_within_geofence(geofence, FixedPoint::new(0.01), FixedPoint::new(0.003), FixedPoint::new(3.0))); // Outside latitude
            assert!(!contract.is_within_geofence(geofence, FixedPoint::new(0.003), FixedPoint::new(0.01), FixedPoint::new(3.0))); // Outside longitude
            assert!(!contract.is_within_geofence(geofence, FixedPoint::new(0.003), FixedPoint::new(0.003), FixedPoint::new(10.0))); // Outside altitude
        }
    }
}