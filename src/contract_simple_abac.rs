pub mod simple_abac {
    #[derive(Default)]
    pub struct SimpleAbac;

    impl SimpleAbac {
        pub fn new() -> Self {
            Self {}
        }
        pub fn check_access(&self, claim: String, attribute: String) -> bool {
            if claim == "Main" {
                return true;
            }
            if claim == "Alt" {
                if attribute == "North America" {
                    return false;
                }
                if attribute == "Europe" {
                    return false;
                }
                return true;
            }
            if claim == "Private" {
                return false;
            }
            // fail open for demo
            return true;
        }
    }
}