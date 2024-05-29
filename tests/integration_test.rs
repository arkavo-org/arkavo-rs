extern crate crypto;
extern crate hex;
#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    struct NanoTDFTests;

    impl NanoTDFTests {
        fn setup() -> Result<(), Box<dyn Error>> {
            // Put setup code here.
            Ok(())
        }

        fn teardown() -> Result<(), Box<dyn Error>> {
            // Put teardown code here.
            Ok(())
        }

        fn test_spec_example_binary_parser() -> Result<(), Box<dyn Error>> {
            let hex_string = "\
                4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80\
                80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70\
                6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36\
                ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15\
                12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c\
                c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da";

            let bytes = hex::decode(hex_string.replace(" ", ""))?;
            println!("{:?}", bytes);
            Ok(())
        }

        fn test_spec_example_decrypt_payload() -> Result<(), Box<dyn Error>> {
            let encrypted_payload = "\
                4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80\
                80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70\
                6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36\
                ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15\
                12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c\
                c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da";

            let bytes = hex::decode(encrypted_payload.replace(" ", ""))?;
            // Add decryption logic here
            println!("{:?}", bytes);
            // Validate the decrypted payload
            Ok(())
        }

        fn test_no_signature_spec_example_binary_parser() -> Result<(), Box<dyn Error>> {
            let hex_string = "\
                4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80\
                80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70\
                6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36\
                ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15\
                12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c\
                c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da";

            let bytes = hex::decode(hex_string.replace(" ", ""))?;
            println!("{:?}", bytes);
            // Process bytes as needed without signature validation
            Ok(())
        }
    }

    #[test]
    fn run_tests() -> Result<(), Box<dyn Error>> {
        NanoTDFTests::setup()?;
        NanoTDFTests::test_spec_example_binary_parser()?;
        NanoTDFTests::test_spec_example_decrypt_payload()?;
        NanoTDFTests::test_no_signature_spec_example_binary_parser()?;
        NanoTDFTests::teardown()?;
        Ok(())
    }
}