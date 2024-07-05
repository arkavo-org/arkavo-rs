extern crate hex;
#[cfg(test)]
mod tests {
    use std::error::Error;

    use alloy_primitives::{Address, U256};
    use alloy_provider::ProviderBuilder;
    use alloy_sol_types::sol;

    use super::*;

    struct AlloyTests;

    impl AlloyTests {
        async fn test() -> Result<(), Box<dyn std::error::Error>> {
            sol! {
                #[sol(rpc)] // <-- Important! Generates the necessary `MyContract` struct and function methods.
                #[sol(bytecode = "0x1234")] // <-- Generates the `BYTECODE` static and the `deploy` method.
                contract MyContract {
                    constructor(address) {} // The `deploy` method will also include any constructor arguments.

                    #[derive(Debug)]
                    function doStuff(uint a, bool b) public payable returns(address c, bytes32 d);
                }
            }

            // Build a provider.
            let provider = ProviderBuilder::new().with_recommended_fillers().on_builtin("http://localhost:8545").await?;

            // If `#[sol(bytecode = "0x...")]` is provided, the contract can be deployed with `MyContract::deploy`,
            // and a new instance will be created.
            let constructor_arg = Address::ZERO;
            let contract = MyContract::deploy(&provider, constructor_arg).await?;

            // Otherwise, or if already deployed, a new contract instance can be created with `MyContract::new`.
            let address = Address::ZERO;
            let contract = MyContract::new(address, &provider);

            // Build a call to the `doStuff` function and configure it.
            let a = U256::from(123);
            let b = true;
            let call_builder = contract.doStuff(a, b).value(U256::from(50e18 as u64));

            // Send the call. Note that this is not broadcasted as a transaction.
            let call_return = call_builder.call().await?;
            println!("{call_return:?}"); // doStuffReturn { c: 0x..., d: 0x... }

            // Use `send` to broadcast the call as a transaction.
            let _pending_tx = call_builder.send().await?;
            Ok(())
        }
    }

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

    #[tokio::test]
    async fn run_tests() {
        let res = run_tests_inner().await;
        assert!(res.is_ok());
    }

    async fn run_tests_inner() -> Result<(), Box<dyn Error>> {
        AlloyTests::test().await;
        NanoTDFTests::setup()?;
        NanoTDFTests::test_spec_example_binary_parser()?;
        NanoTDFTests::test_spec_example_decrypt_payload()?;
        NanoTDFTests::test_no_signature_spec_example_binary_parser()?;
        NanoTDFTests::teardown()?;
        Ok(())
    }
}