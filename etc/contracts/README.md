# Smart Contracts

WebAssembly smart-contracts
https://github.com/paritytech/polkadot-sdk/tree/master/substrate/frame/contracts

## Prerequisites

- ink!

```shell
cargo install cargo-contract
```

## Create !ink contract project

Tip: Open the project in another RustRover project

```shell
cargo contract new my_contract
```

## Compile contract from !ink to polkadot WASM

In contract directory

```shell
cargo contract build
```

## Test contract

In contract directory

```shell
cargo contract build --features e2e-tests
```

## Execute contract

### Run substrate node

```shell
./substrate-contracts-node -dev -lruntime=debug
```

### Deploy

#### Content Rating

```text
Code hash 0xcee0206b80f939ec9da4c69a62284e22e0fa05c98e0c7341deeb3a7e835ef261
Contract 5HKLo6CKbt1Z5dU4wZ3MiufeZzjM6JGwKUWUQ6a91fmuA6RB
```

#### Geofence

```text
Code hash 0x63a3ec45fd3ab905924a38227917e278de277c9b80d6865190d18d0d64f560bb
Contract 5H6sLwXKBv3cdm5VVRxrvA8p5cux2Rrni5CQ4GRyYKo4b9B4
```

#### Timestamp

```text
Code hash 0xee2250ba4215f273e571ecdfc2a373ccc96de5f82c19fcdaca889218fac5ac39
Contract 5D35jFeQboveKiaQSxyLKENGqrnjgUc7B4D23QbhJK4Yr7jT
```

```shell
cargo contract upload --url ws://127.0.0.1:9944 --suri //Alice content_rating/target/ink/content_rating.wasm
cargo contract instantiate --url ws://127.0.0.1:9944 --suri //Alice content_rating/target/ink/content_rating.wasm --execute
```

```shell
cargo contract upload --url ws://127.0.0.1:9944 --suri //Alice timestamp_validator/target/ink/timestamp_validator.wasm
cargo contract instantiate --url ws://127.0.0.1:9944 --suri //Alice timestamp_validator/target/ink/timestamp_validator.wasm --execute
```

```shell
cargo contract upload --url ws://127.0.0.1:9944 --suri //Alice geo_fence_contract/target/ink/geo_fence_contract.wasm
cargo contract instantiate --url ws://127.0.0.1:9944 --suri //Alice geo_fence_contract/target/ink/geo_fence_contract.wasm --execute
```

```shell
cargo contract upload --url ws://127.0.0.1:9944 --suri //Alice simple_abac/target/ink/simple_abac.wasm
cargo contract instantiate --url ws://127.0.0.1:9944 --suri //Alice simple_abac/target/ink/simple_abac.wasm --execute
```

### Execute

In contract directory

```shell
cargo contract call --url ws://127.0.0.1:9944 --suri //Alice --contract 5GnJAVumy3NBdo2u9ZEK1MQAXdiVnZWzzso4diP2JszVgSJQ --message check_access
```

Go to https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F127.0.0.1%3A9944#/contracts

## Approve and Rollout contract

```shell
cp simple_abac/lib.rs ../../src/contract_simple_abac.rs
```
