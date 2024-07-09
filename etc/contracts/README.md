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
