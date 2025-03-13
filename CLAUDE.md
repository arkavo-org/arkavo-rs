# Arkavo Rust Codebase Guide

## Build Commands
- Build: `cargo build`
- Release build: `RUSTFLAGS="-C target-cpu=native" cargo build --release`
- Run: `cargo run`
- Tests: `cargo test`
- Single test: `cargo test -- test_name`
- Benchmarks: `cargo bench`

## Style Guidelines
- **Formatting**: Follow standard Rust formatting with 4-space indentation
- **Imports**: Group standard library imports first, then third-party crates, then internal modules
- **Error Handling**: Use Result<T, E> with custom error types that implement Error and Display traits
- **Naming**: Use snake_case for variables/functions, CamelCase for types/structs, SCREAMING_SNAKE_CASE for constants
- **Types**: Use Rust's strong type system, document complex types with comments
- **Documentation**: Public APIs should have doc comments (///)

## Project Structure
- `/src` - Core library code (nanotdf library)
- `/src/bin` - Binary executables and contract implementations
- `/tests` - Integration tests
- `/benches` - Performance benchmarks
- `/etc/contracts` - Smart contract implementations

## Prerequisites
- Rust 1.83.0+
- NATS server and Redis for development