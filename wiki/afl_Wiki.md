# SigmaOS-afl Component Wiki

## Overview
SigmaOS-afl provides American Fuzzy Lop (AFL) fuzzing support for the SigmaOS operating system. It demonstrates the security fuzzing subsystem and automated testing within the SigmaOS ecosystem, following the principles of clear abstraction and deterministic fuzzing initialization.

## Principles
- Single Responsibility
- Fuzzing Abstraction
- Fail-Fast on Fuzzing Initialization Errors
- Deterministic Fuzzing Setup
- Clear Abstraction Over Fuzzing APIs
- Composition over Inheritance for fuzzing extensions

## Architecture
SigmaOS-afl follows a fuzzing pattern:
- **Fuzzing Core**: Provides mutation-based fuzzing, coverage tracking, and crash detection
- **Target Integration**: Supports binary target fuzzing, library coverage, and seed management
- **Result Analysis**: Supports crash reporting, coverage maps, and performance metrics
- **Error Handling**: Fail-fast on invalid fuzzing configurations or unsupported architectures

## API
The component provides the following public APIs:
- `fuzz::target::add(path)` - Add a binary target for fuzzing
- `fuzz::run::start(duration)` - Start fuzzing campaign for given duration
- `fuzz::crashes::list()` - List detected crashes and coverage artifacts
- `fuzz::seed::manage(seeds)` - Manage fuzzing seed corpus
- Error types for fuzzing failure scenarios or unsupported architectures

## Test Structure (Arrange-Act-ASSERT)
All tests follow the AAA pattern:
1. **Arrange**: Set up test environment with specific fuzzing configuration
2. **Act**: Execute the code under test (target addition, fuzzing start)
3. **Assert**: Verify the expected fuzzing results

Example:
```rust
#[test]
fn test_fuzz_target_aaa() {
    // Arrange
    let target_path = "/binaries/test-vulnerable";
    
    // Act
    let result = fuzz::target::add(target_path);
    
    // Assert
    assert!(result.is_ok());
    assert!(fuzz::target::is_queued(target_path));
}
```

## Development
- Follows Rust best practices with `#![forbid(unsafe_code)]`
- Fuzzing initialization is best-effort; gracefully degrades on unsupported architectures
- Comprehensive error types for all fuzzing failure scenarios
- Unit tests provided for target management and fuzzing control
- Integration tests for full fuzzing subsystem with actual binary targets

## TODO
- Add support for additional fuzzing engines (LibFuzzer, honggfuzzer)
- Expand target integration (Docker targets, remote fuzzing, cloud integration)
- Add coverage analysis features (edge coverage, path coverage, mutation scheduling)
- Create integration tests with actual vulnerable binaries and crash detection
- Implement fuzzing campaign management and automatic restart features