//! Shared fuzz-target bodies for the ZenithFence driver.
//!
//! Each `targets::<name>(data: &[u8])` contains the actual logic + oracles for
//! one fuzz target. The libFuzzer harnesses in `fuzz_targets/` and the
//! Windows-runnable `replay` binary both call these, so there is a single
//! source of truth and the same code is exercised on both platforms.

pub mod targets;
