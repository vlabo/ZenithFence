#![no_main]
//! Full-driver simulation: load the real driver over the mocked WDK and drive it
//! through the user-space channel with a real producer thread (callouts) and a
//! real consumer thread (reads events, writes verdicts). See
//! driver_fuzz::targets::simulation. Run with ThreadSanitizer for race coverage
//! (`just fuzz-tsan simulation`) or ASAN (`just fuzz simulation`).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    driver_fuzz::targets::simulation(data);
});
