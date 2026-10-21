#![no_main]
//! Multithreaded ALE + packet-layer callout stress: many worker threads drive
//! the callouts against one shared device at the same time. See
//! driver_fuzz::targets::callouts_mt. Best run with ThreadSanitizer
//! (`just fuzz-tsan callouts_mt`).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    driver_fuzz::targets::callouts_mt(data);
});
