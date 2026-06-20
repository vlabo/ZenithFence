#![no_main]
//! Stateful ALE + packet-layer callout pipeline. See driver_fuzz::targets::callouts.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    driver_fuzz::targets::callouts(data);
});
