#![no_main]
//! Redirect + checksum mutators. See driver_fuzz::targets::packet_redirect.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    driver_fuzz::targets::packet_redirect(data);
});
