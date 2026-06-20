#![no_main]
//! IPv6 5-tuple extractor. See driver_fuzz::targets::packet_key_v6.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    driver_fuzz::targets::packet_key_v6(data);
});
