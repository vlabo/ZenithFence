#![no_main]
//! IPv4 5-tuple extractor. See driver_fuzz::targets::packet_key_v4.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    driver_fuzz::targets::packet_key_v4(data);
});
