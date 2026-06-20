#![no_main]
//! User-space command channel. See driver_fuzz::targets::device_write.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    driver_fuzz::targets::device_write(data);
});
