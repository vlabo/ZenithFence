#![no_main]
//! Command wire-format parsers. See driver_fuzz::targets::protocol_command.
//! Seed corpus: kext_interface/go_command_test.bin.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    driver_fuzz::targets::protocol_command(data);
});
