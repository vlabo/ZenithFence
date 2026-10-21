//! The device's user-space command channel must never panic.
//!
//! Runs the real driver code (mock/driver) over the mock WDK.

use driver::device::*;
use proptest::prelude::*;
use wdk::driver::Driver;
use wdk::irp_helpers::WriteRequest;

fn mock_device() -> Device {
    Device::new(&Driver::mock()).expect("mock device construction")
}

fn write(device: &mut Device, bytes: &[u8]) {
    let mut wr = WriteRequest::from_bytes(bytes);
    device.write(&mut wr);
}

// Regression for the two confirmed command-channel bugs: an empty buffer
// (used to panic on `bytes[0]`) and short command tails (used to OOB-read
// `size_of::<T>()` bytes in `as_type`). Must now be handled without panicking.
#[test]
fn device_write_handles_empty_and_short_commands() {
    let mut device = mock_device();
    write(&mut device, &[]);
    for cmd in 0u8..=8 {
        write(&mut device, &[cmd]);
        write(&mut device, &[cmd, 0]);
        write(&mut device, &[cmd, 0, 0, 0]);
    }
    for cmd in [9u8, 50, 200, 255] {
        write(&mut device, &[cmd, 1, 2, 3]);
    }
}

proptest! {
    // The user-space command channel must never panic on arbitrary input.
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn device_write_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..96)) {
        let mut device = mock_device();
        write(&mut device, &bytes);
    }
}
