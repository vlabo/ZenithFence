//! Loading and unloading through the real driver_entry / DriverUnload.
//!
//! Runs the real driver code (mock/driver) over the mock WDK.

use driver::entry::*;
use wdk::kernel_types::{
    DRIVER_OBJECT, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE, STATUS_SUCCESS, UNICODE_STRING,
};

// The real DriverEntry, run under the mock, installs a device in the global
// slot and registers the IRP dispatch handlers; the registered DriverUnload
// tears it back down and clears the slot.
#[test]
fn driver_entry_loads_device_and_registers_handlers() {
    let _g = driver_harness::loader::lock();

    let mut driver_object = DRIVER_OBJECT::new();
    let mut registry = UNICODE_STRING;
    let status = driver_entry(&mut driver_object, &mut registry);

    assert_eq!(status, STATUS_SUCCESS);
    assert!(get_device().is_some());
    assert!(driver_object.MajorFunction[IRP_MJ_READ].is_some());
    assert!(driver_object.MajorFunction[IRP_MJ_WRITE].is_some());
    assert!(driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL].is_some());
    let unload = driver_object.DriverUnload.expect("DriverUnload registered");

    // Tearing down via the registered unload frees the device and clears the
    // slot (so a stale pointer can't be dereferenced afterwards).
    unsafe { unload(&driver_object) };
    assert!(get_device().is_none());
}
