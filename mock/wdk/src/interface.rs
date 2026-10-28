//! Host mock of `wdk::interface`. Just enough to let the driver's real
//! `DriverEntry` run: bind a [`Driver`] to the caller-provided `DRIVER_OBJECT`
//! so handler registration writes into it.

use crate::driver::Driver;
use crate::kernel_types::{DEVICE_OBJECT, DRIVER_OBJECT};

/// Mock of `wdk::interface::init_driver_object`.
///
/// The real version creates the device (IoCreateDeviceSecure) and its symbolic
/// link, and returns a `Driver` wrapping them. The mock has no object namespace:
/// it creates the device object in the caller-owned `DRIVER_OBJECT` (which the
/// filter engine requires for callout registration) and binds the `Driver` to it,
/// so the subsequent `set_*_fn` calls land in `MajorFunction`. Undo it with
/// [`delete_device`].
pub fn init_driver_object(
    driver_object: *mut DRIVER_OBJECT,
    _driver_name: &str,
) -> Result<Driver, String> {
    let Some(object) = (unsafe { driver_object.as_mut() }) else {
        return Err("init_driver_object: null driver object".into());
    };
    if object.DeviceObject.is_null() {
        object.DeviceObject = Box::into_raw(Box::new(DEVICE_OBJECT::new()));
    }
    Ok(Driver::from_driver_object(driver_object))
}

/// Mock of `wdk::interface::delete_device`: removes the device object
/// [`init_driver_object`] created (IoDeleteDevice), so a later use of it shows
/// up as a null device object, as in the kernel.
///
/// Like `IoDeleteDevice`, it changes the driver object it is handed, so the
/// pointer must come from one the caller may write (the loader passes its owned
/// `DRIVER_OBJECT`).
pub fn delete_device(driver_object: *const DRIVER_OBJECT, _driver_name: &str) {
    let Some(object) = (unsafe { (driver_object as *mut DRIVER_OBJECT).as_mut() }) else {
        return;
    };
    if !object.DeviceObject.is_null() {
        unsafe { drop(Box::from_raw(object.DeviceObject)) };
        object.DeviceObject = core::ptr::null_mut();
    }
}
