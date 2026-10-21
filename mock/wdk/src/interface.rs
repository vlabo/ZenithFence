//! Host mock of `wdk::interface`. Just enough to let the driver's real
//! `DriverEntry` run: bind a [`Driver`] to the caller-provided `DRIVER_OBJECT`
//! so handler registration writes into it.

use crate::driver::Driver;
use crate::kernel_types::{DEVICE_OBJECT, DRIVER_OBJECT, UNICODE_STRING};

/// Mock of `wdk::ffi::WdfObjectAttributes`. The driver only ever passes a null
/// pointer for it, so the mock is an opaque stand-in to type the argument.
pub struct WdfObjectAttributes;

/// Mock of `wdk::interface::init_driver_object`.
///
/// The real version creates the WDF driver/device objects via FFI and returns a
/// `Driver` wrapping them. The mock has no WDF: it binds the `Driver` to the
/// caller-owned `DRIVER_OBJECT` (so the subsequent `set_*_fn` calls land in
/// `MajorFunction`) and creates the device object (the IoCreateDevice step),
/// which the filter engine requires for callout registration.
pub fn init_driver_object(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: *mut UNICODE_STRING,
    _driver_name: &str,
    _object_attributes: *mut WdfObjectAttributes,
) -> Result<Driver, String> {
    let Some(object) = (unsafe { driver_object.as_mut() }) else {
        return Err("init_driver_object: null driver object".into());
    };
    if object.DeviceObject.is_null() {
        object.DeviceObject = Box::into_raw(Box::new(DEVICE_OBJECT::new()));
    }
    Ok(Driver::from_driver_object(driver_object))
}
