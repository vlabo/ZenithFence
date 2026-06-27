//! Host mock of `wdk::interface`. Just enough to let the driver's real
//! `DriverEntry` run: bind a [`Driver`] to the caller-provided `DRIVER_OBJECT`
//! so handler registration writes into it.

use crate::driver::Driver;
use crate::kernel_types::{DRIVER_OBJECT, UNICODE_STRING};

/// Mock of `wdk::ffi::WdfObjectAttributes`. The driver only ever passes a null
/// pointer for it, so the mock is an opaque stand-in to type the argument.
pub struct WdfObjectAttributes;

/// Mock of `wdk::interface::init_driver_object`.
///
/// The real version creates the WDF driver/device objects via FFI and returns a
/// `Driver` wrapping them. The mock has no WDF: it simply binds the `Driver` to
/// the caller-owned `DRIVER_OBJECT` (the simulation owns the `DEVICE_OBJECT`
/// separately, on the connection side), so the subsequent `set_*_fn` calls land
/// in `MajorFunction`.
pub fn init_driver_object(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: *mut UNICODE_STRING,
    _driver_name: &str,
    _object_attributes: *mut WdfObjectAttributes,
) -> Result<Driver, String> {
    if driver_object.is_null() {
        return Err("init_driver_object: null driver object".into());
    }
    Ok(Driver::from_driver_object(driver_object))
}
