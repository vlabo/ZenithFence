use crate::common::ControlCode;
use crate::device;
use alloc::boxed::Box;
use num_traits::FromPrimitive;
use wdk::irp_helpers::{DeviceControlRequest, ReadRequest, WriteRequest};
use wdk::kernel_types::{
    DEVICE_OBJECT, DRIVER_OBJECT, IRP, NTSTATUS, STATUS_FAILED_DRIVER_ENTRY, STATUS_SUCCESS,
    UNICODE_STRING,
};
use wdk::{err, info, interface};

// Global device pointer. Available in all build configurations: the packet
// callouts reach the device through `get_device()`, the host fuzz harness
// installs a mock `Device` here, and the full-driver simulation installs one via
// the real `driver_entry` below. `get_device` hands out a shared `&'static` so
// producer (callout) and consumer (read) threads can share one device soundly.
static mut DEVICE: *mut device::Device = core::ptr::null_mut();

pub fn get_device() -> Option<&'static device::Device> {
    return unsafe { DEVICE.as_ref() };
}

/// Test/fuzz helper: install a device pointer as the global device. The caller
/// owns the allocation (typically `Box::into_raw`) and must clear it with
/// `clear_device` afterwards. Not compiled into production.
#[cfg(any(test, feature = "mock"))]
pub fn set_device(device: *mut device::Device) {
    unsafe { DEVICE = device };
}

/// Test/fuzz helper: detach and return the current global device pointer.
#[cfg(any(test, feature = "mock"))]
pub fn clear_device() -> *mut device::Device {
    unsafe {
        let ptr = DEVICE;
        DEVICE = core::ptr::null_mut();
        ptr
    }
}

/// Serializes tests that install a `Device` into the global slot, which is a
/// process-wide singleton. Any test (in any module) that calls `driver_entry`,
/// `set_device`, or otherwise touches the slot must hold this for its duration.
#[cfg(any(test, feature = "mock"))]
pub static DEVICE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

static VERSION: [u8; 4] = include!("../../kext_interface/version.txt");

// The real WDM/WFP driver entry plumbing. It is now build-agnostic: under the
// host mock the kernel types resolve to `mock_wdk` stand-ins, so the full-driver
// simulation drives this exact code (DriverEntry + the IRP dispatch handlers)
// instead of a parallel re-implementation. Only the exported `DriverEntry`
// symbol is real-build specific.

// DriverEntry is the entry point of the driver (main function). Will be called
// when the driver is loaded. The exported name must not change.
#[cfg_attr(not(feature = "mock"), export_name = "DriverEntry")]
pub extern "system" fn driver_entry(
    driver_object: *mut DRIVER_OBJECT,
    registry_path: *mut UNICODE_STRING,
) -> NTSTATUS {
    info!("Starting initialization...");

    // Initialize driver object.
    let mut driver = match interface::init_driver_object(
        driver_object,
        registry_path,
        "ZenithFence",
        core::ptr::null_mut(),
    ) {
        Ok(driver) => driver,
        Err(status) => {
            err!("driver_entry: failed to initialize driver: {}", status);
            return STATUS_FAILED_DRIVER_ENTRY;
        }
    };

    // Set driver functions.
    driver.set_driver_unload(driver_unload);
    driver.set_read_fn(driver_read);
    driver.set_write_fn(driver_write);
    driver.set_device_control_fn(device_control);

    // Initialize device. Reads block until an event is available (or the queue is
    // run down): on the real kernel the queue always blocks; under the mock this
    // makes a user-space reader thread block on `Device::read` like the real
    // driver. The synchronous fuzz path uses `Device::new` (non-blocking) instead.
    unsafe {
        let device = match device::Device::new_with_blocking_reads(&driver, true) {
            Ok(device) => Box::new(device),
            Err(err) => {
                wdk::err!("filed to initialize device: {}", err);
                return STATUS_FAILED_DRIVER_ENTRY;
            }
        };
        DEVICE = Box::into_raw(device);
    }

    STATUS_SUCCESS
}

// driver_unload function is called when service delete is called from user-space.
pub(crate) unsafe extern "system" fn driver_unload(_object: *const DRIVER_OBJECT) {
    info!("Unloading complete");
    unsafe {
        if !DEVICE.is_null() {
            _ = Box::from_raw(DEVICE);
            // Null the slot so a late dispatch (or a subsequent load in the same
            // process, as the simulation/tests do) can't use-after-free.
            DEVICE = core::ptr::null_mut();
        }
    }
}

// driver_read event triggered from user-space on file.Read.
unsafe extern "system" fn driver_read(_device_object: &mut DEVICE_OBJECT, irp: &mut IRP) -> NTSTATUS {
    let mut read_request = ReadRequest::new(irp);
    let Some(device) = get_device() else {
        read_request.complete();

        return read_request.get_status();
    };

    device.read(&mut read_request);
    read_request.get_status()
}

/// driver_write event triggered from user-space on file.Write.
unsafe extern "system" fn driver_write(
    _device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    let mut write_request = WriteRequest::new(irp);
    let Some(device) = get_device() else {
        write_request.complete();
        return write_request.get_status();
    };

    device.write(&mut write_request);

    write_request.mark_all_as_read();
    write_request.complete();
    write_request.get_status()
}

/// device_control event triggered from user-space on file.deviceIOControl.
unsafe extern "system" fn device_control(
    _device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    let mut control_request = DeviceControlRequest::new(irp);
    let Some(device) = get_device() else {
        control_request.complete();
        return control_request.get_status();
    };

    let Some(control_code): Option<ControlCode> =
        FromPrimitive::from_u32(control_request.get_control_code())
    else {
        wdk::info!("Unknown IOCTL code: {}", control_request.get_control_code());
        control_request.not_implemented();
        return control_request.get_status();
    };

    wdk::info!("IOCTL: {}", control_code);

    match control_code {
        ControlCode::Version => {
            control_request.write(&VERSION);
        }
        ControlCode::ShutdownRequest => device.shutdown(),
    };

    control_request.complete();
    control_request.get_status()
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use wdk::kernel_types::{
        DRIVER_OBJECT, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE, UNICODE_STRING,
    };

    // The real DriverEntry, run under the mock, installs a device in the global
    // slot and registers the IRP dispatch handlers; the registered DriverUnload
    // tears it back down and clears the slot.
    #[test]
    fn driver_entry_loads_device_and_registers_handlers() {
        let _g = DEVICE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

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
}
