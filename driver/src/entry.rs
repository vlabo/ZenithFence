use crate::common::ControlCode;
use crate::device;
use alloc::boxed::Box;
use num_traits::FromPrimitive;
use wdk::irp_helpers::{DeviceControlRequest, ReadRequest, WriteRequest};
use wdk::{err, info, interface};
use windows_sys::Wdk::Foundation::{DEVICE_OBJECT, DRIVER_OBJECT, IRP};
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};

static VERSION: [u8; 4] = include!("../../kext_interface/version.txt");

// Name of the device user space opens (`\\.\ZenithFence`).
const DRIVER_NAME: &str = "ZenithFence";

// Global device pointer. `get_device` hands out a shared `&'static` so callout
// and read/write threads can share one device soundly (every `Device` field is
// interior-mutable).
static mut DEVICE: *mut device::Device = core::ptr::null_mut();
pub fn get_device() -> Option<&'static device::Device> {
    return unsafe { DEVICE.as_ref() };
}

// DriverEntry is the entry point of the driver (main function). Will be called when driver is loaded.
// Name should not be changed
#[export_name = "DriverEntry"]
pub extern "system" fn driver_entry(
    driver_object: *mut windows_sys::Wdk::Foundation::DRIVER_OBJECT,
    _registry_path: *mut windows_sys::Win32::Foundation::UNICODE_STRING,
) -> windows_sys::Win32::Foundation::NTSTATUS {
    info!("Starting initialization...");

    // Create the device user space opens.
    let mut driver = match interface::init_driver_object(driver_object, DRIVER_NAME) {
        Ok(driver) => driver,
        Err(status) => {
            err!("driver_entry: failed to initialize driver: {}", status);
            return windows_sys::Win32::Foundation::STATUS_FAILED_DRIVER_ENTRY;
        }
    };

    // Set driver functions. Every request type user space sends needs a handler: the I/O manager
    // rejects the ones without.
    driver.set_driver_unload(driver_unload);
    driver.set_create_fn(driver_open_close);
    driver.set_cleanup_fn(driver_open_close);
    driver.set_close_fn(driver_open_close);
    driver.set_read_fn(driver_read);
    driver.set_write_fn(driver_write);
    driver.set_device_control_fn(device_control);

    // Initialize device.
    unsafe {
        let device = match device::Device::new(&driver) {
            Ok(device) => Box::new(device),
            Err(err) => {
                wdk::err!("filed to initialize device: {}", err);
                // The unload routine is not called when DriverEntry fails, so undo it here.
                interface::delete_device(driver_object, DRIVER_NAME);
                return windows_sys::Win32::Foundation::STATUS_FAILED_DRIVER_ENTRY;
            }
        };
        DEVICE = Box::into_raw(device);
    }

    STATUS_SUCCESS
}

// driver_unload function is called when service delete is called from user-space.
unsafe extern "system" fn driver_unload(object: *const DRIVER_OBJECT) {
    info!("Unloading complete");
    unsafe {
        if !DEVICE.is_null() {
            // Dropping the device completes every pending operation and unregisters the callouts,
            // so no callout can still be running once this returns. Only then is it safe to clear
            // the pointer the callouts read through.
            _ = Box::from_raw(DEVICE);
            DEVICE = core::ptr::null_mut();
        }
    }
    // The callouts were registered on the device object, so it goes last.
    interface::delete_device(object, DRIVER_NAME);
}

/// Opening, cleaning up and closing a handle need no work from the driver; they only have to succeed.
unsafe extern "system" fn driver_open_close(
    _device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    wdk::irp_helpers::complete_empty(irp)
}

// driver_read event triggered from user-space on file.Read.
unsafe extern "system" fn driver_read(
    _device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
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
    if get_device().is_none() {
        return control_request.complete();
    }

    let Some(control_code): Option<ControlCode> =
        FromPrimitive::from_u32(control_request.get_control_code())
    else {
        wdk::info!("Unknown IOCTL code: {}", control_request.get_control_code());
        return control_request.not_implemented();
    };

    wdk::info!("IOCTL: {}", control_code);

    match control_code {
        ControlCode::Version => {
            control_request.write(&VERSION);
        }
    };

    // Completing hands the IRP back to the I/O manager; the status comes from the call, not the IRP.
    control_request.complete()
}
