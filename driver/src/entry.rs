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

static VERSION: [u8; 4] = include!("../../kext_interface/version.txt");

// Global device pointer. `get_device` hands out a shared `&'static` so callout
// and read/write threads can share one device soundly (every `Device` field is
// interior-mutable).
static mut DEVICE: *mut device::Device = core::ptr::null_mut();
pub fn get_device() -> Option<&'static device::Device> {
    return unsafe { DEVICE.as_ref() };
}

// Entry point of the driver (main function). Called when the driver is loaded.
// The production build root (kernel/src/lib.rs) exports it as the `DriverEntry`
// symbol. The kernel types come through `wdk::kernel_types`, so this plumbing
// does not depend on `windows_sys` directly.
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

    // Initialize device.
    unsafe {
        let device = match device::Device::new(&driver) {
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
unsafe extern "system" fn driver_unload(_object: *const DRIVER_OBJECT) {
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
