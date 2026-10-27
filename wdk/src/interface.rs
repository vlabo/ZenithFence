use crate::{
    alloc::borrow::ToOwned,
    driver::Driver,
    ffi::{WdmlibIoCreateDeviceSecure, SDDL_DEVOBJ_SYS_ALL_ADM_ALL},
    utils::check_ntstatus,
};
use alloc::ffi::CString;
use alloc::format;
use alloc::string::String;
use widestring::U16CString;
use windows_sys::{
    core::GUID,
    Wdk::{
        Foundation::{DEVICE_OBJECT, DRIVER_OBJECT},
        Storage::FileSystem::DO_BUFFERED_IO,
        System::SystemServices::{
            DbgPrintEx, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
            FILE_DEVICE_SECURE_OPEN,
        },
    },
    Win32::Foundation::UNICODE_STRING,
};

/// Device type FILE_DEVICE_NETWORK (winioctl.h).
const FILE_DEVICE_NETWORK: u32 = 0x12;

/// GUID_DEVCLASS_NET (devguid.h). IoCreateDeviceSecure looks up administrator overrides of the
/// default security descriptor under this device class.
const GUID_DEVCLASS_NET: GUID = GUID::from_u128(0x4d36e972_e325_11ce_bfc1_08002be10318);

// Debug
pub fn dbg_print(str: String) {
    if let Ok(c_str) = CString::new(str) {
        const DPFLTR_IHVDRIVER_ID: u32 = 77;
        unsafe {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, c_str.as_ptr() as _);
        }
    }
}

/// Creates the driver's device (`\Device\<driver_name>`) and the symbolic link user space opens it
/// by (`\\.\<driver_name>`). Only the system and administrators can open it.
///
/// Call it from DriverEntry. The device stays in its initializing state until DriverEntry returns
/// (the I/O manager clears DO_DEVICE_INITIALIZING then), so no request reaches it before the
/// driver has finished setting up. Undo it with `delete_device`, also when DriverEntry fails later.
pub fn init_driver_object(
    driver_object: *mut DRIVER_OBJECT,
    driver_name: &str,
) -> Result<Driver, String> {
    let (device_name, link_name) = device_names(driver_name)?;
    let device_name = as_unicode_string(&device_name);
    let link_name = as_unicode_string(&link_name);

    let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
    unsafe {
        let status = WdmlibIoCreateDeviceSecure(
            driver_object,
            0, // No device extension: the driver keeps its state in a global.
            &device_name,
            FILE_DEVICE_NETWORK,
            FILE_DEVICE_SECURE_OPEN,
            0, // Not exclusive: more than one handle can be open.
            &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
            &GUID_DEVCLASS_NET,
            &mut device_object,
        );
        check_ntstatus(status)?;

        // Read, write and device control requests carry their data in AssociatedIrp.SystemBuffer
        // (see irp_helpers), which the I/O manager only provides for buffered I/O.
        (*device_object).Flags |= DO_BUFFERED_IO;

        let status = IoCreateSymbolicLink(&link_name, &device_name);
        if let Err(err) = check_ntstatus(status) {
            IoDeleteDevice(device_object);
            return Err(err);
        }
    }

    return Ok(Driver::new(driver_object, device_object));
}

/// Removes what `init_driver_object` created: the symbolic link and the device.
///
/// Call it from the unload routine, once nothing uses the device object any more (the callouts
/// registered on it are unregistered), or when DriverEntry fails after `init_driver_object`.
pub fn delete_device(driver_object: *const DRIVER_OBJECT, driver_name: &str) {
    if let Ok((_, link_name)) = device_names(driver_name) {
        unsafe {
            _ = IoDeleteSymbolicLink(&as_unicode_string(&link_name));
        }
    }

    // The driver creates a single device, so it is the only one on the driver object.
    unsafe {
        if let Some(driver) = driver_object.as_ref() {
            if !driver.DeviceObject.is_null() {
                IoDeleteDevice(driver.DeviceObject);
            }
        }
    }
}

/// The device name (`\Device\<driver_name>`) and the symbolic link name (`\??\<driver_name>`).
fn device_names(driver_name: &str) -> Result<(U16CString, U16CString), String> {
    let Ok(device_name) = U16CString::from_str(format!("\\Device\\{}", driver_name)) else {
        return Err("Invalid argument driver_name".to_owned());
    };
    let Ok(link_name) = U16CString::from_str(format!("\\??\\{}", driver_name)) else {
        return Err("Invalid argument driver_name".to_owned());
    };
    return Ok((device_name, link_name));
}

/// Borrows `string` as a UNICODE_STRING. The result points into `string`, so it must not outlive it.
fn as_unicode_string(string: &U16CString) -> UNICODE_STRING {
    let length = (string.len() * 2) as u16; // In bytes, without the terminating null.
    return UNICODE_STRING {
        Length: length,
        MaximumLength: length + 2,
        Buffer: string.as_ptr() as *mut u16,
    };
}
