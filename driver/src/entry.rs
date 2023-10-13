use crate::device;
use alloc::boxed::Box;
use wdk::allocator::NullAllocator;
use wdk::interface::{WdfObjectAttributes, WdfObjectContextTypeInfo};
use wdk::irp_helpers::{ReadRequest, WriteRequest};
use wdk::{err, info, interface};
use windows_sys::Wdk::Foundation::{DEVICE_OBJECT, DRIVER_OBJECT, IRP};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, STATUS_SUCCESS};

static mut DRIVER_CONFIG: WdfObjectContextTypeInfo =
    WdfObjectContextTypeInfo::default("DriverContext\0");

#[no_mangle]
pub extern "system" fn DriverEntry(
    driver_object: *mut windows_sys::Wdk::Foundation::DRIVER_OBJECT,
    registry_path: *mut windows_sys::Win32::Foundation::UNICODE_STRING,
) -> windows_sys::Win32::Foundation::NTSTATUS {
    info!("Starting initialization...");

    let mut object_attributes = WdfObjectAttributes::new();
    object_attributes.add_context::<device::Device>(unsafe { &mut DRIVER_CONFIG });
    object_attributes.set_cleanup_fn(device_cleanup);

    // Initialize driver object.
    let mut driver = match interface::init_driver_object(
        driver_object,
        registry_path,
        "PortmasterTest",
        object_attributes,
    ) {
        Ok(driver) => driver,
        Err(status) => {
            err!("driver_entry: failed to initialize driver: {}", status);
            return windows_sys::Win32::Foundation::STATUS_FAILED_DRIVER_ENTRY;
        }
    };

    // Set driver functions.
    driver.set_driver_unload(driver_unload);
    driver.set_read_fn(driver_read);
    driver.set_write_fn(driver_write);

    // Initialize device.
    if let Some(device_object) = driver.get_device_object_ref() {
        if let Ok(context) =
            interface::get_device_context_from_device_object::<device::Device>(device_object)
        {
            context.init(&driver);
        }
    }
    info!("Initialization complete");

    STATUS_SUCCESS
}

extern "C" fn device_cleanup(device: HANDLE) {
    let device_context =
        interface::get_device_context_from_wdf_device::<device::Device>(device, unsafe {
            &DRIVER_CONFIG
        });

    unsafe {
        // Call drop without freeing memory. Memory is manged by the kernel.
        if !device_context.is_null() {
            let mut owned_device_contex = Box::from_raw_in(device_context, NullAllocator {});
            owned_device_contex.cleanup();
            drop(owned_device_contex);
        }
    }
}

unsafe extern "system" fn driver_unload(_object: *const DRIVER_OBJECT) {
    info!("Unloading complete");
}

unsafe extern "system" fn driver_read(
    device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    let mut read_request = ReadRequest::new(irp);
    let Ok(device) =
        interface::get_device_context_from_device_object::<device::Device>(device_object)
    else {
        read_request.complete();
        return read_request.get_status();
    };

    device.read(&mut read_request);

    read_request.get_status()
}

unsafe extern "system" fn driver_write(
    device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    let mut write_request = WriteRequest::new(irp);
    let Ok(device) =
        interface::get_device_context_from_device_object::<device::Device>(device_object)
    else {
        write_request.complete();
        return write_request.get_status();
    };

    device.write(&mut write_request);

    write_request.mark_all_as_read();
    write_request.complete();
    write_request.get_status()
}

// fn driver_device_control(_driver_object: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
//     unsafe {
//         let buf = (*irp).AssociatedIrp.SystemBuffer;
//         let stack_location: *mut IO_STACK_LOCATION = (*irp)
//             .Tail
//             .Overlay
//             .Anonymous2
//             .Anonymous
//             .CurrentStackLocation;

//         let io_control_code = (*stack_location).Parameters.DeviceIoControl.IoControlCode;
//         if let Ok(code) = io_control_code.try_into() {
//             match code {
//                 IOCTL::Version => {
//                     let version_array = core::slice::from_raw_parts_mut(buf as *mut u8, 4);
//                     version_array[0] = 1;
//                     version_array[1] = 1;
//                     version_array[2] = 1;
//                     version_array[3] = 1;
//                     (*irp).IoStatus.Anonymous.Status = STATUS_SUCCESS;
//                     (*irp).IoStatus.Information = 4;
//                     return STATUS_SUCCESS;
//                 }
//                 IOCTL::ShutdownRequest => todo!(),
//                 IOCTL::RecvVerdictReq => todo!(),
//                 IOCTL::SetVerdict => todo!(),
//                 IOCTL::GetPayload => todo!(),
//                 IOCTL::ClearCache => todo!(),
//                 IOCTL::UpdateVerdict => todo!(),
//                 IOCTL::GetConnectionsStat => todo!(),
//             }
//         }
//     }
//     return STATUS_SUCCESS;
// }
