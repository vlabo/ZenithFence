use crate::filter_engine::FilterEngine;
use alloc::format;
use data_types::PacketInfo;

use wdk::{interface, ioqueue::IOQueue, log};
use winapi::{
    km::wdm::{IoGetCurrentIrpStackLocation, DEVICE_OBJECT, DRIVER_OBJECT, IRP, IRP_MJ},
    shared::ntdef::UNICODE_STRING,
};
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_FAILED_DRIVER_ENTRY, STATUS_SUCCESS};

pub const DRIVER_NAME: &str = "PortmasterTest";
pub static mut FILTER_ENGINE: Option<FilterEngine> = None;
pub static mut IO_QUEUE: IOQueue = IOQueue {
    kernel_queue: core::ptr::null_mut(),
};

#[no_mangle]
pub extern "system" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    registry_path: *mut UNICODE_STRING,
) -> NTSTATUS {
    log!("Starting initialization...");

    // Initialize driver object
    let (_driver_handle, device_handle) = match interface::init_driver_object(
        driver_object,
        registry_path,
        &format!("\\Device\\{}", DRIVER_NAME),
        &format!("\\??\\{}", DRIVER_NAME),
    ) {
        Ok((driver_handle, device_handle)) => (driver_handle, device_handle),
        Err(status) => {
            log!("driver_entry: failed to initialize driver: {}", status);
            return STATUS_FAILED_DRIVER_ENTRY;
        }
    };

    // Set unload function.
    unsafe {
        (*driver_object).DriverUnload = Some(driver_unload);
        (*driver_object).MajorFunction[IRP_MJ::READ as usize] = Some(driver_read);
    }

    unsafe {
        IO_QUEUE = IOQueue::new();
    }

    // Initialize filter engine.
    let device_object = interface::wdf_device_wdm_get_device_object(device_handle);
    let mut filter_engine = match FilterEngine::new(device_object) {
        Ok(engine) => engine,
        Err(err) => {
            log!("driver_entry: {}", err);
            return STATUS_FAILED_DRIVER_ENTRY;
        }
    };

    // Register test callouts.
    filter_engine.register_test_callout();
    if let Err(err) = filter_engine.commit() {
        log!("driver_entry: {}", err);
    } else {
        log!("callout registered");
    }

    // Move filter engine to global variable.
    unsafe {
        FILTER_ENGINE = Some(filter_engine);
    }

    log!("Initialization complete");
    return STATUS_SUCCESS;
}

extern "system" fn driver_unload(_self: &mut DRIVER_OBJECT) {
    log!("Starting driver unload");
    unsafe {
        // Unregister filter engine.
        FILTER_ENGINE = None;
        IO_QUEUE.rundown();
    }
    log!("Unloading complete");
}

unsafe extern "system" fn driver_read(
    _device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    let irp_sp = IoGetCurrentIrpStackLocation(irp);
    let device_io = (*irp_sp).Parameters.DeviceIoControl_mut();

    let system_buffer = irp.AssociatedIrp.SystemBuffer();
    let buffer = core::slice::from_raw_parts_mut(
        *system_buffer as *mut u8,
        device_io.OutputBufferLength as usize,
    );

    let max_count = device_io.OutputBufferLength as usize / core::mem::size_of::<PacketInfo>();

    match IO_QUEUE.wait_and_pop::<PacketInfo>() {
        Ok(packet) => {
            let mut count: usize = 1;
            let bytes = core::mem::transmute::<PacketInfo, [u8; core::mem::size_of::<PacketInfo>()]>(
                packet,
            );
            for i in 0..bytes.len() {
                buffer[i] = bytes[i];
            }

            while count < max_count {
                if let Ok(packet) = IO_QUEUE.pop() {
                    let bytes = core::mem::transmute::<
                        PacketInfo,
                        [u8; core::mem::size_of::<PacketInfo>()],
                    >(packet);
                    for i in 0..bytes.len() {
                        buffer[i] = bytes[i];
                    }
                    count += 1;
                } else {
                    break;
                }
            }

            irp.IoStatus.Information = core::mem::size_of::<PacketInfo>() * count;
            log!("Send {} packets to the client", count);
        }
        Err(status) => {
            log!("failed to pop value: {:?}", status);
            irp.IoStatus.Information = 0;
        }
    }

    let status = irp.IoStatus.__bindgen_anon_1.Status_mut();
    *status = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

#[no_mangle]
pub extern "system" fn _DllMainCRTStartup() {}

// fn init_driver_object(
//     driver_object: *mut DEVICE_OBJECT,
//     registry_path: PVOID,
//     driver: *mut HANDLE,
//     device: *mut HANDLE,
// ) {
//     let mut device_name = UNICODE_STRING {
//         Length: 0,
//         MaximumLength: 0,
//         Buffer: core::ptr::null_mut(),
//     };
//     let mut device_symlink = UNICODE_STRING {
//         Length: 0,
//         MaximumLength: 0,
//         Buffer: core::ptr::null_mut(),
//     };
//     unsafe {
//         let const_device_name: Vec<u16> = "TODO: set real device name".encode_utf16().collect();
//         RtlInitUnicodeString(&mut device_name, const_device_name.as_ptr());

//         let const_device_symlink: Vec<u16> =
//             "TODO: set real device symlink".encode_utf16().collect();
//         RtlInitUnicodeString(&mut device_symlink, const_device_symlink.as_ptr());
//     }
// }

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
