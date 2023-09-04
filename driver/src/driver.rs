use crate::filter_engine::FilterEngine;
use core::marker::PhantomData;
use data_types::PacketInfo;
use link_kit::{driver_entry, driver_read, driver_unload};
use wdk::utils::Driver;
use wdk::utils::ReadRequest;
use wdk::{interface, ioqueue::IOQueue, log};
use winapi::{
    km::wdm::{DEVICE_OBJECT, DRIVER_OBJECT, IRP},
    shared::ntdef::UNICODE_STRING,
};
use windows_sys::Win32::Foundation::NTSTATUS;

pub static mut FILTER_ENGINE: Option<FilterEngine> = None;
pub static mut IO_QUEUE: IOQueue<PacketInfo> = IOQueue::<PacketInfo> {
    kernel_queue: None,
    _type: PhantomData,
};

#[driver_entry(
    name = "PortmasterTest",
    read_fn = true,
    write_fn = false,
    ioctl_fn = false
)]
fn driver_entry(driver: Driver) {
    log!("Starting initialization...");

    unsafe {
        IO_QUEUE = IOQueue::new();
    }

    // Initialize filter engine.
    // let device_object = interface::wdf_device_wdm_get_device_object(device_handle);
    let mut filter_engine = match FilterEngine::new(driver) {
        Ok(engine) => engine,
        Err(err) => {
            log!("driver_entry: {}", err);
            return;
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
}

#[driver_unload]
fn driver_unload() {
    log!("Starting driver unload");
    unsafe {
        // Unregister filter engine.
        FILTER_ENGINE = None;
        IO_QUEUE.rundown();
    }
    log!("Unloading complete");
}

#[driver_read]
fn driver_read(mut read_request: ReadRequest) {
    let max_count = read_request.free_space() / core::mem::size_of::<PacketInfo>();

    unsafe {
        match IO_QUEUE.wait_and_pop() {
            Ok(packet) => {
                let mut count: usize = 1;
                let _ = read_request.write(packet);
                while count < max_count {
                    if let Ok(packet) = IO_QUEUE.pop() {
                        let _ = read_request.write(packet);
                        count += 1;
                    } else {
                        break;
                    }
                }

                log!("Send {} packets to the client", count);
            }
            Err(status) => {
                log!("failed to pop value: {:?}", status);
            }
        }
    }

    read_request.complete();
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
