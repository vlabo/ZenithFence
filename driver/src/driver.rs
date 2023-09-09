// use crate::filter_engine::FilterEngine;
use crate::types::PacketInfo;
use wdk::filter_engine::FilterEngine;
use wdk::utils::{Driver, ReadRequest, WriteRequest};
use wdk::{
    interface,
    ioqueue::{self, IOQueue},
    log,
};
use wdk_macro::{driver_entry, driver_read, driver_unload, driver_write};
use winapi::{
    km::wdm::{DEVICE_OBJECT, DRIVER_OBJECT, IRP},
    shared::ntdef::UNICODE_STRING,
};
use windows_sys::Win32::Foundation::NTSTATUS;

pub static FILTER_ENGINE: FilterEngine = FilterEngine::default();

pub static IO_QUEUE: IOQueue<PacketInfo> = IOQueue::default();

#[driver_entry(
    name = "PortmasterTest",
    read_fn = true,
    write_fn = true,
    ioctl_fn = false
)]
fn driver_entry(driver: Driver) {
    log!("Starting initialization...");

    IO_QUEUE.init();

    // Initialize filter engine.
    if let Err(err) = FILTER_ENGINE.init(driver) {
        log!("driver_entry: {}", err);
    }

    if let Err(err) = FILTER_ENGINE.commit() {
        log!("driver_entry: {}", err);
    }

    log!("Initialization complete");
}

#[driver_unload]
fn driver_unload() {
    log!("Starting driver unload");
    // Unregister filter engine.
    FILTER_ENGINE.deinit();
    log!("Unloading complete");
}

#[driver_read]
fn driver_read(mut read_request: ReadRequest) {
    // let max_count = read_request.free_space() / core::mem::size_of::<PacketInfo>();

    match IO_QUEUE.wait_and_pop() {
        Ok(packet) => {
            let _ = ciborium::into_writer(&packet, &mut read_request);

            log!("Send {} packets to the client", 1);
            read_request.complete();
            return;
        }
        Err(ioqueue::Status::Timeout) => {
            read_request.timeout();
            return;
        }
        Err(err) => {
            log!("failed to pop value: {}", err);
            read_request.complete();
            return;
        }
    }
}

#[driver_write]
fn driver_write(mut write_request: WriteRequest) {
    log!("Write request: {:?}", write_request.get_buffer());
    IO_QUEUE.rundown();
    write_request.mark_all_as_read();
    write_request.complete();
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
