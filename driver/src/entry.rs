use crate::array_holder::ArrayHolder;
use crate::protocol::{self, CommandUnion};
use crate::types::{Info, PacketInfo};
use alloc::vec;
use wdk::consts;
use wdk::filter_engine::callout::Callout;
use wdk::filter_engine::layer::Layer;
use wdk::filter_engine::FILTER_ENGINE;
use wdk::interface::WdfObjectContextTypeInfo;
use wdk::utils::ReadRequest;
use wdk::{
    err, info, interface,
    ioqueue::{self, IOQueue},
};
use windows_sys::Wdk::Foundation::{DEVICE_OBJECT, DRIVER_OBJECT, IRP};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, STATUS_SUCCESS};

// Global driver messaging queue.
pub static IO_QUEUE: IOQueue<Info> = IOQueue::default();
// static LEFTOVER_BUFFER: ArrayHolder = ArrayHolder::default();

#[repr(C)]
struct DeviceContext {
    _wdf_driver: HANDLE,
    read_leftover: ArrayHolder,
}

static mut DRIVER_CONFIG: WdfObjectContextTypeInfo =
    WdfObjectContextTypeInfo::default("DriverContext\0");

#[no_mangle]
pub extern "system" fn DriverEntry(
    driver_object: *mut windows_sys::Wdk::Foundation::DRIVER_OBJECT,
    registry_path: *mut windows_sys::Win32::Foundation::UNICODE_STRING,
) -> windows_sys::Win32::Foundation::NTSTATUS {
    info!("Starting initialization...");

    let driver_config = unsafe { &mut DRIVER_CONFIG };

    // Initialize driver object
    let mut driver = match interface::init_driver_object::<DeviceContext>(
        driver_object,
        registry_path,
        "PortmasterTest",
        driver_config,
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
    driver.set_create_fn(driver_create);
    driver.set_close_fn(driver_close);
    driver.set_close_fn(driver_clanup);

    // Init device context.
    // let driver_config = unsafe { &DRIVER_CONFIG };
    // let derivce_context = driver.get_device_context::<DeviceContext>(driver_config);
    // derivce_context.read_leftover = ArrayHolder::default();

    IO_QUEUE.init();

    // Initialize filter engine.
    if let Err(err) = FILTER_ENGINE.init(driver, 0xa87fb472_fc68_4805_8559_c6ae774773e0) {
        err!("{}", err);
    }

    let callouts = vec![Callout::new(
        "AleLayerOutbound",
        "A Test ALE layer for outbund connections",
        0x58545073_f893_454c_bbea_a57bc964f46d,
        Layer::FwpmLayerAleAuthConnectV4,
        consts::FWP_ACTION_CALLOUT_TERMINATING,
        |mut data| {
            let packet = PacketInfo::from_call_data(&data);
            // let _ = IO_QUEUE.push(Info::LogLine(format!("packet: {:?}", packet)));
            let _ = IO_QUEUE.push(Info::PacketInfo(packet));
            data.permit();
        },
    )];

    if let Err(err) = FILTER_ENGINE.commit(callouts) {
        err!("{}", err);
    }

    info!("Initialization complete");

    STATUS_SUCCESS
}

unsafe extern "system" fn driver_unload(_object: *const DRIVER_OBJECT) {
    info!("Starting driver unload");
    FILTER_ENGINE.deinit();
    IO_QUEUE.deinit();

    // Clear buffer
    info!("Unloading complete");
}

unsafe extern "system" fn driver_create(
    device_object: &mut DEVICE_OBJECT,
    _irp: &mut IRP,
) -> NTSTATUS {
    let Ok(device_context) =
        interface::get_device_context_from_device_object::<DeviceContext>(device_object)
    else {
        return STATUS_SUCCESS;
    };

    device_context.read_leftover = ArrayHolder::default();

    crate::info!("Device create");
    STATUS_SUCCESS
}

unsafe extern "system" fn driver_close(
    device_object: &mut DEVICE_OBJECT,
    _irp: &mut IRP,
) -> NTSTATUS {
    IO_QUEUE.rundown();

    let Ok(device_context) =
        interface::get_device_context_from_device_object::<DeviceContext>(device_object)
    else {
        return STATUS_SUCCESS;
    };

    // Clear buffer
    device_context.read_leftover.load();

    STATUS_SUCCESS
}

unsafe extern "system" fn driver_clanup(
    _device_object: &mut DEVICE_OBJECT,
    _irp: &mut IRP,
) -> NTSTATUS {
    info!("Cleanup");
    IO_QUEUE.rundown();
    STATUS_SUCCESS
}

fn write_to_request(read_request: &mut ReadRequest, device_context: &DeviceContext, data: &[u8]) {
    let command_size = data.len();
    let count = read_request.write(data);

    // Check if full command was written
    if count < command_size {
        // Save the leftovers for later.
        device_context.read_leftover.save(&data[count..]);
    }
}

unsafe extern "system" fn driver_read(
    device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    let mut read_request = wdk::utils::ReadRequest::new(irp);
    let Ok(device_context) =
        interface::get_device_context_from_device_object::<DeviceContext>(device_object)
    else {
        read_request.complete();
        return read_request.get_status();
    };

    if let Some(data) = device_context.read_leftover.load() {
        write_to_request(&mut read_request, device_context, &data);
        read_request.complete();
        return read_request.get_status();
    }

    // Check if there is enough left space (at least 4 bytes for the size of the next struct)
    if read_request.free_space() < 4 {
        read_request.complete();
        return read_request.get_status();
    }

    match IO_QUEUE.wait_and_pop() {
        Ok(info) => {
            protocol::serialize_info(info, |data| {
                let size = (data.len() as u32).to_le_bytes();
                let _ = read_request.write(&size);
                write_to_request(&mut read_request, device_context, data);
            });

            while read_request.free_space() > 4 {
                if let Ok(info) = IO_QUEUE.pop() {
                    protocol::serialize_info(info, |data| {
                        let size = (data.len() as u32).to_le_bytes();
                        let _ = read_request.write(&size);
                        write_to_request(&mut read_request, device_context, data);
                    });
                } else {
                    break;
                }
            }

            read_request.complete();
        }
        Err(ioqueue::Status::Timeout) => read_request.timeout(),
        Err(err) => {
            err!("failed to pop value: {}", err);
            read_request.end_of_file();
        }
    }

    read_request.get_status()
}

unsafe extern "system" fn driver_write(
    _device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    let mut write_request = wdk::utils::WriteRequest::new(irp);
    info!("Write buffer: {:?}", write_request.get_buffer());
    if let Some(command) = protocol::read_command(write_request.get_buffer()) {
        match command {
            CommandUnion::Shutdown => {
                IO_QUEUE.rundown();
            }
            CommandUnion::Response => {
                info!("Verdict response");
            }
            _ => {
                err!("unrecognized command");
            }
        }
    } else {
        err!("Faield to read command");
    }
    write_request.mark_all_as_read();
    write_request.complete();
    write_request.get_status()
}

#[no_mangle]
pub extern "system" fn _DllMainCRTStartup() {}

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

#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)*) => ({
        let message = alloc::format!($($arg)*);
        _ = IO_QUEUE.push(Info::LogLine(alloc::format!("{} {}: {}", $level, core::module_path!(), message)))
    });
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => ($crate::log!("ERROR", $($arg)*));
}

#[macro_export]
macro_rules! dbg {
    ($($arg:tt)*) => ($crate::log!("DEBUG", $($arg)*));
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ($crate::log!("INFO", $($arg)*));
}
