use core::cell::UnsafeCell;

use crate::protocol::{self, CommandUnion};
use crate::types::{Info, PacketInfo};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use wdk::consts;
use wdk::filter_engine::callout::Callout;
use wdk::filter_engine::layer::Layer;
use wdk::filter_engine::FILTER_ENGINE;
use wdk::utils::{Driver, ReadRequest, WriteRequest};
use wdk::{
    err, info, interface,
    ioqueue::{self, IOQueue},
};
use wdk_macro::{driver_entry, driver_read, driver_unload, driver_write};

// Global driver messaging queue.
pub static IO_QUEUE: IOQueue<Info> = IOQueue::default();

struct UnsafeBuffer(UnsafeCell<Option<Vec<u8>>>);
unsafe impl Sync for UnsafeBuffer {}

impl UnsafeBuffer {
    fn save(&self, data: &[u8]) {
        unsafe {
            _ = (*self.0.get()).replace(data.to_vec());
        }
    }

    fn load(&self) -> Option<Vec<u8>> {
        unsafe { (*self.0.get()).take() }
    }
}

static LEFTOVER_BUFFER: UnsafeBuffer = UnsafeBuffer(UnsafeCell::new(None));

#[driver_entry(
    name = "PortmasterTest",
    read_fn = true,
    write_fn = true,
    ioctl_fn = false
)]
fn driver_entry(driver: Driver) {
    crate::info!("Starting initialization...");

    IO_QUEUE.init();

    // Initialize filter engine.
    if let Err(err) = FILTER_ENGINE.init(driver, 0xa87fb472_fc68_4805_8559_c6ae774773e0) {
        crate::err!("{}", err);
    }

    let callouts = vec![
        // Callout::new(
        //     "TestCalloutInbound",
        //     "Testing callout",
        //     0x6f996fe2_3a8f_43be_b578_e01480f2b1a1,
        //     Layer::FwpmLayerAleAuthRecvAcceptV4,
        //     consts::FWP_ACTION_CALLOUT_TERMINATING,
        //     |mut data| {
        //         // let packet = PacketInfo::from_call_data(&data);
        //         // info!("packet: {:?}", packet);
        //         // let _ = IO_QUEUE.push(packet);

        //         data.block();
        //     },
        // ),
        Callout::new(
            "AleLayerOutbound",
            "A Test ALE layer for outbund connections",
            0x58545073_f893_454c_bbea_a57bc964f46d,
            Layer::FwpmLayerAleAuthConnectV4,
            consts::FWP_ACTION_CALLOUT_TERMINATING,
            |mut data| {
                let packet = PacketInfo::from_call_data(&data);
                let _ = IO_QUEUE.push(Info::LogLine(format!("packet: {:?}", packet)));
                let _ = IO_QUEUE.push(Info::PacketInfo(packet));
                data.permit();
            },
        ),
    ];

    if let Err(err) = FILTER_ENGINE.commit(callouts) {
        crate::err!("{}", err);
    }

    crate::info!("Initialization complete");
}

#[driver_unload]
fn driver_unload() {
    info!("Starting driver unload");
    FILTER_ENGINE.deinit();
    IO_QUEUE.deinit();
    info!("Unloading complete");
}

fn write_to_request(read_request: &mut ReadRequest, data: &[u8]) {
    let command_size = data.len();
    let count = read_request.write(data);

    // Check if full command was written
    if count < command_size {
        // Save the leftovers for later.
        LEFTOVER_BUFFER.save(&data[count..]);
    }
}

#[driver_read]
fn driver_read(read_request: &mut ReadRequest) {
    if let Some(data) = LEFTOVER_BUFFER.load() {
        write_to_request(read_request, &data);
        read_request.complete();
        return;
    }

    // Check if there is enough left space (at least 4 bytes for the size of the next struct)
    if read_request.free_space() < 4 {
        read_request.complete();
        return;
    }

    match IO_QUEUE.wait_and_pop() {
        Ok(info) => {
            protocol::serialize_info(info, |data| {
                let size = (data.len() as u32).to_le_bytes();
                let _ = read_request.write(&size);
                write_to_request(read_request, data);
            });

            while read_request.free_space() > 4 {
                if let Ok(info) = IO_QUEUE.pop() {
                    protocol::serialize_info(info, |data| {
                        let size = (data.len() as u32).to_le_bytes();
                        let _ = read_request.write(&size);
                        write_to_request(read_request, data);
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
}

#[driver_write]
fn driver_write(write_request: &mut WriteRequest) {
    crate::info!("Write buffer: {:?}", write_request.get_buffer());
    if let Some(command) = protocol::read_command(write_request.get_buffer()) {
        match command {
            CommandUnion::Shutdown => {
                IO_QUEUE.rundown();
            }
            CommandUnion::Response => {
                crate::info!("Verdict response");
            }
            _ => {
                crate::err!("unrecognized command");
            }
        }
    } else {
        crate::err!("Faield to read command");
    }
    write_request.mark_all_as_read();
    write_request.complete();
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
