// use crate::filter_engine::FilterEngine;
use crate::types::PacketInfo;
use alloc::vec;
use wdk::filter_engine::callout::Callout;
use wdk::filter_engine::layer::Layer;
use wdk::filter_engine::FILTER_ENGINE;
use wdk::utils::{Driver, ReadRequest, WriteRequest};
use wdk::{
    err, info, interface,
    ioqueue::{self, IOQueue},
};
use wdk_macro::{driver_entry, driver_read, driver_unload, driver_write};
use winapi::{
    km::wdm::{DEVICE_OBJECT, DRIVER_OBJECT, IRP},
    shared::ntdef::UNICODE_STRING,
};
use windows_sys::Win32::Foundation::NTSTATUS;

pub static IO_QUEUE: IOQueue<PacketInfo> = IOQueue::default();

#[driver_entry(
    name = "PortmasterTest",
    read_fn = true,
    write_fn = true,
    ioctl_fn = false
)]
fn driver_entry(driver: Driver) {
    info!("Starting initialization...");

    IO_QUEUE.init();

    // Initialize filter engine.
    if let Err(err) = FILTER_ENGINE.init(driver, 0xa87fb472_fc68_4805_8559_c6ae774773e0) {
        err!("{}", err);
    }

    let callouts = vec![
        Callout::new(
            "TestCalloutInbound",
            "Testing callout",
            0x6f996fe2_3a8f_43be_b578_e01480f2b1a1,
            Layer::FwpmLayerAleAuthRecvAcceptV4,
            |data| {
                let packet = PacketInfo::from_call_data(data);
                info!("packet: {:?}", packet);
                let _ = IO_QUEUE.push(packet);
            },
        ),
        Callout::new(
            "TestCalloutOutbound",
            "Testing callout",
            0x58545073_f893_454c_bbea_a57bc964f46d,
            Layer::FwpmLayerAleAuthConnectV4,
            |data| {
                let packet = PacketInfo::from_call_data(data);
                info!("packet: {:?}", packet);
                let _ = IO_QUEUE.push(packet);
            },
        ),
    ];

    if let Err(err) = FILTER_ENGINE.commit(callouts) {
        err!("{}", err);
    }

    info!("Initialization complete");
}

#[driver_unload]
fn driver_unload() {
    info!("Starting driver unload");
    FILTER_ENGINE.deinit();
    IO_QUEUE.deinit();
    info!("Unloading complete");
}

#[driver_read]
fn driver_read(mut read_request: ReadRequest) {
    // let max_count = read_request.free_space() / core::mem::size_of::<PacketInfo>();
    match IO_QUEUE.wait_and_pop() {
        Ok(packet) => {
            let _ = ciborium::into_writer(&packet, &mut read_request);

            info!("Send {} packets to the client", 1);
            read_request.complete();
        }
        Err(ioqueue::Status::Timeout) => read_request.timeout(),
        Err(err) => {
            err!("failed to pop value: {}", err);
            read_request.complete();
        }
    }
}

#[driver_write]
fn driver_write(mut write_request: WriteRequest) {
    info!("Write request: {:?}", write_request.get_buffer());
    IO_QUEUE.rundown();
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
