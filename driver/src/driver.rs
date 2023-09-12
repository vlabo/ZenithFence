// use crate::filter_engine::FilterEngine;
use crate::types::PacketInfo;
use alloc::vec;
use wdk::filter_engine::callout::Callout;
use wdk::filter_engine::FILTER_ENGINE;
use wdk::layer::Layer;
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
    let packet = PacketInfo {
        id: 1,
        process_id: Some(0),
        direction: 3,
        ip_v6: false,
        protocol: 4,
        flags: 5,
        local_ip: [1, 2, 3, 4],
        remote_ip: [4, 5, 6, 7],
        local_port: 8,
        remote_port: 9,
        compartment_id: 10,
        interface_index: 11,
        sub_interface_index: 12,
        packet_size: 13,
    };

    if let Err(err) = IO_QUEUE.push(packet) {
        log!("driver_entry!: faield to test push into queue: {}", err);
    }

    // Initialize filter engine.
    if let Err(err) = FILTER_ENGINE.init(driver, 0xa87fb472_fc68_4805_8559_c6ae774773e0) {
        log!("driver_entry: {}", err);
    }

    let callouts = vec![
        Callout::new(
            "TestCalloutOutbound",
            "Testing callout",
            0x6f996fe2_3a8f_43be_b578_e01480f2b1a1,
            Layer::FwpmLayerOutboundIppacketV4,
            |data| {
                let _ = IO_QUEUE.push(PacketInfo::from_call_data(data));
            },
        ),
        Callout::new(
            "TestCalloutInbound",
            "Testing callout",
            0x58545073_f893_454c_bbea_a57bc964f46d,
            Layer::FwpmLayerInboundIppacketV4,
            |data| {
                let _ = IO_QUEUE.push(PacketInfo::from_call_data(data));
            },
        ),
    ];

    if let Err(err) = FILTER_ENGINE.commit(callouts) {
        log!("driver_entry: {}", err);
    }

    log!("Initialization complete");
}

#[driver_unload]
fn driver_unload() {
    log!("Starting driver unload");
    FILTER_ENGINE.deinit();
    IO_QUEUE.deinit();
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
