use crate::array_holder::ArrayHolder;
use crate::connection_cache::ConnectionAction;
use crate::connection_cache::ConnectionCache;
use crate::id_cache::IdCache;
use crate::protocol::Command;
use crate::protocol::{self};
use crate::types::{PacketInfo, Verdict};
use alloc::{boxed::Box, vec, vec::Vec};
use wdk::allocator::NullAllocator;
use wdk::consts;
use wdk::filter_engine::callout::Callout;
use wdk::filter_engine::layer::{FwpsFieldsAleAuthConnectV4, Layer};
use wdk::filter_engine::FilterEngine;
use wdk::interface::{WdfObjectAttributes, WdfObjectContextTypeInfo};
use wdk::utils::ReadRequest;
use wdk::{
    dbg, err, info, interface,
    ioqueue::{self, IOQueue},
};
use windows_sys::Wdk::Foundation::{DEVICE_OBJECT, DRIVER_OBJECT, IRP};
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, STATUS_SUCCESS};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_FLAG_IS_REAUTHORIZE;

// Device Context
struct DeviceContext {
    filter_engine: FilterEngine,
    read_leftover: ArrayHolder,
    io_queue: IOQueue<Vec<u8>>,
    packet_cache: IdCache<PacketInfo>,
    connection_cache: ConnectionCache,
}

impl DeviceContext {
    fn init(&mut self) {
        self.io_queue.init();
        self.read_leftover = ArrayHolder::default();
        self.packet_cache.init();
        self.connection_cache.init();
    }
}

impl Drop for DeviceContext {
    fn drop(&mut self) {
        dbg!("Device Context drop called.");
    }
}

static mut DRIVER_CONFIG: WdfObjectContextTypeInfo =
    WdfObjectContextTypeInfo::default("DriverContext\0");

#[no_mangle]
pub extern "system" fn DriverEntry(
    driver_object: *mut windows_sys::Wdk::Foundation::DRIVER_OBJECT,
    registry_path: *mut windows_sys::Win32::Foundation::UNICODE_STRING,
) -> windows_sys::Win32::Foundation::NTSTATUS {
    info!("Starting initialization...");

    let mut object_attributes = WdfObjectAttributes::new();
    object_attributes.add_context::<DeviceContext>(unsafe { &mut DRIVER_CONFIG });
    object_attributes.set_cleanup_fn(device_cleanup);

    // Initialize driver object
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

    if let Some(device_object) = driver.get_device_object_ref() {
        if let Ok(context) =
            interface::get_device_context_from_device_object::<DeviceContext>(device_object)
        {
            // Init all global objects.
            context.init();
            if let Err(err) = context
                .filter_engine
                .init(&driver, 0xa87fb472_fc68_4805_8559_c6ae774773e0)
            {
                err!("{}", err);
            }

            let callouts = vec![
                Callout::new(
                    "AleLayerOutbound",
                    "A Test ALE layer for outbund connections",
                    0x58545073_f893_454c_bbea_a57bc964f46d,
                    Layer::FwpmLayerAleAuthConnectV4,
                    consts::FWP_ACTION_CALLOUT_TERMINATING,
                    |mut data, device_object| {
                        let Ok(context) = interface::get_device_context_from_device_object::<
                            DeviceContext,
                        >(device_object) else {
                            return;
                        };
                        let mut packet = PacketInfo::from_callout_data(&data);
                        dbg!("Connect callout: {:?}", packet);
                        if let Some(action) =
                            context.connection_cache.get_connection_action(&packet)
                        {
                            // We already have a verdict for it.
                            if let ConnectionAction::Verdict(verdict) = action {
                                match verdict {
                                    Verdict::Accept => {
                                        data.permit();
                                    }
                                    Verdict::Block => {
                                        data.block();
                                    }
                                    Verdict::Drop => {
                                        data.block_and_absorb();
                                    }
                                    Verdict::Failed => {
                                        data.block();
                                    }
                                    _ => {}
                                }
                            }
                        } else if data.get_value_u32(FwpsFieldsAleAuthConnectV4::Flags as usize)
                            & FWP_CONDITION_FLAG_IS_REAUTHORIZE
                            == 0
                        {
                            // Send request to userspace.
                            let promise = match data.pend_operation() {
                                Ok(cc) => cc,
                                Err(error) => {
                                    err!("failed to postpone decision: {}", error);
                                    data.block();
                                    return;
                                }
                            };
                            let clone = packet.clone();
                            packet.classify_promise = Some(promise);
                            let id = context.packet_cache.push(packet);
                            if let Ok(bytes) = clone.serialize(id) {
                                let _ = context.io_queue.push(bytes);
                            }
                        } else {
                            // Send request to userspace.
                            let promise = data.pend_classification();

                            let clone = packet.clone();
                            packet.classify_promise = Some(promise);
                            let id = context.packet_cache.push(packet);
                            if let Ok(bytes) = clone.serialize(id) {
                                let _ = context.io_queue.push(bytes);
                            }

                            data.block_and_absorb();
                        }
                    },
                ),
                // Callout::new(
                //     "AleRedirect",
                //     "Redirects connections",
                //     0xf72e1faf_4f8b_496a_ac62_1f3286edde44,
                //     Layer::FwpmLayerAleConnectRedirectV4,
                //     consts::FWP_ACTION_CALLOUT_TERMINATING,
                //     |mut data, device_object| {
                //         let Ok(context) = interface::get_device_context_from_device_object::<
                //             DeviceContext,
                //         >(device_object) else {
                //             return;
                //         };
                //         let packet = PacketInfo::from_callout_data(&data);
                //         dbg!("Redirect callout: {:?}", packet);
                //         if let Some(action) =
                //             context.connection_cache.get_connection_action(&packet)
                //         {
                //             match action {
                //                 ConnectionAction::RedirectIPv4(ip, port) => {
                //                     info!("Reddirecting -> {:?}:{}", ip, port);
                //                     if let Err(err) = data.redirect(&[9, 9, 9, 9], port) {
                //                         err!("failed to redirect connection: {}", err)
                //                     }
                //                 }
                //                 _ => {}
                //             }
                //         } else {
                //             dbg!("Noting to redirect");
                //         }
                //     },
                // ),
                // Callout::new(
                //     "AleRedirectv6",
                //     "Redirects connections",
                //     0xb3b97159_922f_4c22_a5a5_023be433ebcf,
                //     Layer::FwpmLayerAleConnectRedirectV6,
                //     consts::FWP_ACTION_CALLOUT_TERMINATING,
                //     |mut data, device_object| {
                //         let Ok(context) = interface::get_device_context_from_device_object::<
                //             DeviceContext,
                //         >(device_object) else {
                //             return;
                //         };
                //         let packet = PacketInfo::from_callout_data(&data);
                //         if let Some(action) =
                //             context.connection_cache.get_connection_action(&packet)
                //         {
                //             match action {
                //                 ConnectionAction::RedirectIPv6(ip, port) => {
                //                     if let Err(err) = data.redirect(&ip, port) {
                //                         err!("failed to redirect connection: {}", err)
                //                     }
                //                 }
                //                 _ => {}
                //             }
                //         }
                //     },
                // ),
            ];

            if let Err(err) = context.filter_engine.commit(callouts) {
                err!("{}", err);
            }
        };
    }

    info!("Initialization complete");

    STATUS_SUCCESS
}

extern "C" fn device_cleanup(device: HANDLE) {
    info!("Cleaning");
    let device_context =
        interface::get_device_context_from_wdf_device::<DeviceContext>(device, unsafe {
            &DRIVER_CONFIG
        });

    unsafe {
        // Call drop without freeing memory. Memory is manged by the kernel.
        if !device_context.is_null() {
            let owned_device_contex = Box::from_raw_in(device_context, NullAllocator {});
            drop(owned_device_contex);
        }
    }
}

unsafe extern "system" fn driver_unload(_object: *const DRIVER_OBJECT) {
    info!("Unloading complete");
}

fn write_buffer(device_context: &DeviceContext, read_request: &mut ReadRequest, data: &[u8]) {
    let command_size = data.len();
    let count = read_request.write(data);

    // Check if full command was written.
    if count < command_size {
        // Save the leftovers for later.
        device_context.read_leftover.save(&data[count..]);
    }
}

fn write_info_object(
    device_context: &DeviceContext,
    read_request: &mut ReadRequest,
    data: Vec<u8>,
) {
    let size = (data.len() as u32).to_le_bytes();
    let _ = read_request.write(&size);
    write_buffer(device_context, read_request, data.as_slice());
}

unsafe extern "system" fn driver_read(
    device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    // Setup structs.
    let mut read_request = wdk::utils::ReadRequest::new(irp);
    let Ok(device_context) =
        interface::get_device_context_from_device_object::<DeviceContext>(device_object)
    else {
        read_request.complete();
        return read_request.get_status();
    };

    if let Some(data) = device_context.read_leftover.load() {
        // There are leftovers from previos request.
        write_buffer(device_context, &mut read_request, &data);
    } else {
        // Noting left from before. Wait for next commands.
        match device_context.io_queue.wait_and_pop() {
            Ok(info) => {
                write_info_object(device_context, &mut read_request, info);
            }
            Err(ioqueue::Status::Timeout) => read_request.timeout(),
            Err(err) => {
                err!("failed to pop value: {}", err);
                read_request.end_of_file();
            }
        }
    }

    // Check for error.
    if read_request.get_status() == STATUS_SUCCESS {
        // Try to write more.
        while read_request.free_space() > 4 {
            if let Ok(info) = device_context.io_queue.pop() {
                write_info_object(device_context, &mut read_request, info);
            } else {
                break;
            }
        }
        read_request.complete();
    }

    read_request.get_status()
}

unsafe extern "system" fn driver_write(
    device_object: &mut DEVICE_OBJECT,
    irp: &mut IRP,
) -> NTSTATUS {
    let mut write_request = wdk::utils::WriteRequest::new(irp);
    let Ok(device_context) =
        interface::get_device_context_from_device_object::<DeviceContext>(device_object)
    else {
        write_request.complete();
        return write_request.get_status();
    };
    info!("Write called");
    match protocol::parse_command(write_request.get_buffer()) {
        Ok(command) => {
            match command {
                Command::Shutdown() => {
                    info!("Shutdown command");
                    device_context.io_queue.rundown();
                }
                Command::Verdict { id, verdict } => {
                    if let Some(mut packet) = device_context.packet_cache.pop_id(id) {
                        info!("Packet: {:?}", packet);
                        info!("Verdict response: {}", verdict);
                        let completion_promise = device_context
                            .connection_cache
                            .add_connection(&mut packet, ConnectionAction::Verdict(verdict));
                        if let Some(mut promise) = completion_promise {
                            if let Err(err) = promise.complete(&device_context.filter_engine) {
                                err!("error compliting connection decision: {}", err);
                            }
                        }
                    } else {
                        err!("Invalid id: {}", id);
                    }
                } // CommandUnion::Redirect => {
                  //     let response = command.command_as_redirect().unwrap();
                  //     if let Some(packet) = device_context.packet_cache.pop_id(response.id()) {
                  //         let remote_ip = response.remote_ip().unwrap().bytes().to_vec();
                  //         let port = response.remote_port();
                  //         info!("Redirect connection: {:?}", packet);
                  //         let completion_promise = device_context
                  //             .connection_cache
                  //             .add_connection(packet, ConnectionAction::RedirectIPv4(remote_ip, port));
                  //         if let Some(mut promise) = completion_promise {
                  //             if let Err(err) = promise.complete(&device_context.filter_engine) {
                  //                 err!("error compliting connection decision: {}", err);
                  //             }
                  //         }
                  //     } else {
                  //         err!("Invalid id: {}", response.id());
                  //     }
                  // }
            }
        }
        Err(err) => {
            err!("Faield to read command: {}", err);
        }
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

// #[macro_export]
// macro_rules! log {
//     ($level:expr, $($arg:tt)*) => ({
//         let message = alloc::format!($($arg)*);
//         _ = IO_QUEUE.push(Info::LogLine(alloc::format!("{} {}: {}", $level, core::module_path!(), message)))
//     });
// }

// #[macro_export]
// macro_rules! err {
//     ($($arg:tt)*) => ($crate::log!("ERROR", $($arg)*));
// }

// #[macro_export]
// macro_rules! dbg {
//     ($($arg:tt)*) => ($crate::log!("DEBUG", $($arg)*));
// }

// #[macro_export]
// macro_rules! info {
//     ($($arg:tt)*) => ($crate::log!("INFO", $($arg)*));
// }
