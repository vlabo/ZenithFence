use alloc::vec;
use alloc::vec::Vec;
use num_traits::FromPrimitive;
use wdk::{
    consts, dbg,
    driver::Driver,
    err,
    filter_engine::{callout::Callout, layer::Layer, packet::Injector, FilterEngine},
    info,
    ioqueue::{self, IOQueue},
    irp_helpers::{ReadRequest, WriteRequest},
};

use crate::{
    array_holder::ArrayHolder,
    callouts,
    connection_cache::{ConnectionAction, ConnectionCache},
    id_cache::PacketCache,
    protocol::{self, Command},
};

// Device Context
pub struct Device {
    pub(crate) filter_engine: FilterEngine,
    pub(crate) read_leftover: ArrayHolder,
    pub(crate) io_queue: IOQueue<Vec<u8>>,
    pub(crate) packet_cache: PacketCache,
    pub(crate) connection_cache: ConnectionCache,
    pub(crate) injector: Injector,
}

impl Device {
    /// Initialize all members of the device. Memory is handled by windows.
    /// Make sure everything is initialized here. Do not assume the that values will be zeroed.
    pub fn init(&mut self, driver: &Driver) {
        self.io_queue.init();
        self.read_leftover = ArrayHolder::default();
        self.packet_cache.init();
        self.connection_cache.init();
        self.injector = Injector::new();

        if let Err(err) = self
            .filter_engine
            .init(driver, 0xa87fb472_fc68_4805_8559_c6ae774773e0)
        {
            err!("filter engine error: {}", err);
        }

        let callouts = vec![
            Callout::new(
                "AleLayerOutbound",
                "A ALE layer for outbund connections",
                0x58545073_f893_454c_bbea_a57bc964f46d,
                Layer::FwpmLayerAleAuthConnectV4,
                consts::FWP_ACTION_CALLOUT_TERMINATING,
                callouts::ale_layer_connect,
            ),
            // Callout::new(
            //     "IPPacketOutbound",
            //     "Ip packet network layer callout",
            //     0xf3183afe_dc35_49f1_8ea2_b16b5666dd36,
            //     Layer::FwpmLayerOutboundIppacketV4,
            //     consts::FWP_ACTION_CALLOUT_TERMINATING,
            //     callouts::network_layer_outbound,
            // ),
        ];

        if let Err(err) = self.filter_engine.commit(callouts) {
            err!("{}", err);
        }
    }

    /// Cleanup is called just before drop.
    pub fn cleanup(&mut self) {}

    fn write_buffer(&mut self, read_request: &mut ReadRequest, data: &[u8], write_size: bool) {
        let buffer_size = data.len();
        if write_size {
            // Write the size of the buffer. False when writhing leftovers.
            let size = (data.len() as u32).to_le_bytes();
            let _ = read_request.write(&size);
        }
        let count = read_request.write(data);

        // Check if full command was written.
        if count < buffer_size {
            // Save the leftovers for later.
            self.read_leftover.save(&data[count..]);
        }
    }

    /// Called when handle.Read is called from userspace.
    pub fn read(&mut self, read_request: &mut ReadRequest) {
        if let Some(data) = self.read_leftover.load() {
            // There are leftovers from previos request.
            self.write_buffer(read_request, &data, false);
        } else {
            // Noting left from before. Wait for next commands.
            match self.io_queue.wait_and_pop() {
                Ok(info) => {
                    // Recived new serialied boject write it to the buffer.
                    self.write_buffer(read_request, &info, true);
                }
                Err(ioqueue::Status::Timeout) => {
                    // Timeout. This will only trigger if pop function is called with timeout.
                    read_request.timeout();
                    return;
                }
                Err(err) => {
                    // Queue failed. Send EOF, to notify userspace. Usualy happens on rundown.
                    err!("failed to pop value: {}", err);
                    read_request.end_of_file();
                    return;
                }
            }
        }

        // Try to write more.
        while read_request.free_space() > 4 {
            if let Ok(info) = self.io_queue.pop() {
                self.write_buffer(read_request, &info, true);
            } else {
                break;
            }
        }
        read_request.complete();
    }

    // Called when handle.Write is called from userspace.
    pub fn write(&mut self, write_request: &mut WriteRequest) {
        // Try parsing the command.
        let command = match protocol::parse_command(write_request.get_buffer()) {
            Ok(command) => command,
            Err(err) => {
                err!("Faield to parse command: {}", err);
                return;
            }
        };

        match command {
            Command::Shutdown() => {
                info!("Shutdown command");
                // End blocking operations from the queue. This will end pending read requests.
                self.io_queue.rundown();
            }
            Command::Verdict { id, verdict } => {
                // Receved verdict decission for a specific connection.

                if let Some(mut packet) = self.packet_cache.pop_id(id) {
                    dbg!("Packet: {:?}", packet);
                    dbg!("Verdict response: {}", verdict);

                    // Add verdict in the cache.
                    let completion_promise = self.connection_cache.add_connection(
                        &mut packet,
                        ConnectionAction::Verdict(FromPrimitive::from_u8(verdict).unwrap()),
                    );

                    // Check if connection was pended. If yes call complete to trigger the callout again.
                    if let Some(promise) = completion_promise {
                        match promise.complete(&self.filter_engine) {
                            Ok(packet_list) => {
                                if let Some(packet_list) = packet_list {
                                    info!("injecting packet_list");
                                    let result =
                                        self.injector.inject_packet_list_transport(packet_list);
                                    if let Err(err) = result {
                                        err!("failed to inject packet: {}", err);
                                    } else {
                                        info!("packet_list injected");
                                    }
                                }
                            }
                            Err(err) => {
                                err!("error compliting connection decision: {}", err);
                            }
                        }
                    }
                } else {
                    // Id was not in the packet cache.
                    err!("Invalid id: {}", id);
                }
            }
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // dbg!("Device Context drop called.");
    }
}
