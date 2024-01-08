use alloc::vec;
use alloc::vec::Vec;
use num_traits::FromPrimitive;
use smoltcp::wire::{IpProtocol, Ipv4Address};
use wdk::{
    consts,
    driver::Driver,
    filter_engine::{
        callout::Callout, layer::Layer, net_buffer::NetworkAllocator, packet::Injector,
        FilterEngine,
    },
    ioqueue::{self, IOQueue},
    irp_helpers::{ReadRequest, WriteRequest},
};

use crate::{
    array_holder::ArrayHolder,
    callouts,
    connection_cache::{ConnectionAction, ConnectionCache, Key},
    dbg, err,
    id_cache::PacketCache,
    logger::Logger,
    protocol::{self, Command},
    types::Verdict,
};

// Device Context
pub struct Device {
    pub(crate) filter_engine: FilterEngine,
    pub(crate) read_leftover: ArrayHolder,
    pub(crate) io_queue: IOQueue<Vec<u8>>,
    pub(crate) packet_cache: PacketCache,
    pub(crate) connection_cache: ConnectionCache,
    pub(crate) injector: Injector,
    pub(crate) network_allocator: NetworkAllocator,
    pub(crate) logger: Logger,
}

impl Device {
    /// Initialize all members of the device. Memory is handled by windows.
    /// Make sure everything is initialized here.
    pub fn init(&mut self, driver: &Driver) {
        self.logger.init();
        self.io_queue.init();
        self.read_leftover = ArrayHolder::default();
        self.packet_cache.init();
        self.connection_cache.init();
        self.injector = Injector::new();
        self.network_allocator = NetworkAllocator::new();

        if let Err(err) = self
            .filter_engine
            .init(driver, 0x7dab1057_8e2b_40c4_9b85_693e381d7896)
        {
            err!(self.logger, "filter engine error: {}", err);
        }

        let callouts = vec![
            Callout::new(
                "AleLayerOutbound",
                "ALE layer for outbound connections",
                0x58545073_f893_454c_bbea_a57bc964f46d,
                Layer::FwpmLayerAleAuthConnectV4,
                consts::FWP_ACTION_CALLOUT_TERMINATING,
                callouts::ale_layer_connect,
            ),
            // Callout::new(
            //     "AleLayerInbound",
            //     "ALE layer for inbound connections",
            //     0xc6021395_0724_4e2c_ae20_3dde51fc3c68,
            //     Layer::FwpmLayerAleAuthRecvAcceptV4,
            //     consts::FWP_ACTION_CALLOUT_TERMINATING,
            //     callouts::ale_layer_accept,
            // ),
            Callout::new(
                "IPPacketOutbound",
                "IP packet outbound network layer callout",
                0xf3183afe_dc35_49f1_8ea2_b16b5666dd36,
                Layer::FwpmLayerOutboundIppacketV4,
                consts::FWP_ACTION_CALLOUT_TERMINATING,
                callouts::network_layer_outbound,
            ),
            Callout::new(
                "IPPacketInbound",
                "IP packet inbound network layer callout",
                0xf0369374_203d_4bf0_83d2_b2ad3cc17a50,
                Layer::FwpmLayerInboundIppacketV4,
                consts::FWP_ACTION_CALLOUT_TERMINATING,
                callouts::network_layer_inbound,
            ),
            Callout::new(
                "AleResourceAssignment",
                "Port release monitor",
                0x6b9d1985_6f75_4d05_b9b5_1607e187906f,
                Layer::FwpmLayerAleResourceAssignmentV4,
                consts::FWP_ACTION_CALLOUT_INSPECTION,
                callouts::ale_resource_monitor_ipv4,
            ),
            Callout::new(
                "AleResourceRelease",
                "Port release monitor",
                0x7b513bb3_a0be_4f77_a4bc_03c052abe8d7,
                Layer::FwpmLayerAleResourceReleaseV4,
                consts::FWP_ACTION_CALLOUT_INSPECTION,
                callouts::ale_resource_monitor_ipv4,
            ),
        ];

        if let Err(err) = self.filter_engine.commit(callouts) {
            err!(self.logger, "{}", err);
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

    /// Called when handle. Read is called from userspace.
    pub fn read(&mut self, read_request: &mut ReadRequest) {
        if let Some(data) = self.read_leftover.load() {
            // There are leftovers from previous request.
            self.write_buffer(read_request, &data, false);
        } else {
            // Noting left from before. Wait for next commands.
            match self.io_queue.wait_and_pop() {
                Ok(info) => {
                    // Received new serialized object write it to the buffer.
                    self.write_buffer(read_request, &info, true);
                }
                Err(ioqueue::Status::Timeout) => {
                    // Timeout. This will only trigger if pop function is called with timeout.
                    read_request.timeout();
                    return;
                }
                Err(err) => {
                    // Queue failed. Send EOF, to notify user-space. Usually happens on rundown.
                    err!(self.logger, "failed to pop value: {}", err);
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

    // Called when handle.Write is called from user-space.
    pub fn write(&mut self, write_request: &mut WriteRequest) {
        // Try parsing the command.
        let command = match protocol::parse_command(write_request.get_buffer()) {
            Ok(command) => command,
            Err(err) => {
                wdk::err!("Failed to parse command: {}", err);
                return;
            }
        };

        let mut completion_promise = None;

        match command {
            Command::Shutdown() => {
                wdk::dbg!("Shutdown command");
                // End blocking operations from the queue. This will end pending read requests.
                self.io_queue.rundown();
            }
            Command::Verdict { id, verdict } => {
                wdk::dbg!("Verdict command");
                // Received verdict decision for a specific connection.
                if let Some(packet) = self.packet_cache.pop_id(id) {
                    if let Some(verdict) = FromPrimitive::from_u8(verdict) {
                        dbg!(self.logger, "Packet: {:?}", packet);
                        dbg!(self.logger, "Verdict response: {}", verdict);

                        // Add verdict in the cache.
                        // let conn = packet.as_connection(ConnectionAction::Verdict(verdict));
                        let key = packet.get_key();
                        completion_promise = self
                            .connection_cache
                            .update_connection(key, ConnectionAction::Verdict(verdict));
                    };
                    // completion_promise = packet.classify_promise.take();
                } else {
                    // Id was not in the packet cache.
                    err!(self.logger, "Invalid id: {}", id);
                }
            }
            Command::Redirect {
                id,
                remote_address,
                remote_port,
            } => {
                if let Some(packet) = self.packet_cache.pop_id(id) {
                    dbg!(self.logger, "packet: {:?}", packet);
                    dbg!(
                        self.logger,
                        "redirect: {:?} {}",
                        remote_address,
                        remote_port
                    );

                    let key = packet.get_key();
                    completion_promise = self.connection_cache.update_connection(
                        key,
                        ConnectionAction::RedirectIP {
                            redirect_address: Ipv4Address::from_bytes(&remote_address),
                            redirect_port: remote_port,
                        },
                    );
                } else {
                    // Id was not in the packet cache.
                    err!(self.logger, "Invalid id: {}", id);
                }
            }
            Command::Update {
                protocol,
                verdict,
                remote_address,
                remote_port,
                local_address,
                local_port,
                redirect_address,
                redirect_port,
            } => {
                let action = match FromPrimitive::from_u8(verdict).unwrap() {
                    Verdict::Redirect => ConnectionAction::RedirectIP {
                        redirect_address: Ipv4Address::from_bytes(&redirect_address),
                        redirect_port,
                    },
                    verdict => ConnectionAction::Verdict(verdict),
                };
                self.connection_cache.update_connection(
                    Key {
                        protocol: IpProtocol::from(protocol),
                        local_address: Ipv4Address::from_bytes(&local_address),
                        local_port,
                        remote_address: Ipv4Address::from_bytes(&remote_address),
                        remote_port,
                    },
                    action,
                );
                // This will trigger re-evaluation of all connections.
                if let Err(err) = self.filter_engine.reset_all_filters() {
                    err!(self.logger, "failed to reset filters: {}", err);
                }
            }
            Command::ClearCache() => {
                wdk::dbg!("ClearCache command");
                self.connection_cache.clear();
                if let Err(err) = self.filter_engine.reset_all_filters() {
                    err!(self.logger, "failed to reset filters: {}", err);
                }
            }
            Command::GetLogs() => {
                wdk::dbg!("GetLogs command");
                let lines = protocol::Info::LogLines(self.logger.flush());
                if let Ok(bytes) = lines.serialize() {
                    let _ = self.io_queue.push(bytes);
                } else {
                    wdk::err!("Failed parse logs");
                }
            }
        }

        // Check if connection was pended. If yes call complete to trigger the callout again.
        if let Some(promise) = completion_promise {
            match promise.complete(&self.filter_engine) {
                Ok(packet_list) => {
                    if let Some(packet_list) = packet_list {
                        let result = self.injector.inject_packet_list_transport(packet_list);
                        if let Err(err) = result {
                            err!(self.logger, "failed to inject packet: {}", err);
                        }
                    }
                }
                Err(err) => {
                    err!(self.logger, "error completing connection decision: {}", err);
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
