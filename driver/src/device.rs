use alloc::boxed::Box;
use alloc::vec;
use num_traits::FromPrimitive;
use protocol::{command::CommandType, info::Info};
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
    types::Verdict,
};

// Device Context
pub struct Device {
    pub(crate) filter_engine: FilterEngine,
    pub(crate) read_leftover: ArrayHolder,
    pub(crate) primary_queue: IOQueue<Box<dyn Info>>,
    pub(crate) secondary_queue: IOQueue<Box<dyn Info>>,
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
        self.primary_queue.init();
        self.secondary_queue.init();
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
            Callout::new(
                "AleLayerInbound",
                "ALE layer for inbound connections",
                0xc6021395_0724_4e2c_ae20_3dde51fc3c68,
                Layer::FwpmLayerAleAuthRecvAcceptV4,
                consts::FWP_ACTION_CALLOUT_TERMINATING,
                callouts::ale_layer_accept,
            ),
            Callout::new(
                "AleEndpointClosure",
                "ALE layer for indicating closing of connection",
                0x58f02845_ace9_4455_ac80_8a84b86fe566,
                Layer::FwpmLayerAleEndpointClosureV4,
                consts::FWP_ACTION_CALLOUT_INSPECTION,
                callouts::endpoint_closure,
            ),
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

    fn write_buffer(&mut self, read_request: &mut ReadRequest, mut info: Box<dyn Info>) {
        let bytes = info.as_bytes();
        let count = read_request.write(bytes);

        // Check if full command was written.
        if count < bytes.len() {
            // Save the leftovers for later.
            self.read_leftover.save(&bytes[count..]);
        }
    }

    /// Called when handle. Read is called from user-space.
    pub fn read(&mut self, read_request: &mut ReadRequest) {
        if let Some(data) = self.read_leftover.load() {
            // There are leftovers from previous request.
            let count = read_request.write(&data);

            // Check if full command was written.
            if count < data.len() {
                // Save the leftovers for later.
                self.read_leftover.save(&data[count..]);
            }
        } else {
            // Noting left from before. Wait for next commands.
            match self.primary_queue.pop() {
                Ok(info) => {
                    self.write_buffer(read_request, info);
                    read_request.complete();
                    return;
                }
                Err(ioqueue::Status::Timeout) => {}
                Err(err) => {
                    // Queue failed. Send EOF, to notify user-space. Usually happens on rundown.
                    err!(self.logger, "failed to pop value: {}", err);
                    read_request.end_of_file();
                    return;
                }
            }
            match self.secondary_queue.pop() {
                Ok(info) => {
                    self.write_buffer(read_request, info);
                    read_request.complete();
                    return;
                }
                Err(ioqueue::Status::Timeout) => {}
                Err(err) => {
                    // Queue failed. Send EOF, to notify user-space. Usually happens on rundown.
                    err!(self.logger, "failed to pop value: {}", err);
                    read_request.end_of_file();
                    return;
                }
            }
            match self.primary_queue.pop_timeout(200) {
                Ok(info) => {
                    // Received new serialized object write it to the buffer.
                    // let bytes = info.as_bytes();
                    self.write_buffer(read_request, info);
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

        read_request.complete();
    }

    // Called when handle.Write is called from user-space.
    pub fn write(&mut self, write_request: &mut WriteRequest) {
        // Try parsing the command.
        let mut buffer = write_request.get_buffer();
        let command = protocol::command::parse_type(buffer);
        let Some(command) = command else {
            err!(self.logger, "Unknown command number: {}", buffer[0]);
            return;
        };
        buffer = &buffer[1..];

        let mut classify_defer = None;

        match command {
            CommandType::Shutdown => {
                wdk::dbg!("Shutdown command");
                self.shutdown();
            }
            CommandType::Verdict => {
                let verdict = protocol::command::parse_verdict(buffer);
                wdk::dbg!("Verdict command");
                // Received verdict decision for a specific connection.
                if let Some(packet) = self.packet_cache.pop_id(verdict.id) {
                    if let Some(verdict) = FromPrimitive::from_u8(verdict.verdict) {
                        dbg!(self.logger, "Packet: {:?}", packet);
                        dbg!(self.logger, "Verdict response: {}", verdict);

                        // Add verdict in the cache.
                        let key = packet.get_key();
                        classify_defer = self
                            .connection_cache
                            .update_connection(key, ConnectionAction::Verdict(verdict));
                    };
                    // completion_promise = packet.classify_promise.take();
                } else {
                    // Id was not in the packet cache.
                    let id = verdict.id;
                    err!(self.logger, "Verdict invalid id: {}", id);
                }
            }
            CommandType::RedirectV4 => {
                let redirect = protocol::command::parse_redirect_v4(buffer);
                if let Some(packet) = self.packet_cache.pop_id(redirect.id) {
                    dbg!(self.logger, "packet: {:?}", packet);
                    let remote_address = redirect.remote_address;
                    let remote_port = redirect.remote_port;
                    dbg!(
                        self.logger,
                        "Redirect: {:?} {}",
                        remote_address,
                        remote_port
                    );

                    let key = packet.get_key();
                    classify_defer = self.connection_cache.update_connection(
                        key,
                        ConnectionAction::RedirectIP {
                            redirect_address: Ipv4Address::from_bytes(&remote_address),
                            redirect_port: remote_port,
                        },
                    );
                } else {
                    // Id was not in the packet cache.
                    let id = redirect.id;
                    err!(self.logger, "Redirect invalid id: {}", id);
                }
            }
            CommandType::UpdateV4 => {
                let update = protocol::command::parse_update_v4(buffer);
                // Build the new action.
                if let Some(verdict) = FromPrimitive::from_u8(update.verdict) {
                    let action = match verdict {
                        Verdict::Redirect | Verdict::RedirectTunnel => {
                            ConnectionAction::RedirectIP {
                                redirect_address: Ipv4Address::from_bytes(&update.redirect_address),
                                redirect_port: update.redirect_port,
                            }
                        }
                        verdict => ConnectionAction::Verdict(verdict),
                    };
                    // Update with new action.
                    classify_defer = self.connection_cache.update_connection(
                        Key {
                            protocol: IpProtocol::from(update.protocol),
                            local_address: Ipv4Address::from_bytes(&update.local_address),
                            local_port: update.local_port,
                            remote_address: Ipv4Address::from_bytes(&update.remote_address),
                            remote_port: update.remote_port,
                        },
                        action,
                    );
                } else {
                    err!(self.logger, "invalid verdict value: {}", update.verdict);
                }
            }
            CommandType::ClearCache => {
                wdk::dbg!("ClearCache command");
                self.connection_cache.clear();
                if let Err(err) = self.filter_engine.reset_all_filters() {
                    err!(self.logger, "failed to reset filters: {}", err);
                }
            }
            CommandType::GetLogs => {
                wdk::dbg!("GetLogs command");
                let lines_vec = self.logger.flush();
                for line in lines_vec {
                    let _ = self.secondary_queue.push(line);
                }
            }
        }

        // Check if connection was pended. If yes call complete to trigger the callout again.
        if let Some(classify_defer) = classify_defer {
            match classify_defer.complete(&mut self.filter_engine) {
                Ok(packet_list) => {
                    if let Some(packet_list) = packet_list {
                        // Inject back all packets collected while classification was pending.
                        let result = self.injector.inject_packet_list_transport(packet_list);
                        if let Err(err) = result {
                            err!(self.logger, "failed to inject packets: {}", err);
                        }
                    }
                }
                Err(err) => {
                    err!(self.logger, "error completing connection decision: {}", err);
                }
            }
        }
    }

    pub fn shutdown(&self) {
        // End blocking operations from the queue. This will end pending read requests.
        self.primary_queue.rundown();
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // dbg!("Device Context drop called.");
    }
}
