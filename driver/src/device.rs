use alloc::boxed::Box;
use alloc::string::String;
use num_traits::FromPrimitive;
use protocol::{command::CommandType, info::Info};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};
use wdk::{
    driver::Driver,
    filter_engine::{
        callout_data::ClassifyDefer,
        net_buffer::{NetBufferList, NetworkAllocator},
        packet::{InjectInfo, Injector, TransportPacketList},
        FilterEngine,
    },
    ioqueue::{self, IOQueue},
    irp_helpers::{ReadRequest, WriteRequest},
};

use crate::{
    array_holder::ArrayHolder, bandwidth::Bandwidth, callouts, connection_cache::ConnectionCache,
    connection_map::Key, dbg, err, id_cache::IdCache, logger::Logger, packet_util::Redirect,
};

pub enum Packet {
    PacketLayer(NetBufferList, InjectInfo),
    AleLayer(ClassifyDefer, Option<TransportPacketList>),
    TransportPacketList(TransportPacketList),
}

// Device Context
pub struct Device {
    pub(crate) filter_engine: FilterEngine,
    pub(crate) read_leftover: ArrayHolder,
    pub(crate) event_queue: IOQueue<Box<dyn Info>>,
    pub(crate) packet_cache: IdCache<(Key, Packet)>,
    pub(crate) connection_cache: ConnectionCache,
    pub(crate) injector: Injector,
    pub(crate) network_allocator: NetworkAllocator,
    pub(crate) bandwidth_stats: Bandwidth,
    pub(crate) logger: Logger,
}

impl Device {
    /// Initialize all members of the device. Memory is handled by windows.
    /// Make sure everything is initialized here.
    pub fn new(driver: &Driver) -> Result<Self, String> {
        let mut filter_engine =
            match FilterEngine::new(driver, 0x7dab1057_8e2b_40c4_9b85_693e381d7896) {
                Ok(fe) => fe,
                Err(err) => return Err(alloc::format!("filter engine error: {}", err)),
            };

        if let Err(err) = filter_engine.commit(callouts::get_callout_vec()) {
            return Err(err);
        }

        Ok(Self {
            filter_engine,
            read_leftover: ArrayHolder::default(),
            event_queue: IOQueue::new(),
            packet_cache: IdCache::new(),
            connection_cache: ConnectionCache::new(),
            injector: Injector::new(),
            network_allocator: NetworkAllocator::new(),
            bandwidth_stats: Bandwidth::new(),
            logger: Logger::new(),
        })
    }

    /// Cleanup is called just before drop.
    // pub fn cleanup(&mut self) {}

    fn write_buffer(&mut self, read_request: &mut ReadRequest, mut info: Box<dyn Info>) {
        let bytes = info.as_bytes();
        let count = read_request.write(bytes);

        // Check if the full buffer was written.
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
            match self.event_queue.wait_and_pop() {
                Ok(info) => {
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

        // Check if we have more space. InfoType + data_size == 5 bytes
        while read_request.free_space() > 5 {
            match self.event_queue.pop() {
                Ok(info) => {
                    self.write_buffer(read_request, info);
                }
                Err(_) => {
                    break;
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

        let mut _classify_defer = None;

        match command {
            CommandType::Shutdown => {
                wdk::dbg!("Shutdown command");
                self.shutdown();
            }
            CommandType::Verdict => {
                let verdict = protocol::command::parse_verdict(buffer);
                wdk::dbg!("Verdict command");
                // Received verdict decision for a specific connection.
                if let Some((key, mut packet)) = self.packet_cache.pop_id(verdict.id) {
                    if let Some(verdict) = FromPrimitive::from_u8(verdict.verdict) {
                        dbg!(self.logger, "Verdict received {}: {}", key, verdict);
                        // Add verdict in the cache.
                        let redirect_info = self.connection_cache.update_connection(key, verdict);

                        // if verdict.is_permanent() {
                        //     dbg!(self.logger, "resetting filters {}: {}", key, verdict);
                        //     _ = self.filter_engine.reset_all_filters();
                        // }

                        match verdict {
                            crate::connection::Verdict::Accept
                            | crate::connection::Verdict::PermanentAccept => {
                                _ = self.inject_packet(packet, false);
                            }
                            crate::connection::Verdict::RedirectNameServer
                            | crate::connection::Verdict::RedirectTunnel => {
                                if let Some(redirect_info) = redirect_info {
                                    if let Err(err) = packet.redirect(redirect_info) {
                                        err!(self.logger, "failed to redirect packet: {}", err);
                                    }
                                    if let Err(err) = self.inject_packet(packet, false) {
                                        err!(self.logger, "failed to inject packet: {}", err);
                                    }
                                }
                            }
                            _ => {
                                if let Err(err) = self.inject_packet(packet, true) {
                                    err!(self.logger, "failed to inject packet: {}", err);
                                }
                            }
                        }
                    };
                } else {
                    // Id was not in the packet cache.
                    let id = verdict.id;
                    err!(self.logger, "Verdict invalid id: {}", id);
                }
            }
            CommandType::UpdateV4 => {
                let update = protocol::command::parse_update_v4(buffer);
                // Build the new action.
                if let Some(verdict) = FromPrimitive::from_u8(update.verdict) {
                    // Update with new action.
                    dbg!(
                        self.logger,
                        "Verdict update received {:?}: {}",
                        update,
                        verdict
                    );
                    _classify_defer = self.connection_cache.update_connection(
                        Key {
                            protocol: IpProtocol::from(update.protocol),
                            local_address: IpAddress::Ipv4(Ipv4Address::from_bytes(
                                &update.local_address,
                            )),
                            local_port: update.local_port,
                            remote_address: IpAddress::Ipv4(Ipv4Address::from_bytes(
                                &update.remote_address,
                            )),
                            remote_port: update.remote_port,
                        },
                        verdict,
                    );
                } else {
                    err!(self.logger, "invalid verdict value: {}", update.verdict);
                }
            }
            CommandType::UpdateV6 => {
                let update = protocol::command::parse_update_v6(buffer);
                // Build the new action.
                if let Some(verdict) = FromPrimitive::from_u8(update.verdict) {
                    // Update with new action.
                    dbg!(
                        self.logger,
                        "Verdict update received {:?}: {}",
                        update,
                        verdict
                    );
                    _classify_defer = self.connection_cache.update_connection(
                        Key {
                            protocol: IpProtocol::from(update.protocol),
                            local_address: IpAddress::Ipv6(Ipv6Address::from_bytes(
                                &update.local_address,
                            )),
                            local_port: update.local_port,
                            remote_address: IpAddress::Ipv6(Ipv6Address::from_bytes(
                                &update.remote_address,
                            )),
                            remote_port: update.remote_port,
                        },
                        verdict,
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
                    let _ = self.event_queue.push(line);
                }
            }
            CommandType::GetBandwidthStats => {
                wdk::dbg!("GetBandwidthStats command");
                let stats = self.bandwidth_stats.get_all_updates_tcp_v4();
                if let Some(stats) = stats {
                    _ = self.event_queue.push(stats);
                }

                let stats = self.bandwidth_stats.get_all_updates_tcp_v6();
                if let Some(stats) = stats {
                    _ = self.event_queue.push(stats);
                }

                let stats = self.bandwidth_stats.get_all_updates_udp_v4();
                if let Some(stats) = stats {
                    _ = self.event_queue.push(stats);
                }

                let stats = self.bandwidth_stats.get_all_updates_udp_v6();
                if let Some(stats) = stats {
                    _ = self.event_queue.push(stats);
                }
            }
            CommandType::PrintMemoryStats => {
                dbg!(
                    self.logger,
                    "Packet cache: {} entries",
                    self.packet_cache.get_entries_count()
                );
                dbg!(
                    self.logger,
                    "BandwidthStats cache: {} entries",
                    self.bandwidth_stats.get_entries_count()
                );
                dbg!(
                    self.logger,
                    "Connection cache: {} entries\n {}",
                    self.connection_cache.get_entries_count(),
                    self.connection_cache.get_full_cache_info()
                );
            }
        }

        // Check if connection was pended. If yes call complete to trigger the callout again.
        // if let Some(classify_defer) = classify_defer {
        //     match classify_defer.complete(&mut self.filter_engine) {
        //         Ok(packet_list) => {
        //             if let Some(packet_list) = packet_list {
        //                 // Inject back all packets collected while classification was pending.
        //                 let result = self.injector.inject_packet_list_transport(packet_list);
        //                 if let Err(err) = result {
        //                     err!(self.logger, "failed to inject packets: {}", err);
        //                 }
        //             }
        //         }
        //         Err(err) => {
        //             err!(self.logger, "error completing connection decision: {}", err);
        //         }
        //     }
        // }
    }

    pub fn shutdown(&self) {
        // End blocking operations from the queue. This will end pending read requests.
        self.event_queue.rundown();
    }

    pub fn inject_packet(&mut self, packet: Packet, blocked: bool) -> Result<(), String> {
        match packet {
            Packet::PacketLayer(nbl, inject_info) => {
                if !blocked {
                    self.injector.inject_net_buffer_list(nbl, inject_info)
                } else {
                    Ok(())
                }
            }
            Packet::AleLayer(defer, tpl) => {
                // FIXME(vladimir): redirect before inject if needed
                let _ = defer.complete(&mut self.filter_engine)?;
                if let Some(packet_list) = tpl {
                    self.injector.inject_packet_list_transport(packet_list)?;
                }

                return Ok(());
            }
            Packet::TransportPacketList(_) => todo!(),
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // dbg!("Device Context drop called.");
    }
}
