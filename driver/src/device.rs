use core::sync::atomic::{AtomicBool, Ordering};

use alloc::string::String;
use num_traits::FromPrimitive;
use protocol::{command::CommandType, info::Info};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};
use wdk::{
    driver::Driver,
    filter_engine::{
        callout_data::ClassifyDefer,
        net_buffer::{NetBufferList, NetworkAllocator},
        packet::{InjectInfo, Injector},
        FilterEngine,
    },
    ioqueue::{self, IOQueue},
    irp_helpers::{ReadRequest, WriteRequest},
};

use crate::{
    array_holder::ArrayHolder,
    callouts,
    connection::{Connection, ConnectionV4, ConnectionV6, Key},
    connection_cache::ConnectionCache,
    dbg, err,
    id_cache::IdCache,
    logger,
    packet_util::Redirect,
};

pub enum Packet {
    PacketLayer(NetBufferList, InjectInfo),
    AleLayer(ClassifyDefer),
}

// Device Context
pub struct Device {
    pub(crate) filter_engine: FilterEngine,
    pub(crate) read_leftover: ArrayHolder,
    pub(crate) event_queue: IOQueue<Info>,
    pub(crate) packet_cache: IdCache,
    pub(crate) connection_cache: ConnectionCache,
    pub(crate) injector: Injector,
    pub(crate) network_allocator: NetworkAllocator,
    /// Set once the teardown has begun. Callouts check it and stop pending operations, because
    /// from that point on nothing is left to answer a pend.
    shutdown_started: AtomicBool,
}

impl Device {
    /// Initialize all members of the device. Memory is handled by windows.
    /// Make sure everything is initialized here.
    pub fn new(driver: &Driver) -> Result<Self, String> {
        let mut filter_engine =
            match FilterEngine::new(driver, 0xf19f6eef_9031_4339_b90a_613da727ee29) {
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
            shutdown_started: AtomicBool::new(false),
        })
    }

    /// Reports whether the teardown has started. Callouts must not pend a new operation once this
    /// is set: the packet cache is being drained and the user space handle is on its way out, so
    /// a pend made now would never be completed.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_started.load(Ordering::SeqCst)
    }

    /// Cleanup is called just before drop.
    // pub fn cleanup(&mut self) {}

    fn write_buffer(&mut self, read_request: &mut ReadRequest, info: Info) {
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
                    err!("failed to pop value: {}", err);
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
            err!("Unknown command number: {}", buffer[0]);
            return;
        };

        // Skip command byte.
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
                        dbg!("Verdict received {}: {}", key, verdict);
                        // Add verdict in the cache.
                        let redirect_info = self.connection_cache.update_connection(key, verdict);

                        match verdict {
                            crate::connection::Verdict::Accept
                            | crate::connection::Verdict::PermanentAccept => {
                                if let Err(err) = self.inject_packet(packet, false) {
                                    err!("failed to inject packet: {} key={}", err, key);
                                } else {
                                    dbg!("packet injected: {}", key);
                                }
                            }
                            crate::connection::Verdict::RedirectNameServer
                            | crate::connection::Verdict::RedirectTunnel => {
                                if let Some(redirect_info) = redirect_info {
                                    if let Err(err) = packet.redirect(redirect_info) {
                                        err!("failed to redirect packet: {} key={}", err, key);
                                    }
                                    if let Err(err) = self.inject_packet(packet, false) {
                                        err!("failed to inject packet: {} key={}", err, key);
                                    }
                                }
                            }
                            _ => {
                                if let Err(err) = self.inject_packet(packet, true) {
                                    err!("failed to inject packet: {} key={}", err, key);
                                }
                            }
                        }
                    };
                } else {
                    // Id was not in the packet cache.
                    let id = verdict.id;
                    err!("Verdict invalid id: {}", id);
                }
            }
            CommandType::UpdateV4 => {
                let update = protocol::command::parse_update_v4(buffer);
                // Build the new action.
                if let Some(verdict) = FromPrimitive::from_u8(update.verdict) {
                    // Update with new action.
                    dbg!("Verdict update received {:?}: {}", update, verdict);
                    let key = Key {
                        protocol: IpProtocol::from(update.protocol),
                        local_address: IpAddress::Ipv4(Ipv4Address::from_octets(
                            update.local_address,
                        )),
                        local_port: update.local_port,
                        remote_address: IpAddress::Ipv4(Ipv4Address::from_octets(
                            update.remote_address,
                        )),
                        remote_port: update.remote_port,
                    };
                    _classify_defer = self.connection_cache.update_connection(key, verdict);
                } else {
                    err!("invalid verdict value: {}", update.verdict);
                }
            }
            CommandType::UpdateV6 => {
                let update = protocol::command::parse_update_v6(buffer);
                // Build the new action.
                if let Some(verdict) = FromPrimitive::from_u8(update.verdict) {
                    // Update with new action.
                    dbg!("Verdict update received {:?}: {}", update, verdict);
                    let key = Key {
                        protocol: IpProtocol::from(update.protocol),
                        local_address: IpAddress::Ipv6(Ipv6Address::from_octets(
                            update.local_address,
                        )),
                        local_port: update.local_port,
                        remote_address: IpAddress::Ipv6(Ipv6Address::from_octets(
                            update.remote_address,
                        )),
                        remote_port: update.remote_port,
                    };
                    _classify_defer = self.connection_cache.update_connection(key, verdict);
                } else {
                    err!("invalid verdict value: {}", update.verdict);
                }
            }
            CommandType::ClearCache => {
                wdk::dbg!("ClearCache command");
                self.connection_cache.clear();
                if let Err(err) = self.filter_engine.reset_all_filters() {
                    err!("failed to reset filters: {}", err);
                }
            }
            CommandType::GetConnectionsUpdate => {
                let update = protocol::command::parse_update_info(buffer);
                let timestamp = update.timestamp;
                wdk::dbg!("GetConnectionsUpdate command");

                let send_event_v4 = |conn: &ConnectionV4| {
                    // Function is behind spin lock. Dont do expensive operations.
                    if conn.last_accessed_timestamp.load(Ordering::SeqCst) > timestamp {
                        return;
                    }

                    let info = protocol::info::connection_update_event_v4_info(
                        conn.protocol.into(),
                        conn.local_address.octets(),
                        conn.remote_address.octets(),
                        conn.local_port,
                        conn.remote_port,
                        conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
                    );
                    _ = self.event_queue.push(info);
                };

                let send_event_v6 = |conn: &ConnectionV6| {
                    // Function is behind spin lock. Dont do expensive operations.
                    if conn.last_accessed_timestamp.load(Ordering::SeqCst) > timestamp {
                        return;
                    }

                    let info = protocol::info::connection_update_event_v6_info(
                        conn.protocol.into(),
                        conn.local_address.octets(),
                        conn.remote_address.octets(),
                        conn.local_port,
                        conn.remote_port,
                        conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
                    );
                    _ = self.event_queue.push(info);
                };

                self.connection_cache
                    .walk_over_connections_v4(send_event_v4);
                self.connection_cache
                    .walk_over_connections_v6(send_event_v6);

                _ = self
                    .event_queue
                    .push(protocol::info::connection_update_end_info());
            }
            CommandType::GetLogs => {
                wdk::dbg!("GetLogs command");
                let lines_vec = logger::flush();
                for line in lines_vec {
                    let _ = self.event_queue.push(line);
                }
            }
            CommandType::PrintMemoryStats => {
                wdk::dbg!("PrintMemoryStats command");
                use core::fmt::Write;

                let (active, ended) = self.connection_cache.get_entries_count();
                let packet_cache_count = self.packet_cache.get_entries_count();
                let (unlinked_v4, unlinked_v6) = self.connection_cache.get_unlinked_queue_counts();

                {
                    let mut log_line = protocol::info::log_line(
                        protocol::info::Severity::Info,
                        logger::MAX_LOG_LINE_SIZE,
                    );
                    _ = write!(
                        log_line,
                        "MemStats: connections active={} ended={} | packet_cache={} | unlinked_ports v4={} v6={}",
                        active, ended, packet_cache_count, unlinked_v4, unlinked_v6
                    );
                    logger::add_line(log_line);
                }

                self.connection_cache
                    .walk_over_connections_v4(|conn: &ConnectionV4| {
                        let proto = match conn.protocol {
                            IpProtocol::Tcp => "TCP",
                            IpProtocol::Udp => "UDP",
                            _ => "???",
                        };
                        let status = if conn.has_ended() { " [ENDED]" } else { "" };
                        let mut log_line = protocol::info::log_line(
                            protocol::info::Severity::Info,
                            logger::MAX_LOG_LINE_SIZE,
                        );
                        _ = write!(
                            log_line,
                            "[{}][{}] {}:{}-{}:{} pid={} {} rx={}B tx={}B{}",
                            proto,
                            conn.direction,
                            conn.local_address,
                            conn.local_port,
                            conn.remote_address,
                            conn.remote_port,
                            conn.process_id,
                            conn.get_verdict(),
                            conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                            conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                            status,
                        );
                        logger::add_line(log_line);
                    });

                self.connection_cache
                    .walk_over_connections_v6(|conn: &ConnectionV6| {
                        let proto = match conn.protocol {
                            IpProtocol::Tcp => "TCP",
                            IpProtocol::Udp => "UDP",
                            _ => "???",
                        };
                        let status = if conn.has_ended() { " [ENDED]" } else { "" };
                        let mut log_line = protocol::info::log_line(
                            protocol::info::Severity::Info,
                            logger::MAX_LOG_LINE_SIZE,
                        );
                        _ = write!(
                            log_line,
                            "[{}][{}] {}:{}-{}:{} pid={} {} rx={}B tx={}B{}",
                            proto,
                            conn.direction,
                            conn.local_address,
                            conn.local_port,
                            conn.remote_address,
                            conn.remote_port,
                            conn.process_id,
                            conn.get_verdict(),
                            conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                            conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                            status,
                        );
                        logger::add_line(log_line);
                    });
            }
            CommandType::CleanEndedConnections => {
                wdk::dbg!("CleanEndedConnections command");
                let (conn_v4, conn_v6) = self.connection_cache.clean_ended_connections();

                // Process ended ipv4 connections
                for conn in conn_v4.iter() {
                    let info = protocol::info::connection_end_event_v4_info(
                        conn.get_process_id(),
                        conn.get_direction() as u8,
                        conn.protocol.into(),
                        conn.local_address.octets(),
                        conn.remote_address.octets(),
                        conn.local_port,
                        conn.remote_port,
                        conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
                    );
                    _ = self.event_queue.push(info);
                }

                conn_v4.clear();

                // Process ended ipv6 connections
                for conn in conn_v6.iter() {
                    let info = protocol::info::connection_end_event_v6_info(
                        conn.get_process_id(),
                        conn.get_direction() as u8,
                        conn.protocol.into(),
                        conn.local_address.octets(),
                        conn.remote_address.octets(),
                        conn.local_port,
                        conn.remote_port,
                        conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
                    );
                    _ = self.event_queue.push(info);
                }
                conn_v6.clear();
            }
        }
    }

    /// Tears the device down, in the only order that leaves nothing behind for the unload:
    /// remove the filters, complete everything that is still pended, then remove the callouts.
    ///
    /// Reachable from the shutdown command (write and device-control) and from the unload path,
    /// and safe to call more than once: the one-time part runs once, the rest runs on every call
    /// so anything that raced in afterwards is still resolved.
    pub fn shutdown(&mut self) {
        if !self.shutdown_started.swap(true, Ordering::SeqCst) {
            // Remove the filters before anything else. Once they are gone no new classify call can
            // reach the callouts, so no new connection can be pended while the teardown runs. The
            // flag set above covers the classify calls that are already in flight.
            if let Err(err) = self.filter_engine.unregister_filters() {
                err!("failed to unregister filters on shutdown: {}", err);
            }

            // End blocking operations from the queue. This will end pending read requests.
            self.event_queue.rundown();
        }

        // Resolve all pending packets. This is important for proper driver unload.
        self.complete_pending_packets();

        // Nothing is pended anymore, so the callouts can be removed. This has to happen here and
        // not be left to the filter engine being dropped: unregistering a callout fails while an
        // operation is still pended on it, and the drop has no way to complete one.
        if let Err(err) = self.filter_engine.unregister_callouts() {
            err!("failed to unregister callouts on shutdown: {}", err);
        }
    }

    /// Completes every operation still held in the packet cache. A pended ALE operation keeps its
    /// IRP alive inside the callout: if the driver unloads while one is still outstanding, that
    /// IRP can never be completed, the thread that owns it never leaves kernel mode, and its
    /// process can no longer be terminated. Everything is resolved with a verdict here so the
    /// callouts can be unregistered cleanly.
    fn complete_pending_packets(&mut self) {
        for _ in 0..10 {
            // Wait before every pass, including the first one, so a classify that was still on its
            // way to pend_operation when the filters were removed has time to land in the cache.
            if let Err(err) = wdk::utils::sleep_ms(10) {
                err!("failed to wait between drain passes: {}", err);
            }

            let pending_packets = self.packet_cache.pop_all();
            if pending_packets.is_empty() {
                // Keep going rather than stopping here: an empty pass does not prove the cache
                // will stay empty, only that nothing had arrived yet.
                continue;
            }

            for el in pending_packets {
                let key = el.value.0;
                let packet = el.value.1;
                // Set any verdict. Driver will unload after that and the filter will not be active.
                _ = self
                    .connection_cache
                    .update_connection(key, crate::connection::Verdict::PermanentBlock);
                _ = self.inject_packet(packet, true); // Blocked must be set, so it only handles the ALE layer.
            }
        }
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
            Packet::AleLayer(defer) => {
                let packet_list = defer.complete(&mut self.filter_engine)?;
                if let Some(packet_list) = packet_list {
                    self.injector.inject_packet_list_transport(packet_list)?;
                }
                Ok(())
            }
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // The driver can also be unloaded without ever receiving a shutdown command (service stop,
        // driver removal, a user space process that died). Run the same teardown here so no pended
        // operation is ever left behind. This still runs before the filter engine is dropped, so
        // completing the operations and removing the callouts is valid at this point; by the time
        // the engine drops there is nothing left for its own failsafe to do.
        self.shutdown();

        _ = logger::flush();
        // dbg!("Device Context drop called.");
    }
}
