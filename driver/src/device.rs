use core::sync::atomic::{AtomicBool, Ordering};

use alloc::string::String;
use num_traits::FromPrimitive;
use protocol::{command::CommandType, info::Info};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};
use wdk::{
    driver::Driver,
    filter_engine::{
        callout_data::{ClassifyDefer, DeferResolution},
        net_buffer::{NetBufferList, NetworkAllocator},
        packet::{InjectInfo, Injector},
        FilterEngine, ResetError,
    },
    ioqueue::{self, IOQueue},
    irp_helpers::{ReadRequest, WriteRequest},
    kmutex::KMutex,
    worker::PeriodicWorker,
};

use crate::{
    pending_event::PendingEvent,
    callouts,
    connection::{Connection, ConnectionV4, ConnectionV6, Direction, Key},
    connection_cache::ConnectionCache,
    dbg, err,
    filter_reset_queue::{FilterResetQueue, PendingReset},
    id_cache::IdCache,
    info, logger,
    packet_util::Redirect,
};

/// The most events waiting for user space to read them. Past it, events are dropped (packet
/// events: the packet is blocked), so a stalled reader cannot make the queue grow without bound.
const MAX_EVENTS: usize = 16384;

/// How long a packet waits for its verdict. User space answers in milliseconds; a packet still
/// waiting after this is blocked, so a connect does not hang on an agent that stopped answering.
const PACKET_VERDICT_TIMEOUT_MS: u64 = 30_000;

/// How often the maintenance thread runs (`maintenance`).
const MAINTENANCE_INTERVAL_MS: u32 = 1000;

pub enum Packet {
    PacketLayer(NetBufferList, InjectInfo),
    AleLayer(ClassifyDefer),
}

/// Gives `&self` access to the `FilterEngine`, which needs `&mut` for its WFP transactions.
///
/// It cannot sit behind the `rw_spin_lock::Mutex` like the rest of the shared state: acquiring
/// that raises the IRQL to DISPATCH_LEVEL, while the filter engine calls (`FwpmTransaction*`,
/// filter and callout (un)registration) must run at PASSIVE_LEVEL. A kernel mutex keeps the IRQL
/// where it is, so the teardown (`shutdown`) and the filter resets (`reset_filters_and_inject`)
/// take turns, and a reset sees the filters the teardown removed instead of adding them back.
pub struct FilterEngineCell {
    inner: KMutex<FilterEngine>,
}

impl FilterEngineCell {
    fn new(filter_engine: FilterEngine) -> Self {
        Self {
            inner: KMutex::new(filter_engine),
        }
    }

    /// Runs `f` with exclusive access to the filter engine. Must only be called at PASSIVE_LEVEL,
    /// and never from within `f`.
    pub fn with<R>(&self, f: impl FnOnce(&mut FilterEngine) -> R) -> R {
        let mut filter_engine = self.inner.lock();
        f(&mut filter_engine)
    }
}

// Device Context
pub struct Device {
    // The device-facing API is `&self` (see `get_device`) so producer (callout)
    // and consumer (read) threads can share one `&Device` soundly. Every field
    // is interior-mutable; the filter engine through `FilterEngineCell`.
    pub filter_engine: FilterEngineCell,
    pub(crate) pending_event: PendingEvent,
    pub(crate) event_queue: IOQueue<Info>,
    pub packet_cache: IdCache,
    pub connection_cache: ConnectionCache,
    pub injector: Injector,
    pub(crate) network_allocator: NetworkAllocator,
    /// Connections that were deferred without a completion handle and are waiting for the filter
    /// reset that releases them. See `reset_filters_and_inject`.
    filter_reset_queue: FilterResetQueue,
    /// Set once the teardown has begun. Callouts check it and stop pending operations, because
    /// from that point on nothing is left to answer a pend.
    shutdown_started: AtomicBool,
    /// Blocks the packets that waited too long for a verdict. Runs at PASSIVE_LEVEL, because
    /// releasing a connection held by a filter takes a filter reset.
    maintenance: PeriodicWorker,
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

        // Started last, so a failure above leaves no thread behind. Until the device is published
        // (`entry::DEVICE`) its runs find nothing to do.
        let maintenance = PeriodicWorker::start(MAINTENANCE_INTERVAL_MS, maintenance)?;

        Ok(Self {
            filter_engine: FilterEngineCell::new(filter_engine),
            pending_event: PendingEvent::new(),
            event_queue: IOQueue::new(MAX_EVENTS),
            packet_cache: IdCache::new(),
            connection_cache: ConnectionCache::new()?,
            injector: Injector::new(),
            network_allocator: NetworkAllocator::new(),
            filter_reset_queue: FilterResetQueue::new(),
            shutdown_started: AtomicBool::new(false),
            maintenance,
        })
    }

    /// Reports whether the teardown has started. Callouts must not pend a new operation once this
    /// is set: the packet cache is being drained and the user space handle is on its way out, so
    /// a pend made now would never be completed.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_started.load(Ordering::SeqCst)
    }

    /// Whether user space is not keeping up: the packet cache or the event queue is full. Callouts
    /// check it before capturing a packet, and block the packet (fail closed) instead of pending it.
    pub fn is_backlogged(&self) -> bool {
        self.packet_cache.is_full() || self.event_queue.is_full()
    }

    /// Hands a captured packet to user space: into the packet cache to wait for its verdict, and
    /// its event into the event queue. Callable at DISPATCH_LEVEL.
    pub fn queue_packet(
        &self,
        key: Key,
        packet: Packet,
        process_id: u64,
        direction: Direction,
        ale_layer: bool,
    ) {
        let (id, info) = self
            .packet_cache
            .push((key, packet), process_id, direction, ale_layer);

        // Without an event (no address to report) the packet waits until it expires.
        let Some(info) = info else {
            return;
        };
        // The queue filled up since the caller checked `is_backlogged`, and user space will never
        // hear of the packet. A copy from the packet layer is simply dropped. A pended ALE
        // operation is left to expire: completing it here, inside the classify that pended it,
        // would reenter the classify.
        if self.event_queue.push(info).is_err() && !ale_layer {
            _ = self.packet_cache.pop_id(id);
        }
    }

    /// Blocks a captured packet that user space did not answer. A pended connection that is still
    /// undecided is failed first, so the classify its reinjection triggers blocks it; one that got
    /// a verdict in the meantime keeps it. PASSIVE_LEVEL only: a connection held by a filter is
    /// released by a filter reset.
    fn resolve_unanswered(&self, key: Key, packet: Packet) {
        if let Packet::AleLayer(_) = packet {
            self.connection_cache.fail_if_undecided(&key);
        }
        if let Err(err) = self.inject_blocked_packet(packet) {
            err!("failed to inject packet: {} key={}", err, key);
        }
    }

    /// Blocks the packets that have waited `PACKET_VERDICT_TIMEOUT_MS` for a verdict.
    /// PASSIVE_LEVEL only.
    fn expire_unanswered_packets(&self) {
        let cutoff = wdk::utils::get_monotonic_ms().saturating_sub(PACKET_VERDICT_TIMEOUT_MS);
        let expired = self.packet_cache.pop_expired(cutoff);
        if expired.is_empty() {
            return;
        }

        err!(
            "no verdict for {} packet(s) after {} ms, blocking them",
            expired.len(),
            PACKET_VERDICT_TIMEOUT_MS
        );
        for (key, packet) in expired {
            self.resolve_unanswered(key, packet);
        }
    }

    /// Cleanup is called just before drop.
    // pub fn cleanup(&mut self) {}

    fn write_buffer(&self, read_request: &mut ReadRequest, info: Info) {
        let count = read_request.write(info.as_bytes());

        // Check if the full event was written.
        if count < info.as_bytes().len() {
            // Keep the rest for the next read.
            self.pending_event.stash(info.into_bytes(), count);
        }
    }

    /// Called when handle. Read is called from user-space.
    // TODO: Waits on this thread until an event arrives; see the TODO at `entry::driver_read`.
    pub fn read(&self, read_request: &mut ReadRequest) {
        // The rest of an event that did not fit in the previous read goes first.
        if !self.pending_event.send(read_request) {
            // Noting left from before. Wait for next commands.
            match self.event_queue.wait_and_pop() {
                Ok(info) => {
                    self.write_buffer(read_request, info);
                }
                Err(ioqueue::Status::Timeout) => {
                    // Timeout. This will only trigger if pop function is called with timeout.
                    read_request.set_timeout();
                    return;
                }
                Err(err) => {
                    // Queue failed. Send EOF, to notify user-space. Usually happens on rundown.
                    err!("failed to pop value: {}", err);
                    read_request.set_end_of_file();
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
        read_request.set_success();
    }

    // Called when handle.Write is called from user-space.
    pub fn write(&self, write_request: &mut WriteRequest) {
        // Try parsing the command.
        let mut buffer = write_request.get_buffer();
        let command = protocol::command::parse_type(buffer);
        let Some(command) = command else {
            err!("unknown or empty command ({} bytes)", buffer.len());
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
                let Some(verdict) = protocol::command::parse_verdict(buffer) else {
                    err!("verdict command too short ({} bytes)", buffer.len());
                    return;
                };
                wdk::dbg!("Verdict command");
                // Received verdict decision for a specific connection.
                if let Some((key, mut packet)) = self.packet_cache.pop_id(verdict.id) {
                    // Every packet taken from the cache must be injected, as allowed or as blocked:
                    // dropping a pended connection leaves it waiting forever. An out-of-range verdict
                    // is a user space bug, so the connection is blocked rather than left pended.
                    let verdict_value = verdict.verdict;
                    let verdict = FromPrimitive::from_u8(verdict_value).unwrap_or_else(|| {
                        err!("invalid verdict value {} for {}, blocking", verdict_value, key);
                        crate::connection::Verdict::Failed
                    });
                    dbg!("Verdict received {}: {}", key, verdict);
                    // Add verdict in the cache.
                    let redirect_info = self.connection_cache.update_connection(key, verdict);

                    match verdict {
                        crate::connection::Verdict::Accept
                        | crate::connection::Verdict::PermanentAccept => {
                            if let Err(err) = self.inject_permitted_packet(packet) {
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
                                if let Err(err) = self.inject_permitted_packet(packet) {
                                    err!("failed to inject packet: {} key={}", err, key);
                                }
                            } else {
                                // The connection is no longer in the cache (cleared since the
                                // packet was pended), so there is nowhere to redirect it to.
                                err!("no redirect info for {}, blocking", key);
                                if let Err(err) = self.inject_blocked_packet(packet) {
                                    err!("failed to inject packet: {} key={}", err, key);
                                }
                            }
                        }
                        _ => {
                            if let Err(err) = self.inject_blocked_packet(packet) {
                                err!("failed to inject packet: {} key={}", err, key);
                            }
                        }
                    }
                } else {
                    // Id was not in the packet cache.
                    let id = verdict.id;
                    err!("Verdict invalid id: {}", id);
                }
            }
            CommandType::UpdateV4 => {
                let Some(update) = protocol::command::parse_update_v4(buffer) else {
                    err!("updateV4 command too short ({} bytes)", buffer.len());
                    return;
                };
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
                let Some(update) = protocol::command::parse_update_v6(buffer) else {
                    err!("updateV6 command too short ({} bytes)", buffer.len());
                    return;
                };
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
                // Goes through the same queue as the deferred reauthorizations: it is the same
                // reset, and only one of them can run at a time. Carries no packet of its own.
                self.reset_filters_and_inject(None);
            }
            CommandType::GetConnectionsUpdate => {
                let Some(update) = protocol::command::parse_update_info(buffer) else {
                    err!("getConnectionsUpdate command too short ({} bytes)", buffer.len());
                    return;
                };
                // Report the connections that saw traffic since the previous update. The
                // request carries the timestamp the driver sent in that update's end event
                // (0 for the first); user space stores it without interpreting it. Ended
                // connections are left out: their end event already carried the final
                // counters, and the agent has dropped them.
                let since = update.timestamp;
                // Taken before the walk, and `since` is inclusive: a connection touched
                // while the walk runs is reported again next time rather than missed.
                let now = wdk::utils::get_monotonic_ms();
                wdk::dbg!("GetConnectionsUpdate command");

                let send_event_v4 = |conn: &ConnectionV4| {
                    // Function is behind spin lock. Dont do expensive operations.
                    if conn.has_ended() || conn.last_accessed_timestamp.load(Ordering::SeqCst) < since {
                        return;
                    }

                    let info = conn.update_info();
                    _ = self.event_queue.push(info);
                };

                let send_event_v6 = |conn: &ConnectionV6| {
                    // Function is behind spin lock. Dont do expensive operations.
                    if conn.has_ended() || conn.last_accessed_timestamp.load(Ordering::SeqCst) < since {
                        return;
                    }

                    let info = conn.update_info();
                    _ = self.event_queue.push(info);
                };

                self.connection_cache
                    .walk_over_connections_v4(send_event_v4);
                self.connection_cache
                    .walk_over_connections_v6(send_event_v6);

                _ = self
                    .event_queue
                    .push(protocol::info::connection_update_end_info(now));
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
                let filter_reset_count = self.filter_reset_queue.get_entries_count();
                let packets_expired = self.packet_cache.get_expired_count();

                {
                    let mut log_line = protocol::info::log_line(
                        protocol::info::Severity::Info,
                        logger::MAX_LOG_LINE_SIZE,
                    );
                    _ = write!(
                        log_line,
                        "MemStats: connections active={} ended={} | packet_cache={} expired={} | events queued={} dropped={} | filter_reset_queue={}",
                        active,
                        ended,
                        packet_cache_count,
                        packets_expired,
                        self.event_queue.queued_count(),
                        self.event_queue.dropped_count(),
                        filter_reset_count
                    );
                    logger::add_line(log_line);
                }

                self.connection_cache.walk_over_connections_v4(log_connection);
                self.connection_cache.walk_over_connections_v6(log_connection);
            }
            CommandType::CleanEndedConnections => {
                wdk::dbg!("CleanEndedConnections command");
                // The events are built while the evicted connections are still alive: they are
                // freed as they are removed.
                let infos = self.connection_cache.clean_ended_connections(
                    |conn: &ConnectionV4| {
                        conn.end_info(conn.get_process_id())
                    },
                    |conn: &ConnectionV6| {
                        conn.end_info(conn.get_process_id())
                    },
                );
                for info in infos {
                    _ = self.event_queue.push(info);
                }
            }
        }
    }

    /// Tears the device down, in the only order that leaves nothing behind for the unload:
    /// remove the filters, complete everything that is still pended, then remove the callouts.
    ///
    /// Reachable from the shutdown command (write) and from the unload path,
    /// and safe to call more than once: the one-time part runs once, the rest runs on every call
    /// so anything that raced in afterwards is still resolved.
    pub fn shutdown(&self) {
        if !self.shutdown_started.swap(true, Ordering::SeqCst) {
            // Stop expiring packets first: from here on the teardown resolves them all.
            self.maintenance.stop();

            // Remove the filters before anything else. Once they are gone no new classify call can
            // reach the callouts, so no new connection can be pended while the teardown runs. The
            // flag set above covers the classify calls that are already in flight.
            if let Err(err) = self.filter_engine.with(|fe| fe.unregister_filters()) {
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
        if let Err(err) = self.filter_engine.with(|fe| fe.unregister_callouts()) {
            err!("failed to unregister callouts on shutdown: {}", err);
        }
    }

    /// Completes every operation still held in the packet cache. A pended ALE operation keeps its
    /// IRP alive inside the callout: if the driver unloads while one is still outstanding, that
    /// IRP can never be completed, the thread that owns it never leaves kernel mode, and its
    /// process can no longer be terminated. Everything is resolved with a verdict here so the
    /// callouts can be unregistered cleanly.
    fn complete_pending_packets(&self) {
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
                _ = self.inject_blocked_packet(packet);
            }
        }
    }

    /// Injects a captured packet that was permitted: a copy from the packet layer goes out, a
    /// pended ALE packet is reinjected (`reinject_ale`).
    pub fn inject_permitted_packet(&self, packet: Packet) -> Result<(), String> {
        match packet {
            Packet::PacketLayer(nbl, inject_info) => {
                self.injector.inject_net_buffer_list(nbl, inject_info)
            }
            Packet::AleLayer(defer) => self.reinject_ale(defer),
        }
    }

    /// Injects a captured packet that was blocked, where an injection is needed. A pended ALE
    /// packet is reinjected (`reinject_ale`) and the cached verdict blocks it; Windows waits for
    /// it. A copy from the packet layer needs no injection and is dropped.
    pub fn inject_blocked_packet(&self, packet: Packet) -> Result<(), String> {
        match packet {
            Packet::PacketLayer(..) => Ok(()),
            Packet::AleLayer(defer) => self.reinject_ale(defer),
        }
    }

    /// Completes a pended ALE packet and reinjects it, whatever the verdict. The first packet of a
    /// new connection was pended, and Windows waits for it. Injecting it runs it through the
    /// classify again, where the cached verdict (blocked or not) decides it. A pended packet must
    /// never be left without a verdict.
    fn reinject_ale(&self, defer: ClassifyDefer) -> Result<(), String> {
        match defer.resolve() {
            // The pended operation has been completed, so the packet can go out right away.
            DeferResolution::Completed(packet_list) => self.inject_pending(packet_list),
            // The connection is still held by the filter that blocked it. Reset the filters to
            // let it go, then inject.
            DeferResolution::HeldByFilter(packet_list) => {
                self.reset_filters_and_inject(packet_list);
                Ok(())
            }
        }
    }

    /// Resets the filters to let go of the connections that are still held by one, and injects the
    /// packets that were captured with them.
    ///
    /// This is the only place the filters are reset while the driver is running, and the reset only
    /// ever happens on the thread holding the drain claim, so two of them can never run at once.
    /// That matters because a reset opens a WFP write transaction and only one transaction can be
    /// open on the filter engine session at a time.
    ///
    /// The connection is therefore always queued first, never reset for on the spot. Whether the
    /// calling thread goes on to do the work depends only on whether another thread is already doing
    /// it:
    ///  - The claim is free: this thread takes it and works the queue until it runs empty, so its
    ///    own packet is injected before this returns.
    ///  - The claim is taken: this returns right away. The holder's next reset releases this
    ///    connection too — it was deferred before that reset, which is all it takes.
    ///
    /// Nothing is lost either way: the entry is queued before the claim is even looked at, and the
    /// claim is only given back while the queue is empty (see `filter_reset_queue`).
    ///
    /// A reset that still loses the race for the transaction — against the teardown removing the
    /// filters, or the initial commit registering them — is retried every
    /// `FILTER_RESET_RETRY_INTERVAL_MS`, up to `FILTER_RESET_MAX_ATTEMPTS` times, with everything
    /// that piled up in the meantime released by the same reset. Waiting means this is only usable
    /// at IRQL <= APC_LEVEL; every caller reaches it from a user space write or from the teardown,
    /// so that holds.
    ///
    /// Reports failures through the log rather than to the caller: a reset serves a whole batch, so
    /// a failed one is not attributable to the connection that happened to trigger it.
    fn reset_filters_and_inject(&self, pending: PendingReset) {
        if !self.filter_reset_queue.push_and_claim(pending) {
            return;
        }

        // Attempts spent in a row on the current batch.
        let mut attempts = 0;

        loop {
            // Take everything that is queued: one reset releases all of it. Only what was queued
            // before the reset, though — whatever arrives while the transaction below runs is not
            // released by it and stays queued for the next pass.
            //
            // This is also the only way out of the loop, and it gives the claim back under the same
            // lock that guards the entries, so the queue can never be left with work and no worker.
            let Some(batch) = self.filter_reset_queue.take_all_or_release() else {
                return;
            };

            match self.filter_engine.with(|fe| fe.reset_all_filters()) {
                Ok(()) => {
                    // This attempt counts too.
                    let attempts_taken = attempts + 1;
                    attempts = 0;
                    let len = batch.len();
                    for pending in batch {
                        if let Err(err) = self.inject_pending(pending) {
                            err!("failed to inject packet after filter reset: {}", err);
                        }
                    }
                    info!(
                        "injected {} reauthorized packets after {} attempt(s)",
                        len, attempts_taken
                    )
                }
                Err(ResetError::TransactionInProgress) => {
                    attempts += 1;
                    if attempts >= 20 {
                        // Give up on this batch. The packets are freed with it and the connections
                        // stay held; the peer retransmits and the next packet is classified again.
                        err!(
                            "giving up on the filter reset after {} attempts, dropping {} packet(s)",
                            attempts,
                            batch.len()
                        );
                        attempts = 0;
                        continue;
                    }

                    // Nothing was changed by the failed attempt, so put the batch back and try the
                    // same reset again. A failed wait only makes the attempts come faster, not
                    // endlessly: they stay bounded and the loop still ends once the queue is empty.
                    self.filter_reset_queue.push_front_all(batch);
                    if let Err(err) = wdk::utils::sleep_ms(10) {
                        err!("failed to wait before the next filter reset: {}", err);
                    }
                }
                Err(err) => {
                    // Not transient. Drop the batch with its packets and carry on with the queue.
                    err!(
                        "failed to reset filters: {}, dropping {} packet(s)",
                        String::from(err),
                        batch.len()
                    );
                    attempts = 0;
                }
            }
        }
    }

    /// Injects a packet captured with a deferred connection, if there was one to capture.
    fn inject_pending(&self, pending: PendingReset) -> Result<(), String> {
        let Some(packet_list) = pending else {
            return Ok(());
        };

        return self.injector.inject_packet_list_transport(packet_list);
    }
}

/// Logs one line describing `conn`, for PrintMemoryStats.
fn log_connection<T: Connection>(conn: &T) {
    use core::fmt::Write;

    let proto = match conn.get_protocol() {
        IpProtocol::Tcp => "TCP",
        IpProtocol::Udp => "UDP",
        _ => "???",
    };
    let status = if conn.has_ended() { " [ENDED]" } else { "" };
    let bandwidth = conn.get_bandwidth_usage();
    let mut log_line =
        protocol::info::log_line(protocol::info::Severity::Info, logger::MAX_LOG_LINE_SIZE);
    _ = write!(
        log_line,
        "[{}][{}] {}:{}-{}:{} pid={} {} rx={}B tx={}B{}",
        proto,
        conn.get_direction(),
        conn.get_local_address(),
        conn.get_local_port(),
        conn.get_remote_address(),
        conn.get_remote_port(),
        conn.get_process_id(),
        conn.get_verdict(),
        bandwidth.rx_bytes.load(Ordering::SeqCst),
        bandwidth.tx_bytes.load(Ordering::SeqCst),
        status,
    );
    logger::add_line(log_line);
}

/// The maintenance thread's routine, every `MAINTENANCE_INTERVAL_MS` at PASSIVE_LEVEL.
fn maintenance() {
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    device.expire_unanswered_packets();
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
