use core::mem;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use alloc::{collections::VecDeque, vec::Vec};
use protocol::info::Info;
use smoltcp::wire::{IpAddress, IpProtocol};
use wdk::rw_spin_lock::Mutex;

use crate::{
    connection::{Direction, Key},
    device::Packet,
};

pub const PACKET_MISSING_ID: u64 = u64::MAX;

/// The most packets held for a verdict at once. Each one is a copy of up to an MTU-sized packet,
/// so this bounds the memory a stalled user space can make the driver hold to a few megabytes.
/// Callers check `is_full` before capturing a packet, so concurrent callouts can overshoot it by
/// about one entry per processor.
pub const MAX_PENDING_PACKETS: usize = 32_768;

pub struct Entry<T> {
    pub value: T,
    id: u64,
    /// When the entry was pushed (`get_monotonic_ms`).
    queued_at_ms: u64,
}

pub struct IdCache {
    values: Mutex<VecDeque<Entry<(Key, Packet)>>>,
    // Interior-mutable so `push` can take `&self`: in the kernel multiple
    // callouts pend packets concurrently (the device is reached through a
    // shared global), so the cache must be safe under `&self`. The id is handed
    // out with `fetch_add` *while holding the values lock* (see `push`).
    next_id: AtomicU64,
    /// Packets taken out by `pop_expired`.
    expired: AtomicUsize,
}

impl IdCache {
    pub fn new() -> Self {
        Self {
            values: Mutex::new(VecDeque::with_capacity(MAX_PENDING_PACKETS)),
            next_id: AtomicU64::new(1), // 0 is invalid id
            expired: AtomicUsize::new(0),
        }
    }

    /// Whether the cache holds `MAX_PENDING_PACKETS`, so no more packets should be captured.
    pub fn is_full(&self) -> bool {
        self.values.read_lock().len() >= MAX_PENDING_PACKETS
    }

    /// Adds a packet awaiting a verdict. Returns its id and the event that tells user space about
    /// it.
    pub fn push(
        &self,
        value: (Key, Packet),
        process_id: u64,
        direction: Direction,
        ale_layer: bool,
    ) -> (u64, Option<Info>) {
        // Assign the id and enqueue under the *same* lock. This keeps the deque
        // ordered by id (pop_id relies on `binary_search_by_key`) and makes
        // duplicate ids impossible even when two threads push concurrently --
        // assigning the id before the lock would let the push order invert
        // relative to id order and break the search invariant.
        let mut values = self.values.write_lock();
        let id = self.next_id.fetch_add(1, Ordering::SeqCst); // Assuming this will not overflow.
        let info = build_info(&value.0, id, process_id, direction, &value.1, ale_layer);
        // Taken under the lock too, so the deque is in time order as well as in id order.
        let queued_at_ms = wdk::utils::get_monotonic_ms();
        values.push_back(Entry {
            value,
            id,
            queued_at_ms,
        });

        // PACKET_MISSING_ID is not checked since there needs to be 18446744073709551614 connection created until it reaches that id.
        // Practically impossible and the impact is just one dropped packet.

        return (id, info);
    }

    pub fn pop_id(&self, id: u64) -> Option<(Key, Packet)> {
        if id == PACKET_MISSING_ID {
            return None;
        }

        let mut values = self.values.write_lock();
        if let Ok(index) = values.binary_search_by_key(&id, |val| val.id) {
            return Some(values.remove(index).unwrap().value);
        }
        None
    }

    #[allow(dead_code)]
    pub fn get_entries_count(&self) -> usize {
        let values = self.values.read_lock();
        return values.len();
    }

    /// Ids of the packets currently waiting for a verdict, oldest first.
    pub fn pending_ids(&self) -> Vec<u64> {
        let values = self.values.read_lock();
        return values.iter().map(|entry| entry.id).collect();
    }

    /// Takes out every packet pushed at or before `cutoff_ms` (`get_monotonic_ms`).
    pub fn pop_expired(&self, cutoff_ms: u64) -> Vec<(Key, Packet)> {
        let mut expired = Vec::new();
        let mut values = self.values.write_lock();
        // The oldest entries are at the front.
        while values
            .front()
            .is_some_and(|entry| entry.queued_at_ms <= cutoff_ms)
        {
            if let Some(entry) = values.pop_front() {
                expired.push(entry.value);
            }
        }
        self.expired.fetch_add(expired.len(), Ordering::Relaxed);
        expired
    }

    /// The number of packets that expired without a verdict.
    pub fn get_expired_count(&self) -> usize {
        self.expired.load(Ordering::Relaxed)
    }

    pub fn pop_all(&self) -> VecDeque<Entry<(Key, Packet)>> {
        let mut new_values = VecDeque::with_capacity(1);
        let mut values = self.values.write_lock();
        mem::swap(&mut *values, &mut new_values);

        return new_values;
    }
}

impl Default for IdCache {
    fn default() -> Self {
        Self::new()
    }
}

fn get_payload<'a>(packet: &'a Packet) -> Option<&'a [u8]> {
    match packet {
        Packet::PacketLayer(nbl, _) => nbl.get_data(),
        Packet::AleLayer(defer) => {
            let p = match defer {
                wdk::filter_engine::callout_data::ClassifyDefer::Initial(_, p) => p,
                wdk::filter_engine::callout_data::ClassifyDefer::Reauthorization(_, p) => p,
            };
            if let Some(tpl) = p {
                tpl.net_buffer_list_queue.get_data()
            } else {
                None
            }
        }
    }
}

/// Builds an informational-only event that carries no packet to reinject (it uses
/// [`PACKET_MISSING_ID`]). Used when the ALE layer only needs to tell user space about a
/// connection and its process id, leaving the real packet to be sent and reinjected by the
/// packet layer. This is the case for inbound loopback and for reauthorized outbound
/// connections (which cannot be pended).
pub fn build_info_only(key: &Key, process_id: u64, direction: Direction) -> Option<Info> {
    let (local_port, remote_port) = match key.protocol {
        IpProtocol::Tcp | IpProtocol::Udp => (key.local_port, key.remote_port),
        _ => (0, 0),
    };

    match (key.local_address, key.remote_address) {
        (IpAddress::Ipv6(local_ip), IpAddress::Ipv6(remote_ip)) if key.is_ipv6() => {
            Some(protocol::info::connection_info_v6(
                PACKET_MISSING_ID,
                process_id,
                direction as u8,
                u8::from(key.protocol),
                local_ip.octets(),
                remote_ip.octets(),
                local_port,
                remote_port,
                4, // Transport layer
                &[],
            ))
        }
        (IpAddress::Ipv4(local_ip), IpAddress::Ipv4(remote_ip)) => {
            Some(protocol::info::connection_info_v4(
                PACKET_MISSING_ID,
                process_id,
                direction as u8,
                u8::from(key.protocol),
                local_ip.octets(),
                remote_ip.octets(),
                local_port,
                remote_port,
                4, // Transport layer
                &[],
            ))
        }
        _ => None,
    }
}

pub fn build_info(
    key: &Key,
    packet_id: u64,
    process_id: u64,
    direction: Direction,
    packet: &Packet,
    ale_layer: bool,
) -> Option<Info> {
    let (local_port, remote_port) = match key.protocol {
        IpProtocol::Tcp | IpProtocol::Udp => (key.local_port, key.remote_port),
        _ => (0, 0),
    };

    // Where the payload starts. Outbound ALE hands over the packet from its
    // transport header; inbound ALE is cloned after retreating over the IP and
    // transport headers (ale_callouts), and the packet layers see the IP header.
    let payload_layer = match (ale_layer, direction) {
        (true, Direction::Outbound) => 4, // Transport layer
        _ => 3,                           // Network layer
    };

    let mut payload = &[][..];
    if let Some(p) = get_payload(packet) {
        payload = p;
    }

    match (key.local_address, key.remote_address) {
        (IpAddress::Ipv6(local_ip), IpAddress::Ipv6(remote_ip)) if key.is_ipv6() => {
            Some(protocol::info::connection_info_v6(
                packet_id,
                process_id,
                direction as u8,
                u8::from(key.protocol),
                local_ip.octets(),
                remote_ip.octets(),
                local_port,
                remote_port,
                payload_layer,
                payload,
            ))
        }
        (IpAddress::Ipv4(local_ip), IpAddress::Ipv4(remote_ip)) => {
            Some(protocol::info::connection_info_v4(
                packet_id,
                process_id,
                direction as u8,
                u8::from(key.protocol),
                local_ip.octets(),
                remote_ip.octets(),
                local_port,
                remote_port,
                payload_layer,
                payload,
            ))
        }
        _ => None,
    }
}
