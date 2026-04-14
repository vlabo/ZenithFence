use core::mem;

use alloc::collections::VecDeque;
use protocol::info::Info;
use smoltcp::wire::{IpAddress, IpProtocol};
use wdk::rw_spin_lock::Mutex;

use crate::{connection::{Direction, Key}, device::Packet};

pub const PACKET_MISSING_ID: u64 = u64::MAX;

pub struct Entry<T> {
    pub value: T,
    id: u64,
}

pub struct IdCache {
    values: Mutex<VecDeque<Entry<(Key, Packet)>>>,
    next_id: u64,
}

impl IdCache {
    pub fn new() -> Self {
        Self {
            values: Mutex::new(VecDeque::with_capacity(1000)),
            next_id: 1, // 0 is invalid id
        }
    }

    pub fn push(
        &mut self,
        value: (Key, Packet),
        process_id: u64,
        direction: Direction,
        ale_layer: bool,
    ) -> Option<Info> {
        let id = self.next_id;
        let info = build_info(&value.0, id, process_id, direction, &value.1, ale_layer);
        let mut values = self.values.write_lock();
        values.push_back(Entry { value, id });
        self.next_id = self.next_id.wrapping_add(1); // Assuming this will not overflow.

        // PACKET_MISSING_ID is not checked since there needs to be 18446744073709551614 connection created until it reaches that id.
        // Practically impossible and the impact is just one dropped packet.

        return info;
    }

    pub fn pop_id(&mut self, id: u64) -> Option<(Key, Packet)> {
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

    pub fn pop_all(&mut self) -> VecDeque<Entry<(Key, Packet)>> {
        let mut new_values = VecDeque::with_capacity(1);
        let mut values = self.values.write_lock();
        mem::swap(&mut *values, &mut new_values);

        return new_values;
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

pub fn build_loopback_info(key: &Key, process_id: u64, direction: Direction) -> Option<Info> {
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

    let payload_layer = if ale_layer {
        4 // Transport layer
    } else {
        3 // Network layer
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
