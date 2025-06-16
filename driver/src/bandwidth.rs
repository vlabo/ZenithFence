use protocol::info::{BandwidthValueV4, BandwidthValueV6, Info};
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv6Address};
use wdk::rw_spin_lock::Mutex;

use crate::driver_hashmap::DeviceHashMap;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Key<Address>
where
    Address: Eq + PartialEq,
{
    pub local_ip: Address,
    pub local_port: u16,
    pub remote_ip: Address,
    pub remote_port: u16,
}

struct Value {
    received_bytes: usize,
    transmitted_bytes: usize,
}

enum Direction {
    Tx(usize),
    Rx(usize),
}
pub struct Bandwidth {
    stats_tcp_v4: Mutex<DeviceHashMap<Key<Ipv4Address>, Value>>,
    stats_tcp_v6: Mutex<DeviceHashMap<Key<Ipv6Address>, Value>>,
    stats_udp_v4: Mutex<DeviceHashMap<Key<Ipv4Address>, Value>>,
    stats_udp_v6: Mutex<DeviceHashMap<Key<Ipv6Address>, Value>>,
}

impl Bandwidth {
    pub fn new() -> Self {
        Self {
            stats_tcp_v4: Mutex::new(DeviceHashMap::new()),
            stats_tcp_v6: Mutex::new(DeviceHashMap::new()),
            stats_udp_v4: Mutex::new(DeviceHashMap::new()),
            stats_udp_v6: Mutex::new(DeviceHashMap::new()),
        }
    }

    pub fn get_all_updates_tcp_v4(&mut self) -> Option<Info> {
        let stats_map;
        {
            let mut stats_tcp_v4 = self.stats_tcp_v4.write_lock();
            if stats_tcp_v4.is_empty() {
                return None;
            }
            stats_map = core::mem::replace(&mut *stats_tcp_v4, DeviceHashMap::new());
        }

        let mut values = alloc::vec::Vec::with_capacity(stats_map.len());
        for (key, value) in stats_map.iter() {
            values.push(BandwidthValueV4 {
                local_ip: key.local_ip.0,
                local_port: key.local_port,
                remote_ip: key.remote_ip.0,
                remote_port: key.remote_port,
                transmitted_bytes: value.transmitted_bytes as u64,
                received_bytes: value.received_bytes as u64,
            });
        }
        Some(protocol::info::bandwidth_stats_array_v4(
            u8::from(IpProtocol::Tcp),
            values,
        ))
    }

    pub fn get_all_updates_tcp_v6(&mut self) -> Option<Info> {
        let stats_map;
        {
            let mut stats_tcp_v6 = self.stats_tcp_v6.write_lock();
            if stats_tcp_v6.is_empty() {
                return None;
            }
            stats_map = core::mem::replace(&mut *stats_tcp_v6, DeviceHashMap::new());
        }

        let mut values = alloc::vec::Vec::with_capacity(stats_map.len());
        for (key, value) in stats_map.iter() {
            values.push(BandwidthValueV6 {
                local_ip: key.local_ip.0,
                local_port: key.local_port,
                remote_ip: key.remote_ip.0,
                remote_port: key.remote_port,
                transmitted_bytes: value.transmitted_bytes as u64,
                received_bytes: value.received_bytes as u64,
            });
        }
        Some(protocol::info::bandwidth_stats_array_v6(
            u8::from(IpProtocol::Tcp),
            values,
        ))
    }

    pub fn get_all_updates_udp_v4(&mut self) -> Option<Info> {
        let stats_map;
        {
            let mut stats_udp_v4 = self.stats_udp_v4.write_lock();
            if stats_udp_v4.is_empty() {
                return None;
            }
            stats_map = core::mem::replace(&mut *stats_udp_v4, DeviceHashMap::new());
        }

        let mut values = alloc::vec::Vec::with_capacity(stats_map.len());
        for (key, value) in stats_map.iter() {
            values.push(BandwidthValueV4 {
                local_ip: key.local_ip.0,
                local_port: key.local_port,
                remote_ip: key.remote_ip.0,
                remote_port: key.remote_port,
                transmitted_bytes: value.transmitted_bytes as u64,
                received_bytes: value.received_bytes as u64,
            });
        }
        Some(protocol::info::bandwidth_stats_array_v4(
            u8::from(IpProtocol::Udp),
            values,
        ))
    }

    pub fn get_all_updates_udp_v6(&mut self) -> Option<Info> {
        let stats_map;
        {
            let mut stats_udp_v6 = self.stats_udp_v6.write_lock();
            if stats_udp_v6.is_empty() {
                return None;
            }
            stats_map = core::mem::replace(&mut *stats_udp_v6, DeviceHashMap::new());
        }

        let mut values = alloc::vec::Vec::with_capacity(stats_map.len());
        for (key, value) in stats_map.iter() {
            values.push(BandwidthValueV6 {
                local_ip: key.local_ip.0,
                local_port: key.local_port,
                remote_ip: key.remote_ip.0,
                remote_port: key.remote_port,
                transmitted_bytes: value.transmitted_bytes as u64,
                received_bytes: value.received_bytes as u64,
            });
        }
        Some(protocol::info::bandwidth_stats_array_v6(
            u8::from(IpProtocol::Udp),
            values,
        ))
    }

    pub fn update_tcp_v4_tx(&mut self, key: Key<Ipv4Address>, tx_bytes: usize) {
        Self::update(&self.stats_tcp_v4, key, Direction::Tx(tx_bytes));
    }

    pub fn update_tcp_v4_rx(&mut self, key: Key<Ipv4Address>, rx_bytes: usize) {
        Self::update(&self.stats_tcp_v4, key, Direction::Rx(rx_bytes));
    }

    pub fn update_tcp_v6_tx(&mut self, key: Key<Ipv6Address>, tx_bytes: usize) {
        Self::update(&self.stats_tcp_v6, key, Direction::Tx(tx_bytes));
    }

    pub fn update_tcp_v6_rx(&mut self, key: Key<Ipv6Address>, rx_bytes: usize) {
        Self::update(&self.stats_tcp_v6, key, Direction::Rx(rx_bytes));
    }

    pub fn update_udp_v4_tx(&mut self, key: Key<Ipv4Address>, tx_bytes: usize) {
        Self::update(&self.stats_udp_v4, key, Direction::Tx(tx_bytes));
    }

    pub fn update_udp_v4_rx(&mut self, key: Key<Ipv4Address>, rx_bytes: usize) {
        Self::update(&self.stats_udp_v4, key, Direction::Rx(rx_bytes));
    }

    pub fn update_udp_v6_tx(&mut self, key: Key<Ipv6Address>, tx_bytes: usize) {
        Self::update(&self.stats_udp_v6, key, Direction::Tx(tx_bytes));
    }

    pub fn update_udp_v6_rx(&mut self, key: Key<Ipv6Address>, rx_bytes: usize) {
        Self::update(&self.stats_udp_v6, key, Direction::Rx(rx_bytes));
    }

    fn update<Address: Eq + PartialEq + core::hash::Hash>(
        map: &Mutex<DeviceHashMap<Key<Address>, Value>>,
        key: Key<Address>,
        bytes: Direction,
    ) {
        let mut map = map.write_lock();
        if let Some(value) = map.get_mut(&key) {
            match bytes {
                Direction::Tx(bytes_count) => value.transmitted_bytes += bytes_count,
                Direction::Rx(bytes_count) => value.received_bytes += bytes_count,
            }
        } else {
            let mut received_bytes = 0;
            let mut transmitted_bytes = 0;
            match bytes {
                Direction::Tx(bytes_count) => transmitted_bytes += bytes_count,
                Direction::Rx(bytes_count) => received_bytes += bytes_count,
            }
            map.insert(
                key,
                Value {
                    received_bytes,
                    transmitted_bytes,
                },
            );
        }
    }
}
