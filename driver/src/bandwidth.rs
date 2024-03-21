use alloc::boxed::Box;
use protocol::info::{BandwidthStatArray, BandwidthValueV4, BandwidthValueV6};
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv6Address};
use wdk::rw_spin_lock::RwMutex;

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
    stats_tcp_v4: RwMutex<DeviceHashMap<Key<Ipv4Address>, Value>>,
    stats_tcp_v6: RwMutex<DeviceHashMap<Key<Ipv6Address>, Value>>,
    stats_udp_v4: RwMutex<DeviceHashMap<Key<Ipv4Address>, Value>>,
    stats_udp_v6: RwMutex<DeviceHashMap<Key<Ipv6Address>, Value>>,
}

impl Bandwidth {
    pub fn new() -> Self {
        Self {
            stats_tcp_v4: RwMutex::new(DeviceHashMap::new()),
            stats_tcp_v6: RwMutex::new(DeviceHashMap::new()),
            stats_udp_v4: RwMutex::new(DeviceHashMap::new()),
            stats_udp_v6: RwMutex::new(DeviceHashMap::new()),
        }
    }

    pub fn get_all_updates_tcp_v4(&mut self) -> Option<Box<BandwidthStatArray<BandwidthValueV4>>> {
        let stats_map;
        {
            let mut stats_tcp_v4 = self.stats_tcp_v4.lock_mut();
            if stats_tcp_v4.is_empty() {
                return None;
            }
            stats_map = stats_tcp_v4.replace(DeviceHashMap::new());
        }

        let mut stats_array = Box::new(BandwidthStatArray::new_v4(
            stats_map.len(),
            u8::from(IpProtocol::Tcp),
        ));
        for (key, value) in stats_map.iter() {
            stats_array.push_value(BandwidthValueV4 {
                local_ip: key.local_ip.0,
                local_port: key.local_port,
                remote_ip: key.remote_ip.0,
                remote_port: key.remote_port,
                transmitted_bytes: value.transmitted_bytes as u64,
                received_bytes: value.received_bytes as u64,
            });
        }
        return Some(stats_array);
    }

    pub fn get_all_updates_tcp_v6(&mut self) -> Option<Box<BandwidthStatArray<BandwidthValueV6>>> {
        let stats_map;
        {
            let mut stats_tcp_v6 = self.stats_tcp_v6.lock_mut();
            if stats_tcp_v6.is_empty() {
                return None;
            }
            stats_map = stats_tcp_v6.replace(DeviceHashMap::new());
        }

        let mut stats_array = Box::new(BandwidthStatArray::new_v6(
            stats_map.len(),
            u8::from(IpProtocol::Tcp),
        ));
        for (key, value) in stats_map.iter() {
            stats_array.push_value(BandwidthValueV6 {
                local_ip: key.local_ip.0,
                local_port: key.local_port,
                remote_ip: key.remote_ip.0,
                remote_port: key.remote_port,
                transmitted_bytes: value.transmitted_bytes as u64,
                received_bytes: value.received_bytes as u64,
            });
        }
        return Some(stats_array);
    }

    pub fn get_all_updates_udp_v4(&mut self) -> Option<Box<BandwidthStatArray<BandwidthValueV4>>> {
        let stats_map;
        {
            let mut stats_udp_v4 = self.stats_udp_v4.lock_mut();
            if stats_udp_v4.is_empty() {
                return None;
            }
            stats_map = stats_udp_v4.replace(DeviceHashMap::new());
        }

        let mut stats_array = Box::new(BandwidthStatArray::new_v4(
            stats_map.len(),
            u8::from(IpProtocol::Udp),
        ));
        for (key, value) in stats_map.iter() {
            stats_array.push_value(BandwidthValueV4 {
                local_ip: key.local_ip.0,
                local_port: key.local_port,
                remote_ip: key.remote_ip.0,
                remote_port: key.remote_port,
                transmitted_bytes: value.transmitted_bytes as u64,
                received_bytes: value.received_bytes as u64,
            });
        }
        return Some(stats_array);
    }

    pub fn get_all_updates_udp_v6(&mut self) -> Option<Box<BandwidthStatArray<BandwidthValueV6>>> {
        let stats_map;
        {
            let mut stats_tcp_v6 = self.stats_tcp_v6.lock_mut();
            if stats_tcp_v6.is_empty() {
                return None;
            }
            stats_map = stats_tcp_v6.replace(DeviceHashMap::new());
        }

        let mut stats_array = Box::new(BandwidthStatArray::new_v6(
            stats_map.len(),
            u8::from(IpProtocol::Udp),
        ));
        for (key, value) in stats_map.iter() {
            stats_array.push_value(BandwidthValueV6 {
                local_ip: key.local_ip.0,
                local_port: key.local_port,
                remote_ip: key.remote_ip.0,
                remote_port: key.remote_port,
                transmitted_bytes: value.transmitted_bytes as u64,
                received_bytes: value.received_bytes as u64,
            });
        }
        return Some(stats_array);
    }

    pub fn update_tcp_v4_tx(&mut self, key: Key<Ipv4Address>, tx_bytes: usize) {
        Self::update(&mut self.stats_tcp_v4, key, Direction::Tx(tx_bytes));
    }

    pub fn update_tcp_v4_rx(&mut self, key: Key<Ipv4Address>, rx_bytes: usize) {
        Self::update(&mut self.stats_tcp_v4, key, Direction::Rx(rx_bytes));
    }

    pub fn update_tcp_v6_tx(&mut self, key: Key<Ipv6Address>, tx_bytes: usize) {
        Self::update(&mut self.stats_tcp_v6, key, Direction::Tx(tx_bytes));
    }

    pub fn update_tcp_v6_rx(&mut self, key: Key<Ipv6Address>, rx_bytes: usize) {
        Self::update(&mut self.stats_tcp_v6, key, Direction::Rx(rx_bytes));
    }

    pub fn update_udp_v4_tx(&mut self, key: Key<Ipv4Address>, tx_bytes: usize) {
        Self::update(&mut self.stats_udp_v4, key, Direction::Tx(tx_bytes));
    }

    pub fn update_udp_v4_rx(&mut self, key: Key<Ipv4Address>, rx_bytes: usize) {
        Self::update(&mut self.stats_udp_v4, key, Direction::Rx(rx_bytes));
    }

    pub fn update_udp_v6_tx(&mut self, key: Key<Ipv6Address>, tx_bytes: usize) {
        Self::update(&mut self.stats_udp_v6, key, Direction::Tx(tx_bytes));
    }

    pub fn update_udp_v6_rx(&mut self, key: Key<Ipv6Address>, rx_bytes: usize) {
        Self::update(&mut self.stats_udp_v6, key, Direction::Rx(rx_bytes));
    }

    fn update<Address: Eq + PartialEq + core::hash::Hash>(
        map: &mut RwMutex<DeviceHashMap<Key<Address>, Value>>,
        key: Key<Address>,
        direction: Direction,
    ) {
        let mut map = map.lock_mut();
        if let Some(value) = map.get_mut(&key) {
            match direction {
                Direction::Tx(bytes_count) => value.transmitted_bytes += bytes_count,
                Direction::Rx(bytes_count) => value.received_bytes += bytes_count,
            }
        } else {
            let mut tx_count = 0;
            let mut rx_count = 0;
            match direction {
                Direction::Tx(bytes_count) => tx_count = bytes_count,
                Direction::Rx(bytes_count) => rx_count = bytes_count,
            }
            map.insert(
                key,
                Value {
                    received_bytes: rx_count,
                    transmitted_bytes: tx_count,
                },
            );
        }
    }

    pub fn get_entries_count(&self) -> usize {
        let mut size = 0;
        size += self.stats_tcp_v4.lock().values().len();
        size += self.stats_tcp_v6.lock().values().len();
        size += self.stats_udp_v4.lock().values().len();
        size += self.stats_udp_v6.lock().values().len();

        return size;
    }
}
