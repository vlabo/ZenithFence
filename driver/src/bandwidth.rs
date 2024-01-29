use alloc::boxed::Box;
use protocol::info::{BandwidthStatArray, BandwidthValueV4, BandwidthValueV6};
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv6Address};
use wdk::rw_spin_lock::RwSpinLock;

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

pub struct Bandwidth {
    stats_tcp_v4: DeviceHashMap<Key<Ipv4Address>, Value>,
    stats_tcp_v4_lock: RwSpinLock,

    stats_tcp_v6: DeviceHashMap<Key<Ipv6Address>, Value>,
    stats_tcp_v6_lock: RwSpinLock,

    stats_udp_v4: DeviceHashMap<Key<Ipv4Address>, Value>,
    stats_udp_v4_lock: RwSpinLock,

    stats_udp_v6: DeviceHashMap<Key<Ipv6Address>, Value>,
    stats_udp_v6_lock: RwSpinLock,
}

impl Bandwidth {
    pub fn new() -> Self {
        Self {
            stats_tcp_v4: DeviceHashMap::new(),
            stats_tcp_v4_lock: RwSpinLock::default(),

            stats_tcp_v6: DeviceHashMap::new(),
            stats_tcp_v6_lock: RwSpinLock::default(),

            stats_udp_v4: DeviceHashMap::new(),
            stats_udp_v4_lock: RwSpinLock::default(),

            stats_udp_v6: DeviceHashMap::new(),
            stats_udp_v6_lock: RwSpinLock::default(),
        }
    }

    pub fn get_all_updates_tcp_v4(&mut self) -> Option<Box<BandwidthStatArray<BandwidthValueV4>>> {
        let stats_map;
        {
            let _guard = self.stats_tcp_v4_lock.write_lock();
            if self.stats_tcp_v4.is_empty() {
                return None;
            }
            stats_map = core::mem::replace(&mut self.stats_tcp_v4, DeviceHashMap::new());
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
            let _guard = self.stats_tcp_v6_lock.write_lock();
            if self.stats_tcp_v6.is_empty() {
                return None;
            }
            stats_map = core::mem::replace(&mut self.stats_tcp_v6, DeviceHashMap::new());
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
            let _guard = self.stats_udp_v4_lock.write_lock();
            if self.stats_udp_v4.is_empty() {
                return None;
            }
            stats_map = core::mem::replace(&mut self.stats_udp_v4, DeviceHashMap::new());
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
            let _guard = self.stats_udp_v6_lock.write_lock();
            if self.stats_tcp_v6.is_empty() {
                return None;
            }
            stats_map = core::mem::replace(&mut self.stats_tcp_v6, DeviceHashMap::new());
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
        Self::update(
            &mut self.stats_tcp_v4,
            &mut self.stats_tcp_v4_lock,
            key,
            true,
            tx_bytes,
        );
    }

    pub fn update_tcp_v4_rx(&mut self, key: Key<Ipv4Address>, rx_bytes: usize) {
        Self::update(
            &mut self.stats_tcp_v4,
            &mut self.stats_tcp_v4_lock,
            key,
            false,
            rx_bytes,
        );
    }

    pub fn update_tcp_v6_tx(&mut self, key: Key<Ipv6Address>, tx_bytes: usize) {
        Self::update(
            &mut self.stats_tcp_v6,
            &mut self.stats_tcp_v6_lock,
            key,
            true,
            tx_bytes,
        );
    }

    pub fn update_tcp_v6_rx(&mut self, key: Key<Ipv6Address>, rx_bytes: usize) {
        Self::update(
            &mut self.stats_tcp_v6,
            &mut self.stats_tcp_v6_lock,
            key,
            false,
            rx_bytes,
        );
    }

    pub fn update_udp_v4_tx(&mut self, key: Key<Ipv4Address>, tx_bytes: usize) {
        Self::update(
            &mut self.stats_udp_v4,
            &mut self.stats_udp_v4_lock,
            key,
            true,
            tx_bytes,
        );
    }

    pub fn update_udp_v4_rx(&mut self, key: Key<Ipv4Address>, rx_bytes: usize) {
        Self::update(
            &mut self.stats_udp_v4,
            &mut self.stats_udp_v4_lock,
            key,
            false,
            rx_bytes,
        );
    }

    pub fn update_udp_v6_tx(&mut self, key: Key<Ipv6Address>, tx_bytes: usize) {
        Self::update(
            &mut self.stats_udp_v6,
            &mut self.stats_udp_v6_lock,
            key,
            true,
            tx_bytes,
        );
    }

    pub fn update_udp_v6_rx(&mut self, key: Key<Ipv6Address>, rx_bytes: usize) {
        Self::update(
            &mut self.stats_udp_v6,
            &mut self.stats_udp_v6_lock,
            key,
            false,
            rx_bytes,
        );
    }

    fn update<Address: Eq + PartialEq + core::hash::Hash>(
        map: &mut DeviceHashMap<Key<Address>, Value>,
        lock: &mut RwSpinLock,
        key: Key<Address>,
        tx: bool,
        bytes_count: usize,
    ) {
        let _guard = lock.write_lock();
        if let Some(value) = map.get_mut(&key) {
            if tx {
                value.transmitted_bytes += bytes_count;
            } else {
                value.received_bytes += bytes_count;
            }
        } else {
            let mut tx_count = 0;
            let mut rx_count = 0;
            if tx {
                tx_count = bytes_count;
            } else {
                rx_count = bytes_count;
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
}
