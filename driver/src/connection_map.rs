use core::{fmt::Display, time::Duration};

use crate::connection::{Connection, Direction, RedirectInfo, Verdict};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use smoltcp::wire::{IpAddress, IpProtocol};
use wdk::rw_spin_lock::Mutex;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub struct Key {
    pub(crate) protocol: IpProtocol,
    pub(crate) local_address: IpAddress,
    pub(crate) local_port: u16,
    pub(crate) remote_address: IpAddress,
    pub(crate) remote_port: u16,
}

impl Display for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "p: {} l: {}:{} r: {}:{}",
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address,
            self.remote_port
        )
    }
}

impl Key {
    /// Returns true if the local address is an IPv4 address.
    pub fn is_ipv6(&self) -> bool {
        match self.local_address {
            IpAddress::Ipv4(_) => false,
            IpAddress::Ipv6(_) => true,
        }
    }

    /// Returns true if the local address is a loopback address.
    pub fn is_loopback(&self) -> bool {
        match self.local_address {
            IpAddress::Ipv4(ip) => ip.is_loopback(),
            IpAddress::Ipv6(ip) => ip.is_loopback(),
        }
    }

    /// Returns a new key with the local and remote addresses and ports reversed.
    #[allow(dead_code)]
    pub fn reverse(&self) -> Key {
        Key {
            protocol: self.protocol,
            local_address: self.remote_address,
            local_port: self.remote_port,
            remote_address: self.local_address,
            remote_port: self.local_port,
        }
    }
}

struct Port<T: Connection> {
    conns: Vec<T>,
}

pub struct ConnectionMap<T: Connection> {
    tcp: Box<[Option<Arc<Mutex<Port<T>>>>]>,
    udp: Box<[Option<Arc<Mutex<Port<T>>>>]>,
}

impl<T: Connection + Clone> ConnectionMap<T> {
    pub fn new() -> Self {
        Self {
            tcp: vec![None; u16::MAX as usize].into_boxed_slice(),
            udp: vec![None; u16::MAX as usize].into_boxed_slice(),
        }
    }

    pub fn add(&mut self, conn: T) {
        let array = match conn.get_protocol() {
            IpProtocol::Tcp => &mut self.tcp,
            IpProtocol::Udp => &mut self.udp,
            _ => return,
        };

        let port = match array[conn.get_local_port() as usize].clone() {
            Some(port) => port.clone(),
            None => {
                let p = Arc::new(Mutex::new(Port {
                    conns: Vec::<T>::with_capacity(1),
                }));
                array[conn.get_local_port() as usize] = Some(p.clone());
                p
            }
        };

        let mut port = port.write_lock();
        port.conns.push(conn);
    }

    pub fn update_verdict(&mut self, key: Key, verdict: Verdict) -> Option<RedirectInfo> {
        let port = match self.find_port(key.protocol, key.local_port) {
            Some(ptr) => ptr,
            None => return None,
        };
        let mut port = port.write_lock();

        for conn in &mut port.conns {
            if conn.remote_equals(&key) {
                conn.set_verdict(verdict);
                return conn.redirect_info();
            }
        }
        return None;
    }

    pub fn read_update_bd_usage<C>(
        &self,
        key: &Key,
        byte_size: u64,
        direction: Direction,
        read_connection: fn(&T) -> Option<C>,
    ) -> Option<C> {
        let port = match self.find_port(key.protocol, key.local_port) {
            Some(ptr) => ptr,
            None => return None,
        };
        let mut port = port.write_lock();

        for conn in &mut port.conns {
            if conn.remote_equals(key) {
                conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                conn.update_bandwidth_data(byte_size, direction);
                return read_connection(conn);
            }
            if conn.redirect_equals(key) {
                conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                conn.update_bandwidth_data(byte_size, direction);
                return read_connection(conn);
            }
        }

        None
    }

    pub fn read<C>(&self, key: &Key, read_connection: fn(&T) -> Option<C>) -> Option<C> {
        let port = match self.find_port(key.protocol, key.local_port) {
            Some(ptr) => ptr,
            None => return None,
        };
        let mut port = port.write_lock();

        for conn in &mut port.conns {
            if conn.remote_equals(key) {
                conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                return read_connection(conn);
            }
            if conn.redirect_equals(key) {
                conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                return read_connection(conn);
            }
        }

        None
    }

    pub fn end(&mut self, key: Key) -> Option<T> {
        let port = match self.find_port(key.protocol, key.local_port) {
            Some(ptr) => ptr,
            None => return None,
        };
        let mut port = port.write_lock();

        for (_, conn) in port.conns.iter_mut().enumerate() {
            if conn.remote_equals(&key) {
                conn.end(wdk::utils::get_system_timestamp_ms());
                return Some(conn.clone());
            }
        }
        return None;
    }

    pub fn end_all_on_port(&mut self, key: (IpProtocol, u16)) -> Option<Vec<T>> {
        let port = match self.find_port(key.0, key.1) {
            Some(ptr) => ptr,
            None => return None,
        };
        let mut port = port.write_lock();

        let mut vec = Vec::with_capacity(port.conns.len());
        for (_, conn) in port.conns.iter_mut().enumerate() {
            if !conn.has_ended() {
                conn.end(wdk::utils::get_system_timestamp_ms());
                vec.push(conn.clone());
            }
        }
        return Some(vec);
    }

    /// clear removes all verdicts from the cache.
    pub fn clear(&mut self) {
        // Reset all values in the array
        for c in &mut self.tcp {
            _ = c.take()
        }
        for c in &mut self.udp {
            _ = c.take()
        }
    }

    pub fn clean_ended_connections(&mut self, removed_connections: &mut Vec<T>) {
        let now = wdk::utils::get_system_timestamp_ms();
        const TWO_MINUETS: u64 = Duration::from_secs(60 * 2).as_millis() as u64;
        let before_two_minutes = now - TWO_MINUETS;
        let before_one_minute = now - Duration::from_secs(60).as_millis() as u64;

        fn clean_ports<T: Connection + Clone>(
            ports: &mut [Option<Arc<Mutex<Port<T>>>>],
            removed_connections: &mut Vec<T>,
            before_one_minute: u64,
            before_two_minutes: u64,
        ) {
            for p in ports {
                let mut is_empty = false;
                if let Some(port_arc) = p {
                    // Lock port
                    let mut port = port_arc.write_lock();
                    port.conns.retain(|c| {
                        if c.has_ended() && c.get_end_time() < before_one_minute {
                            // Ended more than 1 minute ago
                            // End event was already reported, no need to add it to removed_connections.
                            return false;
                        }

                        if removed_connections.capacity() > removed_connections.len() {
                            // Only remove connections if there is enough space in the supplied array.
                            if c.get_last_accessed_time() < before_two_minutes {
                                // Last active more than 2 minutes ago
                                removed_connections.push(c.clone());
                                return false;
                            }
                        }
                        true
                    });
                    is_empty = port.conns.is_empty();
                }
                // If there are no more connections in the port. Clean it.
                if is_empty {
                    *p = None;
                }
            }
        }

        clean_ports(
            &mut self.tcp,
            removed_connections,
            before_one_minute,
            before_two_minutes,
        );
        clean_ports(
            &mut self.udp,
            removed_connections,
            before_one_minute,
            before_two_minutes,
        );
    }

    pub fn walk_over_connections<F: FnMut(&T)>(&mut self, mut iter: F) {
        // Iterate over TCP ports.
        for p in &mut self.tcp {
            if let Some(port_arc) = p {
                // Lock port
                let port = port_arc.read_lock();
                for c in &port.conns {
                    iter(c);
                }
            }
        }

        // Iterate over UDP ports.
        for p in &mut self.udp {
            if let Some(port_arc) = p {
                // Lock port
                let port = port_arc.read_lock();
                for c in &port.conns {
                    iter(c);
                }
            }
        }
    }

    fn find_port(&self, protocol: IpProtocol, port: u16) -> Option<Arc<Mutex<Port<T>>>> {
        let array = match protocol {
            IpProtocol::Tcp => &self.tcp,
            IpProtocol::Udp => &self.udp,
            _ => return None,
        };

        // Copy the Arc. This will hold active reference to the port while it is alive.
        return array[port as usize].clone();
    }
}
