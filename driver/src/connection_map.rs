use core::{fmt::Display, time::Duration};

use crate::connection::Connection;
use alloc::vec::Vec;
use hashbrown::HashMap;
use smoltcp::wire::{IpAddress, IpProtocol};

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
    /// Returns the protocol and port as a tuple.
    pub fn small(&self) -> (IpProtocol, u16) {
        (self.protocol, self.local_port)
    }

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

pub struct ConnectionMap<T: Connection>(HashMap<(IpProtocol, u16), Vec<T>>);

impl<T: Connection + Clone> ConnectionMap<T> {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(&mut self, conn: T) {
        let key = conn.get_key().small();
        if let Some(connections) = self.0.get_mut(&key) {
            connections.push(conn);
        } else {
            self.0.insert(key, alloc::vec![conn]);
        }
    }

    pub fn get_mut(&mut self, key: &Key) -> Option<&mut T> {
        if let Some(connections) = self.0.get_mut(&key.small()) {
            for conn in connections {
                if conn.remote_equals(key) {
                    conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                    return Some(conn);
                }
            }
        }

        None
    }

    pub fn read<C>(&self, key: &Key, read_connection: fn(&T) -> Option<C>) -> Option<C> {
        if let Some(connections) = self.0.get(&key.small()) {
            for conn in connections {
                if conn.remote_equals(key) {
                    conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                    return read_connection(conn);
                }
                if conn.redirect_equals(key) {
                    conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                    return read_connection(conn);
                }
            }
        }

        None
    }

    pub fn end(&mut self, key: Key) -> Option<T> {
        if let Some(connections) = self.0.get_mut(&key.small()) {
            for (_, conn) in connections.iter_mut().enumerate() {
                if conn.remote_equals(&key) {
                    conn.end(wdk::utils::get_system_timestamp_ms());
                    return Some(conn.clone());
                }
            }
        }
        return None;
    }

    pub fn end_all_on_port(&mut self, key: (IpProtocol, u16)) -> Option<Vec<T>> {
        if let Some(connections) = self.0.get_mut(&key) {
            let mut vec = Vec::with_capacity(connections.len());
            for (_, conn) in connections.iter_mut().enumerate() {
                if !conn.has_ended() {
                    conn.end(wdk::utils::get_system_timestamp_ms());
                    vec.push(conn.clone());
                }
            }
            return Some(vec);
        }
        return None;
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn clean_ended_connections(&mut self, removed_connections: &mut Vec<T>) {
        // Have a limit how much connections can be removed at once.
        // Removing thousand connections at once can take significant time that can cause callouts to block and the OS to crash.
        const LIMIT_OF_REMOVED_CONNECTIONS: u32 = 100;

        let now = wdk::utils::get_system_timestamp_ms();
        const TWO_MINUETS: u64 = Duration::from_secs(60 * 2).as_millis() as u64;
        let before_two_minutes = now - TWO_MINUETS;
        let before_one_minute = now - Duration::from_secs(60).as_millis() as u64;

        let mut removed_count = 0;

        self.0.retain(|_, connections| {
            connections.retain(|c| {
                if removed_count >= LIMIT_OF_REMOVED_CONNECTIONS {
                    // Limit reached, keep the rest.
                    return true;
                }

                if c.has_ended() && c.get_end_time() < before_one_minute {
                    // Ended more than 1 minute ago
                    // End event was already reported, no need to add it to removed_connections.
                    removed_count += 1;
                    return false;
                }

                if removed_connections.capacity() > removed_connections.len() {
                    // Only remove connections if there is enough space in the supplied array.
                    if c.get_last_accessed_time() < before_two_minutes {
                        // Last active more than 2 minutes ago
                        removed_connections.push(c.clone());
                        removed_count += 1;
                        return false;
                    }
                }

                // Keep
                return true;
            });
            !connections.is_empty()
        });
    }

    #[allow(dead_code)]
    pub fn get_count(&self) -> usize {
        let mut count = 0;
        for conn in self.0.values() {
            count += conn.len();
        }
        return count;
    }

    pub fn iter(&self) -> hashbrown::hash_map::Iter<'_, (IpProtocol, u16), Vec<T>> {
        self.0.iter()
    }
}
