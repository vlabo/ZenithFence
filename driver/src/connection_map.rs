use core::fmt::Display;

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
    pub fn small(&self) -> (IpProtocol, u16) {
        (self.protocol, self.local_port)
    }

    pub fn is_ipv6(&self) -> bool {
        match self.local_address {
            IpAddress::Ipv4(_) => false,
            IpAddress::Ipv6(_) => true,
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self.local_address {
            IpAddress::Ipv4(ip) => ip.is_loopback(),
            IpAddress::Ipv6(ip) => ip.is_loopback(),
        }
    }
}

pub struct ConnectionMap<T: Connection>(HashMap<(IpProtocol, u16), Vec<T>>);

impl<T: Connection> ConnectionMap<T> {
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
                    return read_connection(conn);
                }
                if conn.redirect_equals(key) {
                    return read_connection(conn);
                }
            }
        }

        None
    }

    pub fn remove(&mut self, key: Key) -> Option<T> {
        let mut index = None;
        let mut conn = None;
        let mut delete = false;
        if let Some(connections) = self.0.get_mut(&key.small()) {
            for (i, conn) in connections.iter().enumerate() {
                if conn.remote_equals(&key) {
                    index = Some(i);
                    break;
                }
            }
            if let Some(index) = index {
                conn = Some(connections.remove(index));
            }

            if connections.is_empty() {
                delete = true;
            }
        }
        if delete {
            self.0.remove(&key.small());
        }

        return conn;
    }

    pub fn remove_port(&mut self, key: (IpProtocol, u16)) -> Option<Vec<T>> {
        self.0.remove(&key)
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

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
