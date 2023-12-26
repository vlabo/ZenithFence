use core::fmt::Display;

use crate::types::Verdict;
use alloc::{collections::BTreeMap, vec::Vec};
use smoltcp::wire::{IpProtocol, Ipv4Address};
use wdk::rw_spin_lock::RwSpinLock;

#[derive(Clone)]
pub enum ConnectionAction {
    Verdict(Verdict),
    RedirectIP {
        redirect_address: Ipv4Address,
        redirect_port: u16,
    },
}

#[derive(Clone)]
pub struct Connection {
    pub(crate) protocol: IpProtocol,
    pub(crate) local_address: Ipv4Address,
    pub(crate) local_port: u16,
    pub(crate) remote_address: Ipv4Address,
    pub(crate) remote_port: u16,
    pub(crate) action: ConnectionAction,
}

impl Connection {
    pub fn get_key(&self) -> Key {
        Key {
            protocol: self.protocol,
            local_address: self.local_address,
            local_port: self.local_port,
            remote_address: self.remote_address,
            remote_port: self.remote_port,
        }
    }

    fn local_equals(&self, key: &Key) -> bool {
        if self.protocol.eq(&key.protocol) {
            return false;
        }

        if self.local_port != key.local_port {
            return false;
        }
        if self.remote_port != key.remote_port {
            return false;
        }

        true
    }

    fn remote_equals(&self, key: &Key) -> bool {
        if !self.local_address.eq(&key.local_address) {
            return false;
        }

        if !self.remote_address.eq(&key.remote_address) {
            return false;
        }

        true
    }

    fn redirect_equals(&self, key: &Key) -> bool {
        match self.action {
            ConnectionAction::RedirectIP {
                redirect_address,
                redirect_port,
            } => {
                if redirect_port != key.remote_port {
                    return false;
                }

                if !redirect_address.eq(&key.remote_address) {
                    return false;
                }

                true
            }
            _ => false,
        }
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord)]
pub struct Key {
    pub(crate) protocol: IpProtocol,
    pub(crate) local_address: Ipv4Address,
    pub(crate) local_port: u16,
    pub(crate) remote_address: Ipv4Address,
    pub(crate) remote_port: u16,
}

impl Display for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "p: {} l: {}:{} r: {} {}",
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address,
            self.remote_port
        )
    }
}

impl Key {
    fn small(&self) -> (IpProtocol, u16) {
        (self.protocol, self.local_port)
    }
}

pub struct ConnectionCache {
    connections: BTreeMap<(IpProtocol, u16), Vec<Connection>>,
    lock: RwSpinLock,
}

impl ConnectionCache {
    pub fn init(&mut self) {
        self.connections = BTreeMap::new();
        self.lock = RwSpinLock::default();
    }

    pub fn add_connection(&mut self, connection: Connection) {
        let _guard = self.lock.write_lock();
        let key = connection.get_key();
        if let Some(conns) = self.connections.get_mut(&key.small()) {
            conns.push(connection);
        } else {
            let conns = alloc::vec![connection];
            self.connections.insert(key.small(), conns);
        }
    }

    pub fn update_connection(&mut self, key: Key, action: ConnectionAction) {
        let _guard = self.lock.write_lock();
        if let Some(conns) = self.connections.get_mut(&key.small()) {
            if conns.len() == 1 {
                conns[0].action = action;
            } else {
                for conn in conns {
                    if conn.local_equals(&key) && conn.remote_equals(&key) {
                        conn.action = action;
                        return;
                    }
                }
            }
        }
    }

    pub fn get_connection_action(&mut self, key: Key) -> Option<Connection> {
        let _guard = self.lock.read_lock();

        if let Some(conns) = self.connections.get(&key.small()) {
            if conns.len() == 1 {
                return Some(conns[0].clone());
            } else {
                for conn in conns {
                    if !conn.local_equals(&key) {
                        continue;
                    }
                    if conn.remote_equals(&key) {
                        return Some(conn.clone());
                    }
                    if conn.redirect_equals(&key) {
                        return Some(conn.clone());
                    }
                }
            }
        }

        None
    }

    pub fn unregister_port(&mut self, key: (IpProtocol, u16)) -> Option<Vec<Connection>> {
        let _guard = self.lock.read_lock();
        self.connections.remove(&key)
    }

    pub fn clear(&mut self) {
        let _guard = self.lock.write_lock();
        self.connections.clear();
    }
}
