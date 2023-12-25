use core::fmt::Display;

use crate::types::Verdict;
use alloc::collections::BTreeMap;
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
    connections: BTreeMap<(IpProtocol, u16), Connection>,
    lock: RwSpinLock,
}

impl ConnectionCache {
    pub fn init(&mut self) {
        self.connections = BTreeMap::new();
        self.lock = RwSpinLock::default();
    }

    pub fn add_connection(&mut self, connection: Connection) {
        let _guard = self.lock.write_lock();

        self.connections
            .insert(connection.get_key().small(), connection);
    }

    pub fn update_connection(&mut self, key: Key, action: ConnectionAction) {
        let _guard = self.lock.write_lock();
        if let Some(connection) = self.connections.get_mut(&key.small()) {
            connection.action = action;
        }
    }

    pub fn get_connection_action(&mut self, key: Key) -> Option<Connection> {
        let _guard = self.lock.read_lock();

        if let Some(conn) = self.connections.get_mut(&key.small()) {
            return Some(conn.clone());
        }

        None
    }

    pub fn remove_connection(&mut self, key: Key) -> Option<Connection> {
        let _guard = self.lock.read_lock();

        self.connections.remove(&key.small())
    }

    pub fn clear(&mut self) {
        let _guard = self.lock.write_lock();
        self.connections.clear();
    }
}
