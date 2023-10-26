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

#[derive(PartialEq, PartialOrd, Eq, Ord)]
struct Key {
    port: u16,
    protocol: IpProtocol,
}

pub struct ConnectionCache {
    connections: BTreeMap<Key, Connection>,
    lock: RwSpinLock,
}

impl ConnectionCache {
    pub fn init(&mut self) {
        self.connections = BTreeMap::new();
        self.lock = RwSpinLock::default();
    }

    pub fn add_connection(&mut self, connection: Connection) {
        // let promise = packet.classify_promise.take();
        let _quard = self.lock.write_lock();

        self.connections.insert(
            Key {
                port: connection.local_port,
                protocol: connection.protocol,
            },
            connection,
        );

        // promise
    }

    pub fn update_connection(&mut self, protocol: IpProtocol, port: u16, action: ConnectionAction) {
        let _guard = self.lock.write_lock();
        if let Some(connection) = self.connections.get_mut(&Key { port, protocol }) {
            connection.action = action;
        }
    }

    pub fn get_connection_action(&self, port: u16, protocol: IpProtocol) -> Option<Connection> {
        let _guard = self.lock.read_lock();

        if let Some(connection) = self.connections.get(&Key { port, protocol }) {
            return Some(connection.clone());
        }

        None
    }
}
