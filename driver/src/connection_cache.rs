use crate::types::{PacketInfo, Verdict};
use alloc::collections::BTreeMap;
use smoltcp::wire::{IpProtocol, Ipv4Address};
use wdk::filter_engine::callout_data::ClassifyPromise;
use wdk::rw_spin_lock::RwSpinLock;

#[derive(Clone)]
#[allow(dead_code)]
pub enum ConnectionAction {
    Verdict(Verdict),
    RedirectIP {
        local_address: Ipv4Address,
        original_remote_address: Ipv4Address,
        original_remote_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
    },
}

#[derive(PartialEq, PartialOrd, Eq, Ord)]
struct Key {
    port: u16,
    protocol: IpProtocol,
}

pub struct ConnectionCache {
    connections: BTreeMap<Key, ConnectionAction>,
    lock: RwSpinLock,
}

impl ConnectionCache {
    pub fn init(&mut self) {
        self.connections = BTreeMap::new();
        self.lock = RwSpinLock::default();
    }

    pub fn add_connection(
        &mut self,
        packet: &mut PacketInfo,
        action: ConnectionAction,
    ) -> Option<ClassifyPromise> {
        let promise = packet.classify_promise.take();
        let _quard = self.lock.write_lock();

        self.connections.insert(
            Key {
                port: packet.local_port,
                protocol: IpProtocol::from(packet.protocol),
            },
            action,
        );

        promise
    }

    pub fn get_connection_action(
        &self,
        port: u16,
        protocol: IpProtocol,
    ) -> Option<ConnectionAction> {
        let _quard = self.lock.read_lock();

        if let Some(action) = self.connections.get(&Key { port, protocol }) {
            return Some(action.clone());
        }

        None
    }
}
