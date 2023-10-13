use crate::types::{PacketInfo, Verdict};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use wdk::{rw_spin_lock::RwSpinLock, utils::ClassifyPromise};

#[derive(Clone)]
#[allow(dead_code)]
pub enum ConnectionAction {
    Verdict(Verdict),
    RedirectIPv4(Vec<u8>, u16),
    RedirectIPv6(Vec<u8>, u16),
}

struct Connection {
    // info: PacketInfo,
    action: ConnectionAction,
}

pub struct ConnectionCache {
    connections: BTreeMap<u16, Connection>,
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
        verdict: ConnectionAction,
    ) -> Option<ClassifyPromise> {
        let promise = packet.classify_promise.take();
        let _quard = self.lock.write_lock();
        self.connections.insert(
            packet.local_port,
            Connection {
                // info: packet,
                action: verdict,
            },
        );

        promise
    }

    pub fn get_connection_action(&self, packet: &PacketInfo) -> Option<ConnectionAction> {
        let _quard = self.lock.read_lock();

        if let Some(connection) = self.connections.get(&packet.local_port) {
            return Some(connection.action.clone());
        }

        None
    }
}
