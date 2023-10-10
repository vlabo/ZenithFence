use alloc::collections::BTreeMap;
use wdk::{rw_spin_lock::RwSpinLock, utils::ClassifyPromise};

use crate::types::{PacketInfo, Verdict};

struct Connection {
    info: PacketInfo,
    verdict: Verdict,
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
        mut packet: PacketInfo,
        verdict: Verdict,
    ) -> Option<ClassifyPromise> {
        let promise = packet.classify_promise.take();
        let _quard = self.lock.write_lock();
        self.connections.insert(
            packet.local_port,
            Connection {
                info: packet,
                verdict,
            },
        );
        return promise;
    }

    pub fn get_connection_verdict(&self, packet: &PacketInfo) -> Option<Verdict> {
        let _quard = self.lock.read_lock();

        if let Some(connection) = self.connections.get(&packet.local_port) {
            return Some(connection.verdict);
        }

        None
    }
}
