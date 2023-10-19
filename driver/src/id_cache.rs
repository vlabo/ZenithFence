use alloc::collections::VecDeque;
use alloc::vec::Vec;
use wdk::rw_spin_lock::RwSpinLock;

use crate::types::PacketInfo;

struct PacketEntry {
    value: PacketInfo,
    id: u64,
}

pub struct PacketCache {
    values: VecDeque<PacketEntry>,
    lock: RwSpinLock,
    next_id: u64,
}

impl PacketCache {
    pub fn init(&mut self) {
        self.values = VecDeque::with_capacity(1000);
        self.lock.init();
        self.next_id = 0;
    }

    pub fn push_and_serialize(&mut self, value: PacketInfo) -> Result<Vec<u8>, ()> {
        let _guard = self.lock.write_lock();
        let id = self.next_id;
        let serialized = value.serialize(id);
        self.values.push_back(PacketEntry { value, id });

        self.next_id += 1; // Assuming this will not overflow.
        serialized
    }

    pub fn pop_id(&mut self, id: u64) -> Option<PacketInfo> {
        let _guard = self.lock.write_lock();
        if let Ok(index) = self.values.binary_search_by_key(&id, |val| val.id) {
            return Some(self.values.remove(index).unwrap().value);
        }
        None
    }
}
