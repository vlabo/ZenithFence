use alloc::collections::VecDeque;
use wdk::rw_spin_lock::RwSpinLock;

struct Entry<T> {
    value: T,
    id: u64,
}

pub struct IdCache<T> {
    values: VecDeque<Entry<T>>,
    lock: RwSpinLock,
    next_id: u64,
}

impl<T> IdCache<T> {
    pub fn new() -> Self {
        Self {
            values: VecDeque::with_capacity(1000),
            lock: RwSpinLock::default(),
            next_id: 1, // 0 is invalid id
        }
    }

    pub fn push(&mut self, value: T) -> u64 {
        let _guard = self.lock.write_lock();
        let id = self.next_id;
        self.values.push_back(Entry { value, id });
        self.next_id = self.next_id.wrapping_add(1); // Assuming this will not overflow.
        return id;
    }

    pub fn pop_id(&mut self, id: u64) -> Option<T> {
        let _guard = self.lock.write_lock();
        if let Ok(index) = self.values.binary_search_by_key(&id, |val| val.id) {
            return Some(self.values.remove(index).unwrap().value);
        }
        None
    }

    pub fn get_entries_count(&self) -> usize {
        let _guard = self.lock.read_lock();
        return self.values.len();
    }
}
