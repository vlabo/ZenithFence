use alloc::collections::VecDeque;
use wdk::rw_spin_lock::RwSpinLock;

struct Entry<T> {
    value: T,
    id: u64,
}

pub struct IdCache<T> {
    values: Option<VecDeque<Entry<T>>>,
    lock: RwSpinLock,
    next_id: u64,
}

impl<T> IdCache<T> {
    pub fn init(&mut self) {
        self.values = Some(VecDeque::with_capacity(1000));
        self.lock = RwSpinLock::default();
        self.next_id = 1; // 0 is invalid id
    }

    pub fn push(&mut self, value: T) -> u64 {
        if let Some(values) = &mut self.values {
            let _guard = self.lock.write_lock();
            let id = self.next_id;
            values.push_back(Entry { value, id });
            self.next_id = self.next_id.wrapping_add(1); // Assuming this will not overflow.
            return id;
        }
        return 0;
    }

    pub fn pop_id(&mut self, id: u64) -> Option<T> {
        if let Some(values) = &mut self.values {
            let _guard = self.lock.write_lock();
            if let Ok(index) = values.binary_search_by_key(&id, |val| val.id) {
                return Some(values.remove(index).unwrap().value);
            }
        }
        None
    }

    pub fn get_entries_count(&self) -> usize {
        if let Some(values) = &self.values {
            let _guard = self.lock.read_lock();
            return values.len();
        }

        return 0;
    }
}
