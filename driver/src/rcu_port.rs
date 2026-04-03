use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

use crate::connection::Connection;
use wdk::rw_spin_lock::Mutex;

// -------------------------------------------------------------------------------------------------
// RCU-style per-port slot.
// This is not a standard RCU because there can be multiple writers.
// Readers can read the latest state directly from connections field.
// Writers must take the mutex lock and publish the changes with single atomic operation.
// The Arc pointers must stay the same during the whole lifetime of the connection, only the vector must be changed
// -------------------------------------------------------------------------------------------------
pub(crate) struct RCUPort<T: Connection> {
    // Null = no connections on this port.
    // Non-null = Arc::into_raw(Arc::new(Vec<Arc<T>>)), i.e. AtomicPtr owns one Arc reference.
    // AtomicPtr (instead of Arc) is used for immutable replaces of the pointer.
    connections: AtomicPtr<Vec<Arc<T>>>,

    // writer mutex for concurrent writers. Readers never take this.
    write_mutex: Mutex<()>,
}

impl<T: Connection> RCUPort<T> {
    // Lock-free. Returns a clone of the current snapshot.
    // The returned Arc keeps the snapshot alive for as long as the caller holds it,
    // regardless of subsequent writes.
    #[inline(always)]
    pub(crate) fn snapshot(&self) -> Option<Arc<Vec<Arc<T>>>> {
        let ptr = self.connections.load(Ordering::Acquire);
        if ptr.is_null() {
            return None;
        }
        // SAFETY: see the note above. ptr is alive (refcount ≥ 1) when we reach here.
        // After increment_strong_count the caller owns a reference and the snapshot
        // cannot be freed until the caller drops its Arc.
        unsafe {
            Arc::increment_strong_count(ptr);
            Some(Arc::from_raw(ptr))
        }
    }

    // Publishes a new snapshot. Only writers call this; serialized by write_mutex.
    // The new Vec must be fully built before calling — do the allocation outside any lock.
    pub(crate) fn publish(&self, new: Option<Vec<Arc<T>>>) {
        let new_raw: *mut Vec<Arc<T>> = match new {
            Some(v) => Arc::into_raw(Arc::new(v)) as *mut _,
            None => ptr::null_mut(),
        };

        // Hold the exclusive lock only for the pointer swap (~2 ns).
        let _guard = self.write_mutex.write_lock();
        let old_raw = self.connections.swap(new_raw, Ordering::AcqRel);
        drop(_guard);

        if !old_raw.is_null() {
            // Release our reference to the old snapshot.
            // If any callout still holds an Arc from snapshot(), refcount > 0 and the
            // snapshot stays alive. It is freed automatically when the last Arc is dropped.
            unsafe { drop(Arc::from_raw(old_raw as *const Vec<Arc<T>>)) };
        }
    }
}
