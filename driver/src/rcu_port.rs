use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

use crate::connection::Connection;
use wdk::rw_spin_lock::{Mutex, MutexWriteGuard};

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

// Guard returned by RCUPort::lock(). publish() is only accessible through this type,
// so the compiler statically enforces that no publish can happen without holding the lock.
pub(crate) struct RCUPortWriteGuard<'a, T: Connection> {
    port: &'a RCUPort<T>,
    _guard: MutexWriteGuard<'a, ()>,
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
        // ptr is alive (refcount ≥ 1) when we reach here.
        // After increment_strong_count the caller owns a reference and the snapshot
        // cannot be freed until the caller drops its Arc.
        unsafe {
            Arc::increment_strong_count(ptr);
            Some(Arc::from_raw(ptr))
        }
    }

    // Acquires the write mutex. Locks the port for writing. All concurrent writes will pause.
    // Reading and updating the state must happen after the lock has been acquired.
    // SAFETY: NEVER update to a value that was read before the lock was acquired.
    pub(crate) fn lock(&self) -> RCUPortWriteGuard<'_, T> {
        RCUPortWriteGuard {
            port: self,
            _guard: self.write_mutex.write_lock(),
        }
    }
}

impl<T: Connection> RCUPortWriteGuard<'_, T> {
    // Publishes a new snapshot. Callable only through the write guard, which guarantees
    // the write mutex is held for the duration of the pointer swap.
    // The new Vec must be fully built before calling — do the allocation outside the lock.
    pub(crate) fn publish(&self, new: Option<Vec<Arc<T>>>) {
        let new_raw: *mut Vec<Arc<T>> = match new {
            Some(v) => Arc::into_raw(Arc::new(v)) as *mut _,
            None => ptr::null_mut(),
        };

        let old_raw = self.port.connections.swap(new_raw, Ordering::AcqRel);

        if !old_raw.is_null() {
            // Release our reference to the old snapshot.
            // If any reader still holds an Arc from snapshot(), refcount > 0 and the
            // snapshot stays alive. It is freed automatically when the last Arc is dropped.
            unsafe { drop(Arc::from_raw(old_raw as *const Vec<Arc<T>>)) };
        }
    }
}
