use alloc::boxed::Box;
use alloc::sync::Arc;
use core::{
    ptr,
    sync::atomic::{AtomicPtr, AtomicU16, AtomicU64, Ordering},
};

use crate::connection::Connection;
use crate::mpsc_queue::MpscQueue;
use wdk::rw_spin_lock::{Mutex, MutexWriteGuard};

// -------------------------------------------------------------------------------------------------
// RCU-style per-port slot.
// Readers acquire a RCUPortReadGuard (lock-free, loads raw pointer) and access the snapshot
// through it. The guard increments the ConnectionArray's reader counter on creation and
// decrements it on drop, enabling deferred reclamation by the consumer of unlinked_ports.
// Writers acquire the write mutex and publish changes atomically. The old snapshot is stamped
// with an unlinked timestamp and pushed onto a caller-supplied MPSC queue for safe reclamation.
// -------------------------------------------------------------------------------------------------

// Heap-allocated, fixed-length array of connections. Length is set on publish and never changes.
// Wrapped in a newtype so AtomicPtr holds a thin (non-fat) pointer.
pub(crate) struct ConnectionArray<T: Connection> {
    array: Box<[Arc<T>]>,

    pub(crate) readers: AtomicU16,
    pub(crate) unlinked_timestamp: AtomicU64,
}

pub(crate) struct RCUPort<T: Connection> {
    // Null = no connections on this port.
    // Non-null = Box::into_raw(Box::new(ConnectionArray<T>)), i.e. AtomicPtr owns one allocation.
    // The outer AtomicPtr is swapped atomically on every write (RCU snapshot).
    // The inner Arc<T> elements are stable heap pointers; they are never swapped in place.
    connections: AtomicPtr<ConnectionArray<T>>,

    // Writer mutex for concurrent writers. Readers never take this.
    write_mutex: Mutex<()>,
}

impl<T: Connection> RCUPort<T> {
    // Lock-free. Loads the current snapshot pointer and returns a guard.
    pub(crate) fn read(&self) -> RCUPortReadGuard<'_, T> {
        let ptr = self.connections.load(Ordering::SeqCst);
        // Increment reader count only if non-null (null = no connections on this port).
        if !ptr.is_null() {
            unsafe { (*ptr).readers.fetch_add(1, Ordering::SeqCst) };
        }
        RCUPortReadGuard {
            _port: self,
            snapshot: ptr as *const _,
        }
    }

    // Acquires the write mutex. All concurrent writes will pause.
    pub(crate) fn lock(&self) -> RCUPortWriteGuard<'_, T> {
        RCUPortWriteGuard {
            port: self,
            _guard: self.write_mutex.write_lock(),
        }
    }
}

// Guard returned by RCUPort::read(). Holds a raw snapshot pointer for the caller.
pub(crate) struct RCUPortReadGuard<'a, T: Connection> {
    _port: &'a RCUPort<T>,
    snapshot: *const ConnectionArray<T>,
}

impl<T: Connection> RCUPortReadGuard<'_, T> {
    pub(crate) fn get(&self) -> Option<&[Arc<T>]> {
        if self.snapshot.is_null() {
            None
        } else {
            unsafe { Some(&(*self.snapshot).array) }
        }
    }
}

impl<T: Connection> Drop for RCUPortReadGuard<'_, T> {
    fn drop(&mut self) {
        if !self.snapshot.is_null() {
            unsafe { (*self.snapshot).readers.fetch_sub(1, Ordering::SeqCst) };
        }
    }
}

// Guard returned by RCUPort::lock(). publish() and snapshot() are only accessible through this
// type, so the compiler statically enforces that no write can happen without holding the lock.
pub(crate) struct RCUPortWriteGuard<'a, T: Connection> {
    port: &'a RCUPort<T>,
    _guard: MutexWriteGuard<'a, ()>,
}

impl<T: Connection> RCUPortWriteGuard<'_, T> {
    // Returns a reference to the current snapshot. Safe because the write mutex is held —
    // no concurrent publish() can run and swap the pointer while this guard is alive.
    pub(crate) fn snapshot(&self) -> Option<&[Arc<T>]> {
        let ptr = self.port.connections.load(Ordering::SeqCst);
        if ptr.is_null() {
            return None;
        }
        unsafe { Some(&(*ptr).array) }
    }

    // Publishes a new snapshot. The slice must be fully built before calling.
    // The old snapshot pointer is stamped with the current time and pushed onto
    // the provided queue for deferred reclamation.
    pub(crate) fn publish(
        &self,
        new: Option<Box<[Arc<T>]>>,
        queue: &MpscQueue<ConnectionArray<T>>,
    ) {
        let new_raw: *mut ConnectionArray<T> = match new {
            Some(v) => Box::into_raw(Box::new(ConnectionArray {
                array: v,
                readers: AtomicU16::new(0),
                unlinked_timestamp: AtomicU64::new(0),
            })),
            None => ptr::null_mut(),
        };

        let old = self.port.connections.swap(new_raw, Ordering::SeqCst);
        if old.is_null() {
            return;
        }
        unsafe {
            (*old)
                .unlinked_timestamp
                .store(wdk::utils::get_system_timestamp_ms(), Ordering::SeqCst);
        }

        queue.push(old);
    }
}
