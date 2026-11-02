use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::connection::Connection;
use wdk::rw_spin_lock::Mutex;

// -------------------------------------------------------------------------------------------------
// The connections on one local port, behind a reader-writer spin lock of their own.
// Readers take the lock shared and never wait for each other; a writer takes it exclusive and
// changes the list in place. Every port has its own lock, so traffic on one port never waits for
// another.
// -------------------------------------------------------------------------------------------------

/// One connection on a port: its compact key inline, so a lookup scans contiguous memory and only
/// dereferences the match.
pub(crate) struct Entry<T: Connection> {
    pub(crate) key: T::CompactKey,
    pub(crate) conn: Box<T>,
}

impl<T: Connection> Entry<T> {
    pub(crate) fn new(conn: Box<T>) -> Self {
        Self {
            key: conn.compact_key(),
            conn,
        }
    }
}

pub(crate) struct PortConnections<T: Connection> {
    // Null = no connections on this port. Changed only under the exclusive lock, and read under
    // the lock, which orders the accesses; the atomic only lets `is_empty` peek without it.
    entries: AtomicPtr<Vec<Entry<T>>>,

    lock: Mutex<()>,
}

impl<T: Connection> Drop for PortConnections<T> {
    fn drop(&mut self) {
        let entries = *self.entries.get_mut();
        if !entries.is_null() {
            unsafe { drop(Box::from_raw(entries)) };
        }
    }
}

impl<T: Connection> PortConnections<T> {
    // Lock-free check: returns true if the port has no connections. Only a hint, since it can
    // change right after; used to skip empty ports without taking the lock.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.load(Ordering::Relaxed).is_null()
    }

    /// Runs `f` on the connections of this port, holding the lock shared. `f` must not use the
    /// connection cache again: a writer waiting on this port would deadlock it.
    pub(crate) fn read<R>(&self, f: impl FnOnce(&[Entry<T>]) -> R) -> R {
        let _guard = self.lock.read_lock();
        let entries = self.entries.load(Ordering::Relaxed);
        if entries.is_null() {
            f(&[])
        } else {
            f(unsafe { &*entries })
        }
    }

    /// Runs `f` on the connections of this port, holding the lock exclusive, so it can change
    /// them. Connections `f` removes are freed right away: no reader can be looking at them. `f`
    /// must not use the connection cache again.
    pub(crate) fn write<R>(&self, f: impl FnOnce(&mut Vec<Entry<T>>) -> R) -> R {
        let _guard = self.lock.write_lock();
        let current = self.entries.load(Ordering::Relaxed);
        let mut entries = if current.is_null() {
            Box::new(Vec::new())
        } else {
            unsafe { Box::from_raw(current) }
        };

        let result = f(&mut entries);

        // An empty port keeps no allocation.
        let new = if entries.is_empty() {
            core::ptr::null_mut()
        } else {
            Box::into_raw(entries)
        };
        self.entries.store(new, Ordering::Relaxed);
        result
    }
}
