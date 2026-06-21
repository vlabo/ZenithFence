use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicIsize, Ordering},
};

/// Host mock of the kernel reader-writer spin lock based `Mutex`.
///
/// This is a REAL reader-writer spinlock (not a no-op), so the multithreaded
/// host fuzz/stress harness exercises the same mutual exclusion the kernel
/// spinlock provides. Multiple readers may hold it at once; a writer is
/// exclusive.
///
/// IMPORTANT: the real type is valid when zero-initialized, and the driver
/// relies on that -- `connection_cache::alloc_port_array` allocates arrays of
/// `RCUPort<T>` (which contain `Mutex<()>`) with `alloc_zeroed`. So this mock
/// must also be valid when its bytes are all zero. We back the lock word with an
/// `AtomicIsize` that is `0` (unlocked) when zeroed:
///   *  `0` -> unlocked
///   * `-1` -> write-locked (exclusive)
///   * `>0` -> number of active readers (shared)
///
/// The data lives in an `UnsafeCell<T>`; the lock word is what makes concurrent
/// access sound. No lock-ordering cycles exist in the driver (each operation
/// holds at most one port lock at a time), so this spinlock cannot deadlock.
pub struct Mutex<T> {
    lock: AtomicIsize,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Mutex<T> {}
unsafe impl<T: Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            lock: AtomicIsize::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire a shared (reader) lock, spinning until no writer holds it.
    pub fn read_lock(&self) -> MutexReadGuard<'_, T> {
        loop {
            let cur = self.lock.load(Ordering::Relaxed);
            if cur >= 0 {
                // No writer present; try to register one more reader.
                if self
                    .lock
                    .compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            } else {
                // A writer holds the lock; back off and retry.
                spin();
            }
        }
        MutexReadGuard { lock: self }
    }

    /// Acquire the exclusive (writer) lock, spinning until fully unlocked.
    pub fn write_lock(&self) -> MutexWriteGuard<'_, T> {
        while self
            .lock
            .compare_exchange_weak(0, -1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Held by a reader or another writer; back off and retry.
            spin();
        }
        MutexWriteGuard { lock: self }
    }
}

// Cheap contention back-off. mock_wdk is a std crate, so we can yield to the
// scheduler to avoid pathological spinning when threads > cores.
#[inline]
fn spin() {
    core::hint::spin_loop();
    std::thread::yield_now();
}

pub struct MutexWriteGuard<'a, T> {
    lock: &'a Mutex<T>,
}

impl<'a, T> Deref for MutexWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for MutexWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for MutexWriteGuard<'a, T> {
    fn drop(&mut self) {
        // Release the exclusive lock.
        self.lock.lock.store(0, Ordering::Release);
    }
}

pub struct MutexReadGuard<'a, T> {
    lock: &'a Mutex<T>,
}

impl<'a, T> Deref for MutexReadGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> Drop for MutexReadGuard<'a, T> {
    fn drop(&mut self) {
        // Release one reader.
        self.lock.lock.fetch_sub(1, Ordering::Release);
    }
}
