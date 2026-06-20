use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
};

/// Host mock of the kernel reader-writer spin lock based `Mutex`.
///
/// IMPORTANT: the real type is valid when zero-initialized, and the driver
/// relies on that -- `connection_cache::alloc_port_array` allocates arrays of
/// `RCUPort<T>` (which contain `Mutex<()>`) with `alloc_zeroed`. So this mock
/// must also be valid when its bytes are all zero. We back it with an
/// `UnsafeCell<i32>` "lock" word (valid at 0) and an `UnsafeCell<T>` for the
/// data. Fuzzing is single-threaded, so the lock is a no-op.
pub struct Mutex<T> {
    _lock: UnsafeCell<i32>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Mutex<T> {}
unsafe impl<T: Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            _lock: UnsafeCell::new(0),
            data: UnsafeCell::new(data),
        }
    }

    pub fn read_lock(&self) -> MutexReadGuard<'_, T> {
        MutexReadGuard { lock: self }
    }

    pub fn write_lock(&self) -> MutexWriteGuard<'_, T> {
        MutexWriteGuard { lock: self }
    }
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

pub struct MutexReadGuard<'a, T> {
    lock: &'a Mutex<T>,
}

impl<'a, T> Deref for MutexReadGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}
