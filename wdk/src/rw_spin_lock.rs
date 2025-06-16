use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
};

use windows_sys::Wdk::System::SystemServices::{
    ExAcquireSpinLockExclusive, ExAcquireSpinLockShared, ExReleaseSpinLockExclusive,
    ExReleaseSpinLockShared,
};

/// A reader-writer spin lock implementation.
///
/// This lock allows multiple readers to access the data simultaneously,
/// but only one writer can access the data at a time. It uses a spin loop
/// to wait for the lock to become available.
pub struct RwSpinLock {
    data: UnsafeCell<i32>,
}

impl RwSpinLock {
    /// Creates a new `RwSpinLock` with the default initial value.
    pub const fn default() -> Self {
        Self {
            data: UnsafeCell::new(0),
        }
    }

    pub fn read_lock(&self) -> u8 {
        return unsafe { ExAcquireSpinLockShared(self.data.get()) };
    }

    pub fn write_lock(&self) -> u8 {
        return unsafe { ExAcquireSpinLockExclusive(self.data.get()) };
    }

    pub fn read_unlock(&self, old_irq: u8) {
        unsafe { ExReleaseSpinLockShared(self.data.get(), old_irq) };
    }
    pub fn write_unlock(&self, old_irq: u8) {
        unsafe { ExReleaseSpinLockExclusive(self.data.get(), old_irq) };
    }
}

// High level interface for RWSpinLock
pub struct Mutex<T> {
    lock: RwSpinLock,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Mutex<T> {}
unsafe impl<T: Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            lock: RwSpinLock::default(),
            data: UnsafeCell::new(data),
        }
    }

    // Locks the resource for reading
    pub fn read_lock(&self) -> MutexReadGuard<'_, T> {
        let old_irq = self.lock.read_lock();
        MutexReadGuard {
            lock: self,
            old_irq,
        }
    }

    // Locks the resource for writing
    pub fn write_lock(&self) -> MutexWriteGuard<'_, T> {
        let old_irq = self.lock.write_lock();
        MutexWriteGuard {
            lock: self,
            old_irq,
        }
    }
}

// MutexReadGuard is a mutex write guard lock
pub struct MutexWriteGuard<'a, T> {
    lock: &'a Mutex<T>,
    old_irq: u8,
}

impl<'a, T> Deref for MutexWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> Drop for MutexWriteGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.lock.write_unlock(self.old_irq);
    }
}

impl<'a, T> DerefMut for MutexWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

// MutexReadGuard is a mutex read guard lock
pub struct MutexReadGuard<'a, T> {
    lock: &'a Mutex<T>,
    old_irq: u8,
}

impl<'a, T> Deref for MutexReadGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> Drop for MutexReadGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.lock.read_unlock(self.old_irq);
    }
}
