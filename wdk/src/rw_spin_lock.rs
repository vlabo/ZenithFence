use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
};

use windows_sys::Wdk::System::SystemServices::{
    ExAcquireSpinLockExclusive, ExAcquireSpinLockShared, ExReleaseSpinLockExclusive,
    ExReleaseSpinLockShared,
};

pub struct RwMutex<T> {
    lock: UnsafeCell<i32>,
    data: T,
}

impl<T> RwMutex<T> {
    pub fn new(data: T) -> RwMutex<T> {
        Self {
            lock: UnsafeCell::new(0),
            data,
        }
    }

    pub fn lock(&self) -> MutexReadGuard<T> {
        let irq = unsafe { ExAcquireSpinLockShared(self.lock.get()) };
        MutexReadGuard {
            data: &self.data,
            lock: &self.lock,
            old_irq: irq,
        }
    }

    pub fn lock_mut(&mut self) -> MutexWriteGuard<T> {
        let irq = unsafe { ExAcquireSpinLockExclusive(self.lock.get()) };
        MutexWriteGuard {
            data: &mut self.data,
            lock: &self.lock,
            old_irq: irq,
        }
    }
}

pub struct MutexReadGuard<'a, T> {
    data: &'a T,
    lock: &'a UnsafeCell<i32>,
    old_irq: u8,
}

impl<'a, T> Deref for MutexReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<'a, T> Drop for MutexReadGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { ExReleaseSpinLockShared(self.lock.get(), self.old_irq) };
    }
}

pub struct MutexWriteGuard<'a, T> {
    data: &'a mut T,
    lock: &'a UnsafeCell<i32>,
    old_irq: u8,
}

impl<'a, T> Deref for MutexWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<'a, T> DerefMut for MutexWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<'a, T> Drop for MutexWriteGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { ExReleaseSpinLockExclusive(self.lock.get(), self.old_irq) };
    }
}
