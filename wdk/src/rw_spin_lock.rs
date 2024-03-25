use core::cell::UnsafeCell;

use windows_sys::Wdk::System::SystemServices::{
    ExAcquireSpinLockExclusive, ExAcquireSpinLockShared, ExReleaseSpinLockExclusive,
    ExReleaseSpinLockShared,
};

pub struct RwSpinLock {
    data: UnsafeCell<i32>,
}

impl RwSpinLock {
    pub const fn default() -> Self {
        Self {
            data: UnsafeCell::new(0),
        }
    }

    pub fn read_lock(&self) -> RwLockGuard {
        let irq = unsafe { ExAcquireSpinLockShared(self.data.get()) };
        RwLockGuard {
            data: &self.data,
            exclusive: false,
            old_irq: irq,
        }
    }

    pub fn write_lock(&self) -> RwLockGuard {
        let irq = unsafe { ExAcquireSpinLockExclusive(self.data.get()) };
        RwLockGuard {
            data: &self.data,
            exclusive: true,
            old_irq: irq,
        }
    }
}

pub struct RwLockGuard<'a> {
    data: &'a UnsafeCell<i32>,
    exclusive: bool,
    old_irq: u8,
}

impl<'a> Drop for RwLockGuard<'a> {
    fn drop(&mut self) {
        unsafe {
            if self.exclusive {
                ExReleaseSpinLockExclusive(self.data.get(), self.old_irq);
            } else {
                ExReleaseSpinLockShared(self.data.get(), self.old_irq);
            }
        }
    }
}
