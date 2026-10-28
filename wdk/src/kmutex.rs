use alloc::boxed::Box;
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

use windows_sys::Wdk::{
    Foundation::KMUTANT,
    System::SystemServices::{Executive, KeInitializeMutex, KeReleaseMutex, KeWaitForSingleObject},
};

/// A mutex backed by a kernel mutex object (KMUTEX), for data that is only used at PASSIVE_LEVEL.
///
/// Unlike a spin lock or a FAST_MUTEX, holding it leaves the IRQL where it was (it only disables
/// normal kernel APCs), so the holder can call routines that require PASSIVE_LEVEL, such as the
/// filter engine management functions, and can wait.
///
/// `lock` must be called at IRQL <= APC_LEVEL, because it waits. Never lock it again while holding
/// it: kernel mutexes are recursive, so the second lock would succeed and hand out a second `&mut`.
pub struct KMutex<T> {
    // Boxed so the kernel object never moves once it is initialized.
    mutex: Box<UnsafeCell<KMUTANT>>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for KMutex<T> {}
unsafe impl<T: Send> Send for KMutex<T> {}

impl<T> KMutex<T> {
    pub fn new(data: T) -> Self {
        let mutex = Box::new(UnsafeCell::new(unsafe {
            MaybeUninit::<KMUTANT>::zeroed().assume_init()
        }));
        unsafe { KeInitializeMutex(mutex.get(), 0) };
        Self {
            mutex,
            data: UnsafeCell::new(data),
        }
    }

    /// Waits until the mutex is free and takes it. IRQL <= APC_LEVEL only.
    pub fn lock(&self) -> KMutexGuard<'_, T> {
        // Kernel mode, not alertable, no timeout: the wait only returns once the mutex is owned.
        const KERNEL_MODE: i8 = 0;
        unsafe {
            KeWaitForSingleObject(
                self.mutex.get() as *const _,
                Executive,
                KERNEL_MODE,
                0,
                core::ptr::null(),
            );
        }
        KMutexGuard { lock: self }
    }
}

/// Owns the mutex until dropped.
pub struct KMutexGuard<'a, T> {
    lock: &'a KMutex<T>,
}

impl<'a, T> Deref for KMutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for KMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for KMutexGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { KeReleaseMutex(self.lock.mutex.get(), 0) };
    }
}
