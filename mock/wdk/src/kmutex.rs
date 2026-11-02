//! Host mock of `wdk::kmutex`, backed by `std::sync::Mutex`.
//!
//! The kernel version waits on a KMUTEX and leaves the IRQL alone, so its holder
//! may call PASSIVE_LEVEL routines and wait. The host has no IRQL; only the
//! mutual exclusion matters here.

use core::ops::{Deref, DerefMut};
use std::sync::{Mutex, MutexGuard};

pub struct KMutex<T> {
    inner: Mutex<T>,
}

impl<T> KMutex<T> {
    pub fn new(data: T) -> Self {
        Self {
            inner: Mutex::new(data),
        }
    }

    /// Waits until the mutex is free and takes it. Recovers from poison: a
    /// panicking holder must not wedge every later caller and hide the failure.
    ///
    /// Unlike the kernel mutex this one is not recursive: locking it again while
    /// holding it deadlocks instead of handing out a second `&mut`, which the
    /// real type forbids anyway.
    pub fn lock(&self) -> KMutexGuard<'_, T> {
        KMutexGuard {
            guard: self.inner.lock().unwrap_or_else(|p| p.into_inner()),
        }
    }
}

/// Owns the mutex until dropped.
pub struct KMutexGuard<'a, T> {
    guard: MutexGuard<'a, T>,
}

impl<T> Deref for KMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for KMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}
