//! Loads and unloads the real driver the way the kernel does.
//!
//! The driver keeps its device in a process-wide global, so there is one loaded
//! driver per process. Loading runs the real `driver_entry` against a fresh mock
//! `DRIVER_OBJECT`; unloading calls the `DriverUnload` that `driver_entry`
//! registered on it. Nothing here reaches into the driver's globals directly.

use std::sync::{Mutex, MutexGuard};

use wdk::kernel_types::{DRIVER_OBJECT, NTSTATUS, STATUS_SUCCESS, UNICODE_STRING};

/// Serializes everything that loads, unloads or drives the process-wide driver
/// instance; a [`crate::sim::Simulation`] holds it for its whole lifetime.
pub static DRIVER_LOCK: Mutex<()> = Mutex::new(());

/// Takes [`DRIVER_LOCK`], recovering from a poisoned lock (a failed test must
/// not cascade into every later one).
pub fn lock() -> MutexGuard<'static, ()> {
    DRIVER_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// The `DRIVER_OBJECT` of the currently loaded driver. It must outlive the
/// driver (the driver keeps pointers into it), so it is boxed and kept here
/// until the matching unload.
struct LoadedDriver(Box<DRIVER_OBJECT>);

// SAFETY: the object is only touched while holding `LOADED`, and the driver
// itself is designed to be called from any thread.
unsafe impl Send for LoadedDriver {}

static LOADED: Mutex<Option<LoadedDriver>> = Mutex::new(None);

/// Loads the driver unless one is already loaded. User-space reads block until
/// an event arrives or the queue is run down, like the kernel's. Returns the
/// `driver_entry` status (`STATUS_SUCCESS` when a driver was already loaded).
pub fn load() -> NTSTATUS {
    let mut loaded = LOADED.lock().unwrap_or_else(|p| p.into_inner());
    if loaded.is_some() {
        return STATUS_SUCCESS;
    }
    // The event queue is created inside `driver_entry`, so the read mode has to
    // be chosen before it runs.
    wdk::ioqueue::set_default_blocking(true);
    let mut driver_object = Box::new(DRIVER_OBJECT::new());
    let mut registry = UNICODE_STRING;
    let status = driver::driver_entry(driver_object.as_mut(), &mut registry);
    if status == STATUS_SUCCESS {
        *loaded = Some(LoadedDriver(driver_object));
    }
    status
}

/// Unloads the driver through its registered `DriverUnload`, like the kernel on
/// service stop. No-op if nothing is loaded.
pub fn unload() {
    let taken = LOADED.lock().unwrap_or_else(|p| p.into_inner()).take();
    if let Some(LoadedDriver(driver_object)) = taken {
        if let Some(driver_unload) = driver_object.DriverUnload {
            unsafe { driver_unload(driver_object.as_ref()) };
        }
    }
}

/// Unloads any loaded driver and loads a fresh one.
pub fn reload() -> NTSTATUS {
    unload();
    load()
}

/// Runs `f` with the loaded driver's `DRIVER_OBJECT` (e.g. to open a
/// user-space connection to it). `None` if no driver is loaded.
pub fn with_driver_object<R>(f: impl FnOnce(&DRIVER_OBJECT) -> R) -> Option<R> {
    let loaded = LOADED.lock().unwrap_or_else(|p| p.into_inner());
    loaded.as_ref().map(|LoadedDriver(driver_object)| f(driver_object))
}
