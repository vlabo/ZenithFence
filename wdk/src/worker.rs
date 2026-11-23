use core::{
    cell::UnsafeCell,
    ffi::c_void,
    mem::MaybeUninit,
    sync::atomic::{AtomicPtr, Ordering},
};

use alloc::{boxed::Box, format, string::String};
use windows_sys::{
    Wdk::{
        Foundation::{KEVENT, OBJECT_ATTRIBUTES},
        System::SystemServices::{
            Executive, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject,
            ObReferenceObjectByHandle, ObfDereferenceObject, PsTerminateSystemThread,
        },
    },
    Win32::{
        Foundation::{STATUS_SUCCESS, STATUS_TIMEOUT},
        System::Kernel::{NotificationEvent, OBJ_KERNEL_HANDLE},
    },
};

use crate::{consts::KERNEL_MODE, ffi, utils::check_ntstatus};

/// THREAD_ALL_ACCESS (winnt.h).
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;

/// What the thread works with. Boxed by `PeriodicWorker`, so its address stays the same for as
/// long as the thread runs.
struct Shared {
    stop: UnsafeCell<KEVENT>,
    /// The wait between two runs, in 100-nanosecond units (negative: relative to now).
    interval: i64,
    routine: fn(),
}

/// A kernel thread that calls a routine at a fixed interval, at PASSIVE_LEVEL, until stopped.
///
/// The routine runs on a thread of its own, so it may wait and call routines that require
/// PASSIVE_LEVEL. It is never called again once `stop` has returned.
pub struct PeriodicWorker {
    shared: Box<Shared>,
    /// The referenced thread object; null once the worker was stopped.
    thread: AtomicPtr<c_void>,
}

unsafe impl Sync for PeriodicWorker {}
unsafe impl Send for PeriodicWorker {}

impl PeriodicWorker {
    /// Starts a thread that calls `routine` every `interval_ms` milliseconds, the first time one
    /// interval from now. PASSIVE_LEVEL only.
    pub fn start(interval_ms: u32, routine: fn()) -> Result<Self, String> {
        let shared = Box::new(Shared {
            stop: UnsafeCell::new(unsafe { MaybeUninit::zeroed().assume_init() }),
            interval: -(i64::from(interval_ms) * 10_000),
            routine,
        });

        unsafe {
            KeInitializeEvent(shared.stop.get(), NotificationEvent, 0);

            // A kernel handle, so no user process can reach it.
            let object_attributes = OBJECT_ATTRIBUTES {
                Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: 0,
                ObjectName: core::ptr::null(),
                Attributes: OBJ_KERNEL_HANDLE as u32,
                SecurityDescriptor: core::ptr::null(),
                SecurityQualityOfService: core::ptr::null(),
            };
            let mut handle = 0;
            check_ntstatus(ffi::PsCreateSystemThread(
                &mut handle,
                THREAD_ALL_ACCESS,
                &object_attributes,
                0,
                core::ptr::null_mut(),
                thread_main,
                &*shared as *const Shared as *mut c_void,
            ))
            .map_err(|err| format!("failed to create worker thread: {}", err))?;

            // Waiting for the thread to end needs the thread object, not the handle.
            let mut thread = core::ptr::null_mut();
            let status = ObReferenceObjectByHandle(
                handle,
                THREAD_ALL_ACCESS,
                0, // Any object type: the handle was just created as a thread.
                KERNEL_MODE,
                &mut thread,
                core::ptr::null_mut(),
            );
            _ = ffi::ZwClose(handle);
            if let Err(err) = check_ntstatus(status) {
                // The thread is running and cannot be waited for. Stop it, and leak what it uses
                // rather than free memory it may still read.
                KeSetEvent(shared.stop.get(), 0, 0);
                Box::leak(shared);
                return Err(format!("failed to reference worker thread: {}", err));
            }

            Ok(Self {
                shared,
                thread: AtomicPtr::new(thread),
            })
        }
    }

    /// Stops the thread and waits until it has ended; a routine that is running finishes first.
    /// Safe to call more than once. PASSIVE_LEVEL only, and never from the routine itself.
    pub fn stop(&self) {
        let thread = self.thread.swap(core::ptr::null_mut(), Ordering::SeqCst);
        if thread.is_null() {
            return;
        }
        unsafe {
            KeSetEvent(self.shared.stop.get(), 0, 0);
            // The thread object is signaled once the thread has fully ended, after its last
            // instruction in this driver.
            KeWaitForSingleObject(thread, Executive, KERNEL_MODE, 0, core::ptr::null());
            ObfDereferenceObject(thread);
        }
    }
}

impl Drop for PeriodicWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

unsafe extern "system" fn thread_main(context: *mut c_void) {
    let shared = &*(context as *const Shared);
    loop {
        // Not alertable. Times out for the next run, or returns success once stopped.
        let status = KeWaitForSingleObject(
            shared.stop.get() as *const c_void,
            Executive,
            KERNEL_MODE,
            0,
            &shared.interval,
        );
        if status != STATUS_TIMEOUT {
            break;
        }
        (shared.routine)();
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}
