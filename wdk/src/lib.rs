#![cfg_attr(not(test), no_std)]
#![allow(clippy::needless_return)]

extern crate alloc;

pub mod allocator;
pub mod consts;
pub mod debug;
pub mod driver;
pub mod error;
pub mod filter_engine;
pub mod interface;
pub mod ioqueue;
pub mod irp_helpers;
pub mod rw_spin_lock;
pub mod spin_lock;
pub mod utils;

#[allow(dead_code)]
pub mod ffi;

/// Re-exports of the kernel / Win32 types the driver's entry plumbing names
/// (`DriverEntry`, the IRP dispatch handlers). The driver refers to them through
/// `wdk::kernel_types::*` so the host mock can provide API-compatible stand-ins
/// under the same path, letting the same `entry.rs` compile in both builds.
pub mod kernel_types {
    pub use windows_sys::Wdk::Foundation::{DEVICE_OBJECT, DRIVER_OBJECT, IRP};
    pub use windows_sys::Win32::Foundation::{
        NTSTATUS, STATUS_FAILED_DRIVER_ENTRY, STATUS_SUCCESS, UNICODE_STRING,
    };
}

// Needed by the linker for legacy reasons. Not important for rust.
#[cfg(not(test))]
#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

// Needed by the compiler but not used.
#[cfg(not(test))]
#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    0
}
