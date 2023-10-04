#![cfg_attr(not(test), no_std)]
#![feature(error_in_core)]
#![feature(const_maybe_uninit_zeroed)]

extern crate alloc;

pub mod allocator;
pub mod consts;
pub mod debug;
pub mod error;
pub mod filter_engine;
pub mod interface;
pub mod ioqueue;
// pub mod lock;
pub mod utils;

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
