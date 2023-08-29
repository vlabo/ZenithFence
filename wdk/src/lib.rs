#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod allocator;
pub mod consts;
pub mod debug;
pub mod interface;
pub mod ioqueue;
pub mod layer;
pub mod lock;

// Needed by the linker for legacy reasons. Not important for rust.
#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

// Needed by the compiler but not used.
#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 {
    0
}
