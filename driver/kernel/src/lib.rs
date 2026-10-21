//! Production build root of the kernel driver.
//!
//! This crate only adds what a kernel image needs at link time on top of the
//! `driver` core: the global allocator, the panic handler, the CRT stub and the
//! exported `DriverEntry`. All driver logic lives in `driver`, which the host
//! fuzz/simulation harnesses build against `mock_wdk` instead. Keep this crate
//! free of logic so the code they test is the code that ships.

#![no_std]
#![no_main]

// The wdk logging macros (`err!` in the panic handler) format through `alloc`.
extern crate alloc;

use core::panic::PanicInfo;
use wdk::allocator::WindowsAllocator;
use wdk::kernel_types::{DRIVER_OBJECT, NTSTATUS, UNICODE_STRING};

// Declaration of the global memory allocator
#[global_allocator]
static HEAP: WindowsAllocator = WindowsAllocator {};

#[no_mangle]
pub extern "system" fn _DllMainCRTStartup() {}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use wdk::err;

    err!("{}", info);
    loop {}
}

// DriverEntry is the entry point of the driver (main function). Will be called
// when the driver is loaded. The exported name must not change.
#[export_name = "DriverEntry"]
pub extern "system" fn driver_entry(
    driver_object: *mut DRIVER_OBJECT,
    registry_path: *mut UNICODE_STRING,
) -> NTSTATUS {
    driver::driver_entry(driver_object, registry_path)
}
