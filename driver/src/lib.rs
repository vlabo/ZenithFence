#![cfg_attr(not(any(test, feature = "mock")), no_std)]
#![cfg_attr(not(any(test, feature = "mock")), no_main)]
#![allow(clippy::needless_return)]

// In the host fuzz/test build, redirect every `wdk::...` path in this crate to
// the pure-Rust `mock_wdk` crate. The production build (default `real_wdk`
// feature) leaves this out and uses the real kernel `wdk` dependency.
#[cfg(feature = "mock")]
extern crate mock_wdk as wdk;

#[cfg(all(feature = "real_wdk", feature = "mock"))]
compile_error!("features `real_wdk` and `mock` are mutually exclusive; build mock with --no-default-features --features mock");

extern crate alloc;

mod ale_callouts;
mod array_holder;
pub mod mpsc_queue;
mod callouts;
mod common;
mod connection;
mod connection_cache;
mod rcu_port;
mod device;
mod entry;
mod id_cache;
pub mod logger;
mod packet_callouts;
mod packet_util;

// Public surface used only by host property tests and the external fuzz crate.
// Gated on `mock` (not `test`) because it references mock-only constructors; a
// plain `cargo test` with the real `wdk` cannot link the driver anyway. Run
// tests with: cargo test --no-default-features --features mock
#[cfg(feature = "mock")]
pub mod fuzz_api;

// Full-driver simulation harness: loads the real driver over the mocked WDK and
// drives it through the user-space channel with real producer/consumer threads.
#[cfg(feature = "mock")]
pub mod sim;

#[cfg(not(any(test, feature = "mock")))]
use wdk::allocator::WindowsAllocator;

#[cfg(not(any(test, feature = "mock")))]
use core::panic::PanicInfo;

// Declaration of the global memory allocator
#[cfg(not(any(test, feature = "mock")))]
#[global_allocator]
static HEAP: WindowsAllocator = WindowsAllocator {};

#[cfg(not(any(test, feature = "mock")))]
#[no_mangle]
pub extern "system" fn _DllMainCRTStartup() {}

#[cfg(not(any(test, feature = "mock")))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use wdk::err;

    err!("{}", info);
    loop {}
}
