#![cfg_attr(not(test), no_std)]
#![allow(clippy::needless_return)]

extern crate alloc;

// The modules marked `pub` are the driver's public API: the callout entry
// points, the device and its caches, the packet helpers. The kernel image
// (kernel/) only needs `driver_entry`; the rest is public so the host test
// harness (mock/harness) can drive and observe the very same code over the
// mock WDK.
pub mod ale_callouts;
mod pending_event;
mod callouts;
mod common;
pub mod connection;
pub mod connection_cache;
mod port_connections;
pub mod device;
pub mod entry;
mod filter_reset_queue;
pub mod id_cache;
pub mod logger;
pub mod packet_callouts;
pub mod packet_util;

// The driver entry point. The production build root (kernel/) exports it as
// `DriverEntry`.
pub use entry::driver_entry;

// The global allocator, panic handler and the exported `DriverEntry` are not
// here: they belong to the kernel image, so they live in the production build
// root (kernel/src/lib.rs).
