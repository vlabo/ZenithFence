#![cfg_attr(not(test), no_std)]
#![allow(clippy::needless_return)]

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
mod filter_reset_queue;
mod id_cache;
pub mod logger;
mod packet_callouts;
mod packet_util;

// The driver entry point. The production build root (kernel/) exports it as
// `DriverEntry`.
pub use entry::driver_entry;

// The global allocator, panic handler and the exported `DriverEntry` are not
// here: they belong to the kernel image, so they live in the production build
// root (kernel/src/lib.rs).
