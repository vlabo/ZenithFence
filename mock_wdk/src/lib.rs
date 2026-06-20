//! Host-side mock of the `wdk` crate.
//!
//! Mirrors the module tree and the exact public method signatures the `driver`
//! crate consumes, backed by ordinary host data structures (Vec, UnsafeCell,
//! VecDeque) instead of kernel objects. No `windows_sys`, no FFI, no `#[link]`.

pub mod consts;
pub mod driver;
pub mod filter_engine;
pub mod ioqueue;
pub mod irp_helpers;
pub mod rw_spin_lock;
pub mod utils;

// Logging macros. The driver calls these through the renamed crate path
// (`wdk::dbg!`, `wdk::info!`, `wdk::err!`). They expand to a no-op that still
// evaluates the arguments (so there are no "unused variable" warnings and any
// side effects in the format arguments are preserved). The driver's *own*
// `crate::dbg!` / `crate::err!` macros (defined in `driver/src/logger.rs`) are
// unaffected -- only the `wdk::`-qualified calls resolve here.

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

#[macro_export]
macro_rules! dbg {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}
