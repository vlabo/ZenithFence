use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};
use protocol::info::{Info, Severity};

#[cfg(not(debug_assertions))]
pub const LOG_LEVEL: u8 = Severity::Error as u8;

#[cfg(debug_assertions)]
pub const LOG_LEVEL: u8 = Severity::Error as u8;

static mut LOG_LINES: [AtomicPtr<Info>; 10000] = unsafe { MaybeUninit::zeroed().assume_init() };
static START_INDEX: AtomicUsize = unsafe { MaybeUninit::zeroed().assume_init() };
static END_INDEX: AtomicUsize = unsafe { MaybeUninit::zeroed().assume_init() };

pub fn add_line(severity: Severity, prefix: String, line_str: String) {
    let mut index = END_INDEX.fetch_add(1, Ordering::Acquire);
    unsafe {
        index %= LOG_LINES.len();
        let ptr = &mut LOG_LINES[index];
        let line = Box::new(protocol::info::log_line(severity, prefix, line_str));
        let old = ptr.swap(Box::into_raw(line), Ordering::SeqCst);
        if !old.is_null() {
            _ = Box::from_raw(old);
        }
    }
}

pub fn flush() -> Vec<Info> {
    let mut vec = Vec::new();
    let end_index = END_INDEX.load(Ordering::Acquire);
    let start_index = START_INDEX.load(Ordering::Acquire);
    if end_index <= start_index {
        return vec;
    }
    unsafe {
        let count = end_index - start_index;
        for i in start_index..start_index + count {
            let index = i % LOG_LINES.len();
            let ptr = LOG_LINES[index].swap(core::ptr::null_mut(), Ordering::SeqCst);
            if !ptr.is_null() {
                vec.push(*Box::from_raw(ptr));
            }
        }
    }

    START_INDEX.store(end_index, Ordering::Release);
    vec
}

#[macro_export]
macro_rules! crit {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Error as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $crate::logger::add_line(protocol::info::Severity::Critical, alloc::format!("{}:{} ", file!(), line!()), message)
        }
    });
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Error as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $crate::logger::add_line(protocol::info::Severity::Error, alloc::format!("{}:{} ", file!(), line!()), message)
        }
    });
}

#[macro_export]
macro_rules! dbg {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Debug as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $crate::logger::add_line(protocol::info::Severity::Debug, alloc::format!("{}:{} ", file!(), line!()), message)
        }
    });
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Warning as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $crate::logger::add_line(protocol::info::Severity::Warning, alloc::format!("{}:{} ", file!(), line!()), message)
        }
    });
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Info as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $crate::logger::add_line(protocol::info::Severity::Info, alloc::format!("{}:{} ", file!(), line!()), message)
        }
    });
}
