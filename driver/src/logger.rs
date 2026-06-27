use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use protocol::info::{Info, Severity};

pub const LOG_LEVEL: u8 = Severity::Error as u8;

pub const MAX_LOG_LINE_SIZE: usize = 150;
const SIZE_OF_LOG_LINE_BUFFER: usize = 1024;
static LOG_LINES: [AtomicPtr<Info>; SIZE_OF_LOG_LINE_BUFFER] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; SIZE_OF_LOG_LINE_BUFFER];
static START_INDEX: AtomicUsize = AtomicUsize::new(0);
static END_INDEX: AtomicUsize = AtomicUsize::new(0);

pub fn add_line(log_line: Info) {
    let index = END_INDEX.fetch_add(1, Ordering::SeqCst) % SIZE_OF_LOG_LINE_BUFFER;
    let line = Box::new(log_line);
    let old = LOG_LINES[index].swap(Box::into_raw(line), Ordering::SeqCst);
    if !old.is_null() {
        // `old` was produced by `Box::into_raw` in a previous `add_line`.
        unsafe { _ = Box::from_raw(old) };
    }
}

pub fn flush() -> Vec<Info> {
    let mut vec = Vec::new();
    let end_index = END_INDEX.load(Ordering::SeqCst);
    let start_index = START_INDEX.load(Ordering::SeqCst);
    if end_index <= start_index {
        return vec;
    }
    let count = end_index - start_index;
    for i in start_index..start_index + count {
        let index = i % SIZE_OF_LOG_LINE_BUFFER;
        let ptr = LOG_LINES[index].swap(core::ptr::null_mut(), Ordering::SeqCst);
        if !ptr.is_null() {
            // `ptr` was produced by `Box::into_raw` in `add_line`.
            vec.push(*unsafe { Box::from_raw(ptr) });
        }
    }

    START_INDEX.store(end_index, Ordering::SeqCst);
    vec
}

#[macro_export]
macro_rules! log_internal {
    ($log_line:expr, $($arg:tt)*) => ({
        use core::fmt::Write;
        _ = write!($log_line, "{}:{} ", file!(), line!());
        _ = write!($log_line, $($arg)*);
        $crate::logger::add_line($log_line);
    });
}

#[macro_export]
macro_rules! crit {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Critical as u8 >= $crate::logger::LOG_LEVEL {
            let mut log_line = protocol::info::log_line(protocol::info::Severity::Critical, $crate::logger::MAX_LOG_LINE_SIZE);
            $crate::log_internal!(log_line, $($arg)*);
        }
    });
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Error as u8 >= $crate::logger::LOG_LEVEL {
            let mut log_line = protocol::info::log_line(protocol::info::Severity::Error, $crate::logger::MAX_LOG_LINE_SIZE);
            $crate::log_internal!(log_line, $($arg)*);
        }
    });
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Warning as u8 >= $crate::logger::LOG_LEVEL {
            let mut log_line = protocol::info::log_line(protocol::info::Severity::Warning, $crate::logger::MAX_LOG_LINE_SIZE);
            $crate::log_internal!(log_line, $($arg)*);
        }
    });
}

#[macro_export]
macro_rules! dbg {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Debug as u8 >= $crate::logger::LOG_LEVEL {
            let mut log_line = protocol::info::log_line(protocol::info::Severity::Debug, $crate::logger::MAX_LOG_LINE_SIZE);
            $crate::log_internal!(log_line, $($arg)*);
        }
    });
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        if protocol::info::Severity::Info as u8 >= $crate::logger::LOG_LEVEL {
            let mut log_line = protocol::info::log_line(protocol::info::Severity::Info, $crate::logger::MAX_LOG_LINE_SIZE);
            $crate::log_internal!(log_line, $($arg)*);
        }
    });
}
