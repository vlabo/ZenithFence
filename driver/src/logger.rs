use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use protocol::info::{LogLine, Severity};

pub const LOG_LEVEL: u8 = Severity::Debug as u8;

pub(crate) struct Logger {
    log_lines: [AtomicPtr<LogLine>; 1024],
    start_index: usize,
    end_index: AtomicUsize,
}

impl Logger {
    pub fn init(&mut self) {
        for ptr in &mut self.log_lines {
            ptr.store(core::ptr::null_mut(), Ordering::Relaxed);
        }
    }

    pub fn add_line(&mut self, severity: Severity, prefix: String, line_str: String) {
        let mut index = self.end_index.fetch_add(1, Ordering::Acquire);
        index %= self.log_lines.len();
        let ptr = &mut self.log_lines[index];
        let line = Box::new(LogLine::new(severity, prefix, line_str));
        let old = ptr.swap(Box::into_raw(line), Ordering::Release);
        if !old.is_null() {
            unsafe {
                _ = Box::from_raw(old);
            }
        }
    }

    pub fn flush(&mut self) -> Vec<Box<LogLine>> {
        let mut vec = Vec::new();
        let end_index = self.end_index.load(Ordering::Acquire);
        if end_index <= self.start_index {
            return vec;
        }
        let start_index = self.start_index;
        let count = end_index - start_index;
        for i in start_index..start_index + count {
            let index = i % self.log_lines.len();
            let ptr = self.log_lines[index].swap(core::ptr::null_mut(), Ordering::Acquire);
            unsafe {
                if !ptr.is_null() {
                    vec.push(Box::from_raw(ptr));
                }
            }
        }

        self.start_index = end_index;
        vec
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        for line in &self.log_lines {
            let ptr = line.load(Ordering::Relaxed);
            unsafe {
                if !ptr.is_null() {
                    _ = Box::from_raw(ptr);
                }
            }
        }
    }
}

#[macro_export]
macro_rules! crit {
    ($log:expr, $($arg:tt)*) => ({
        if protocol::info::Severity::Error as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line(protocol::info::Severity::Critical, alloc::format!("{}:{} ", core::module_path!(), line!()), message)
        }
    });
}

#[macro_export]
macro_rules! err {
    ($log:expr, $($arg:tt)*) => ({
        if protocol::info::Severity::Error as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line(protocol::info::Severity::Error, alloc::format!("{}:{} ", core::module_path!(), line!()), message)
        }
    });
}

#[macro_export]
macro_rules! dbg {
    ($log:expr, $($arg:tt)*) => ({
        if protocol::info::Severity::Debug as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line(protocol::info::Severity::Debug, alloc::format!("{}:{} ", core::module_path!(), line!()), message)
        }
    });
}

#[macro_export]
macro_rules! warn {
    ($log:expr, $($arg:tt)*) => ({
        if protocol::info::Severity::Warning as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line(protocol::info::Severity::Warning, alloc::format!("{}:{} ", core::module_path!(), line!()), message)
        }
    });
}

#[macro_export]
macro_rules! info {
    ($log:expr, $($arg:tt)*) => ({
        if protocol::info::Severity::Info as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line(protocol::info::Severity::Info, alloc::format!("{}:{} ", core::module_path!(), line!()), message)
        }
    });
}
