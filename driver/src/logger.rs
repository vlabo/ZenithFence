use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub const LOG_LEVEL: u8 = Severity::Debug as u8;

#[derive(Serialize, Deserialize, Debug)]
#[repr(u8)]
pub enum Severity {
    Trace = 1,
    Debug = 2,
    Info = 3,
    Warning = 4,
    Error = 5,
    Critical = 6,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct LogLine {
    severity: u8,
    line: String,
}

struct Synced {
    value: Option<LogLine>,
    processing: AtomicBool,
}

pub(crate) struct Logger {
    log_lines: [Synced; 1024],
    start_index: usize,
    end_index: AtomicUsize,
}

impl Logger {
    pub fn init(&mut self) {
        for line in &mut self.log_lines {
            line.value = None;
            line.processing = AtomicBool::default();
        }
    }

    pub fn add_line(&mut self, severity: Severity, line_str: String) {
        let mut index = self.end_index.fetch_add(1, Ordering::Acquire);
        index %= self.log_lines.len();
        let line = &mut self.log_lines[index];
        let result =
            line.processing
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed);
        if result.is_err() {
            return;
        }

        line.value = Some(LogLine {
            severity: severity as u8,
            line: line_str,
        });
        line.processing.store(false, Ordering::Release);
    }

    pub fn flush(&mut self) -> Vec<LogLine> {
        let mut vec = Vec::new();
        loop {
            if self.end_index.load(Ordering::Acquire) <= self.start_index {
                break;
            }
            let index = self.start_index % self.log_lines.len();
            let line = &mut self.log_lines[index];
            if line.processing.load(Ordering::SeqCst) {
                break;
            }

            if let Some(line) = line.value.take() {
                vec.push(line);
            }

            self.start_index = self.start_index.wrapping_add(1);
        }
        vec
    }
}

#[macro_export]
macro_rules! crit {
    ($log:expr, $($arg:tt)*) => ({
        if $crate::logger::Severity::Error as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line($crate::logger::Severity::Critical, alloc::format!("{}:{} {}", core::module_path!(), line!(), message))
        }
    });
}

#[macro_export]
macro_rules! err {
    ($log:expr, $($arg:tt)*) => ({
        if $crate::logger::Severity::Error as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line($crate::logger::Severity::Error, alloc::format!("{}:{} {}", core::module_path!(), line!(), message))
        }
    });
}

#[macro_export]
macro_rules! dbg {
    ($log:expr, $($arg:tt)*) => ({
        if $crate::logger::Severity::Debug as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line($crate::logger::Severity::Debug, alloc::format!("{}:{} {}", core::module_path!(), line!(), message))
        }
    });
}

#[macro_export]
macro_rules! warn {
    ($log:expr, $($arg:tt)*) => ({
        if $crate::logger::Severity::Warning as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line($crate::logger::Severity::Warning, alloc::format!( "{}:{} {}", core::module_path!(), line!(), message))
        }
    });
}

#[macro_export]
macro_rules! info {
    ($log:expr, $($arg:tt)*) => ({
        if $crate::logger::Severity::Info as u8 >= $crate::logger::LOG_LEVEL {
            let message = alloc::format!($($arg)*);
            $log.add_line($crate::logger::Severity::Info, alloc::format!( "{}:{} {}", core::module_path!(), line!(), message))
        }
    });
}
