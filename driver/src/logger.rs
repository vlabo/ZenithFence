use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use wdk::rw_spin_lock::RwSpinLock;

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

pub(crate) struct Logger {
    log_lines: Option<Vec<LogLine>>,
    lock: RwSpinLock,
}

impl Logger {
    pub fn init(&mut self) {
        self.log_lines = Some(Vec::new());
    }

    pub fn add_line(&mut self, severity: Severity, line: String) {
        let _guard = self.lock.write_lock();
        if let Some(log_lines) = &mut self.log_lines {
            log_lines.push(LogLine {
                severity: severity as u8,
                line,
            });
        }
    }

    pub fn flush(&mut self) -> Vec<LogLine> {
        let lines;
        {
            let _guard = self.lock.write_lock();
            lines = self.log_lines.replace(Vec::new());
        }
        lines.unwrap()
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
