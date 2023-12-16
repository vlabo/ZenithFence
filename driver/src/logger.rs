use alloc::collections::VecDeque;
use alloc::string::String;
use serde::{Deserialize, Serialize};
use wdk::rw_spin_lock::RwSpinLock;

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
    log_lines: Option<VecDeque<LogLine>>,
    lock: RwSpinLock,
}

impl Logger {
    pub fn init(&mut self) {
        self.log_lines = Some(VecDeque::new());
    }

    pub fn add_line(&mut self, severity: Severity, line: String) {
        let _guard = self.lock.write_lock();
        if let Some(log_lines) = &mut self.log_lines {
            log_lines.push_back(LogLine {
                severity: severity as u8,
                line,
            });
        }
    }

    pub fn flush(&mut self) -> VecDeque<LogLine> {
        let lines;
        {
            let _guard = self.lock.write_lock();
            lines = self.log_lines.replace(VecDeque::new());
        }
        lines.unwrap()
    }
}

#[macro_export]
macro_rules! crit {
    ($log:expr, $($arg:tt)*) => ({
        let message = alloc::format!($($arg)*);
        $log.add_line($crate::logger::Severity::Critical, alloc::format!("{}:{} {}", core::module_path!(), line!(), message))
    });
}

#[macro_export]
macro_rules! err {
    ($log:expr, $($arg:tt)*) => ({
        let message = alloc::format!($($arg)*);
        $log.add_line($crate::logger::Severity::Error, alloc::format!("{}:{} {}", core::module_path!(), line!(), message))
    });
}

#[macro_export]
macro_rules! dbg {
    ($log:expr, $($arg:tt)*) => ({
        let message = alloc::format!($($arg)*);
        $log.add_line($crate::logger::Severity::Debug, alloc::format!("{}:{} {}", core::module_path!(), line!(), message))
    });
}

#[macro_export]
macro_rules! warn {
    ($log:expr, $($arg:tt)*) => ({
        let message = alloc::format!($($arg)*);
        $log.add_line($crate::logger::Severity::Warning, alloc::format!( "{}:{} {}", core::module_path!(), line!(), message))
    });
}

#[macro_export]
macro_rules! info {
    ($log:expr, $($arg:tt)*) => ({
        let message = alloc::format!($($arg)*);
        $log.add_line($crate::logger::Severity::Info, alloc::format!( "{}:{} {}", core::module_path!(), line!(), message))
    });
}
