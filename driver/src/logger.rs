use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct LogLine {
    severity: String,
    line: String,
}

pub(crate) struct Logger {
    log_lines: Option<VecDeque<LogLine>>,
}

impl Logger {
    pub fn init(&mut self) {
        self.log_lines = Some(VecDeque::new());
    }

    pub fn add_line(&mut self, severity: &str, line: String) {
        if let Some(log_lines) = &mut self.log_lines {
            log_lines.push_back(LogLine {
                severity: severity.to_string(),
                line,
            });
        }
    }

    pub fn flush(&mut self) -> VecDeque<LogLine> {
        let lines = self.log_lines.replace(VecDeque::new());
        lines.unwrap()
    }
}

#[macro_export]
macro_rules! err {
    ($log:expr, $($arg:tt)*) => ({
        let message = alloc::format!($($arg)*);
        $log.add_line("err", alloc::format!("{}: {}", core::module_path!(), message))
    });
}

#[macro_export]
macro_rules! dbg {
    ($log:expr, $($arg:tt)*) => ({
        let message = alloc::format!($($arg)*);
        $log.add_line("dbg", alloc::format!("{}: {}", core::module_path!(), message))
    });
}

#[macro_export]
macro_rules! info {
    ($log:expr, $($arg:tt)*) => ({
        let message = alloc::format!($($arg)*);
        $log.add_line("info", alloc::format!( "{}: {}", core::module_path!(), message))
    });
}
