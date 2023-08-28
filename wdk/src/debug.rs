#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => (wdk::interface::dbg_print(alloc::format!($($arg)*)));
}
