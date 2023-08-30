#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ($crate::interface::dbg_print(alloc::format!($($arg)*)));
}
