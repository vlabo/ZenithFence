use alloc::format;
use alloc::string::{String, ToString};
use ntstatus::ntstatus::NtStatus;
use windows_sys::Win32::Foundation::STATUS_SUCCESS;

use crate::consts::{APC_LEVEL, KERNEL_MODE};
use crate::ffi;

/// Kernel wait intervals are counted in 100-nanosecond units.
const HUNDRED_NANOS_PER_MILLISECOND: i64 = 10_000;

/// Returns the symbolic name of an NTSTATUS value, or a placeholder if it is not a known code.
pub fn ntstatus_name(status: i32) -> String {
    let Some(name) = NtStatus::from_u32(status as u32) else {
        return "UNKNOWN_ERROR_CODE".to_string();
    };

    return name.to_string();
}

pub fn check_ntstatus(status: i32) -> Result<(), String> {
    if status == STATUS_SUCCESS {
        return Ok(());
    }

    return Err(ntstatus_name(status));
}

pub fn get_system_timestamp_ms() -> u64 {
    // 100 nano seconds units -> device by 10 -> micro seconds -> divide by 1000 -> milliseconds
    unsafe { ffi::pm_QuerySystemTime() / 10_000 }
}

/// Blocks the calling thread for at least `milliseconds`, giving the rest of the system a chance
/// to make progress. The wait is non-alertable, so an APC does not cut it short.
///
/// Only usable at IRQL <= APC_LEVEL. Waiting above that would bugcheck, so the level is checked
/// and reported as an error instead.
pub fn sleep_ms(milliseconds: u32) -> Result<(), String> {
    let irql = unsafe { ffi::KeGetCurrentIrql() };
    if irql > APC_LEVEL {
        return Err(format!("cannot wait at IRQL {}", irql));
    }

    // A negative interval is relative to now; a positive one would be an absolute system time.
    // The multiplication cannot overflow: u32 milliseconds times 10_000 stays well inside an i64.
    let interval = -(i64::from(milliseconds) * HUNDRED_NANOS_PER_MILLISECOND);
    let status = unsafe { ffi::KeDelayExecutionThread(KERNEL_MODE, 0, &interval) };

    return check_ntstatus(status);
}

// get_system_timestamp_ns return the number of nanoseconds since the start of the system. SHould be used only for performance measurements.
pub fn get_startup_time_ns() -> u64 {
    let mut freq: i64 = 0;
    let counter = unsafe { ffi::KeQueryPerformanceCounter(&mut freq as *mut i64) };
    // Convert counter ticks to nanoseconds
    ((counter as u128) * 1_000_000_000u128 / freq as u128) as u64
}
