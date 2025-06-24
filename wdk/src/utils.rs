use alloc::string::{String, ToString};
use ntstatus::ntstatus::NtStatus;
use windows_sys::Win32::Foundation::STATUS_SUCCESS;

use crate::ffi;

pub fn check_ntstatus(status: i32) -> Result<(), String> {
    if status == STATUS_SUCCESS {
        return Ok(());
    }

    let Some(status) = NtStatus::from_u32(status as u32) else {
        return Err("UNKNOWN_ERROR_CODE".to_string());
    };

    return Err(status.to_string());
}

pub fn get_system_timestamp_ms() -> u64 {
    // 100 nano seconds units -> device by 10 -> micro seconds -> divide by 1000 -> milliseconds
    unsafe { ffi::pm_QuerySystemTime() / 10_000 }
}

// get_system_timestamp_ns return the number of nanoseconds since the start of the system. SHould be used only for performance measurements.
pub fn get_startup_time_ns() -> u64 {
    let mut freq: i64 = 0;
    let counter = unsafe { ffi::KeQueryPerformanceCounter(&mut freq as *mut i64) };
    // Convert counter ticks to nanoseconds
    ((counter as u128) * 1_000_000_000u128 / freq as u128) as u64
}
