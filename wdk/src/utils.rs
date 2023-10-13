use alloc::string::{String, ToString};
use ntstatus::ntstatus::NtStatus;
use windows_sys::Win32::Foundation::STATUS_SUCCESS;

pub fn check_ntstatus(status: i32) -> Result<(), String> {
    if status == STATUS_SUCCESS {
        return Ok(());
    }

    let Some(status) = NtStatus::from_u32(status as u32) else {
        return Err("UNKNOWN_ERROR_CODE".to_string());
    };

    return Err(status.to_string());
}
