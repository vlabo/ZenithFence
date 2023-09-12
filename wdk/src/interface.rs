use crate::alloc::borrow::ToOwned;
use crate::utils::Driver;
use alloc::ffi::CString;
use alloc::string::String;
use ntstatus::ntstatus::NtStatus;
use widestring::U16CString;
use winapi::shared::ntdef::UNICODE_STRING;
use winapi::{ctypes::wchar_t, km::wdm::DRIVER_OBJECT};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, NTSTATUS};
#[derive(Debug, onlyerror::Error)]
pub enum Error {
    #[error("invalid string argument: {0}")]
    InvalidString(String),
    #[error("ntstatus: {0}")]
    NTStatus(NtStatus),
    #[error("unknown result")]
    UnknownResult,
}

extern "C" {
    // Debug
    fn DbgPrint(str: *const i8);
}

extern "C" {
    // Helper
    pub fn pm_InitDriverObject(
        driverObject: *mut DRIVER_OBJECT,
        registryPath: *mut UNICODE_STRING,
        driver: *mut HANDLE,
        device: *mut HANDLE,
        win_driver_path: *const wchar_t,
        dos_driver_path: *const wchar_t,
    ) -> NTSTATUS;
}

// Debug
pub fn dbg_print(str: String) {
    if let Ok(c_str) = CString::new(str) {
        unsafe {
            DbgPrint(c_str.as_ptr());
        }
    }
}

pub fn init_driver_object(
    driver_object: *mut DRIVER_OBJECT,
    registry_path: *mut UNICODE_STRING,
    win_driver_path: &str,
    dos_driver_path: &str,
) -> Result<Driver, Error> {
    let mut driver_handle = INVALID_HANDLE_VALUE;
    let mut device_handle = INVALID_HANDLE_VALUE;

    let Ok(win_driver) = U16CString::from_str(win_driver_path) else {
        return Err(Error::InvalidString("win_driver_path".to_owned()));
    };
    let Ok(dos_driver) = U16CString::from_str(dos_driver_path) else {
        return Err(Error::InvalidString("dos_driver_path".to_owned()));
    };

    let win_driver_raw = win_driver.into_raw();
    let dos_driver_raw = dos_driver.into_raw();

    unsafe {
        let status = pm_InitDriverObject(
            driver_object,
            registry_path,
            &mut driver_handle,
            &mut device_handle,
            win_driver_raw,
            dos_driver_raw,
        );

        // Free string memory
        let _ = U16CString::from_raw(win_driver_raw);
        let _ = U16CString::from_raw(dos_driver_raw);

        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(Driver::new(driver_handle, device_handle));
        }

        Err(Error::NTStatus(status))
    }
}
