use crate::alloc::borrow::ToOwned;
use crate::{layer::Layer, utils::Driver};
use alloc::string::String;
use alloc::{ffi::CString, string};
use core::ptr;
use ntstatus::ntstatus::NtStatus;
use widestring::U16CString;
use winapi::{
    ctypes::wchar_t,
    km::wdm::{DEVICE_OBJECT, DRIVER_OBJECT},
    shared::ntdef::UNICODE_STRING,
};
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::{
    core::GUID,
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE},
};

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

#[link(name = "WdfDriverEntry", kind = "static")]
#[link(name = "WdfLdr", kind = "static")]
#[link(name = "BufferOverflowK", kind = "static")]
#[link(name = "uuid", kind = "static")]
#[link(name = "wdmsec", kind = "static")]
#[link(name = "wmilib", kind = "static")]
#[link(name = "ntoskrnl", kind = "static")]
#[link(name = "ndis", kind = "static")]
#[link(name = "wfp_lib", kind = "static")]
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
    fn pm_RegisterSublayer(
        filter_engine_handle: HANDLE,
        name: *const wchar_t,
        description: *const wchar_t,
        guid: GUID,
    ) -> NTSTATUS;
    fn pm_CreateFilterEngine(handle: *mut HANDLE) -> NTSTATUS;
    fn pm_RegisterCallout(
        device_object: *mut DEVICE_OBJECT,
        filter_engine_handle: HANDLE,
        name: *const wchar_t,
        description: *const wchar_t,
        guid: GUID,
        layer_guid: GUID,
        callout_fn: unsafe extern "C" fn(
            *const u8,
            *const u8,
            *mut u8,
            *const u8,
            *const u8,
            u64,
            *mut u8,
        ),
        callout_id: *mut u32,
    ) -> NTSTATUS;

    fn pm_RegisterFilter(
        filter_negine_handle: HANDLE,
        sublayer_guid: GUID,
        name: *const wchar_t,
        description: *const wchar_t,
        callout_guid: GUID,
        layer_guid: GUID,
        action: u32,
        filter_id: *mut u64,
    ) -> NTSTATUS;

    fn pm_GetDeviceObject(wdf_device: HANDLE) -> *mut DEVICE_OBJECT;
}

#[link(name = "Fwpkclnt", kind = "static")]
#[link(name = "Fwpuclnt", kind = "static")]
extern "C" {
    // Fwpm
    fn FwpmFilterDeleteById0(filter_engine_handle: HANDLE, id: u64) -> NTSTATUS;
    fn FwpsCalloutUnregisterById0(id: u32) -> NTSTATUS;
    fn FwpmSubLayerDeleteByKey0(filter_engine_handle: HANDLE, guid: *const GUID) -> NTSTATUS;

    fn FwpmEngineClose0(filter_engine_handle: HANDLE) -> NTSTATUS;
    fn FwpmTransactionBegin0(filter_engine_handle: HANDLE, flags: u32) -> NTSTATUS;
    fn FwpmTransactionCommit0(filter_engine_handle: HANDLE) -> NTSTATUS;
    fn FwpmTransactionAbort0(filter_engine_handle: HANDLE) -> NTSTATUS;
}

// Debug
pub fn dbg_print(str: string::String) {
    if let Ok(c_str) = CString::new(str) {
        unsafe {
            DbgPrint(c_str.as_ptr());
        }
    }
}

pub fn create_filter_engine() -> Result<HANDLE, Error> {
    unsafe {
        let mut handle: HANDLE = INVALID_HANDLE_VALUE;
        let status = pm_CreateFilterEngine(ptr::addr_of_mut!(handle));
        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(handle);
        }

        return Err(Error::NTStatus(status));
    }
}

pub fn register_sublayer(
    filter_engine_handle: HANDLE,
    name: &str,
    description: &str,
    guid: u128,
) -> Result<(), Error> {
    let Ok(name_cstr) = U16CString::from_str(name) else {
        return Err(Error::InvalidString("name".to_owned()));
    };
    let Ok(description_cstr) = U16CString::from_str(description) else {
        return Err(Error::InvalidString("description".to_owned()));
    };

    let name_raw = name_cstr.into_raw();
    let description_raw = description_cstr.into_raw();

    unsafe {
        let status = pm_RegisterSublayer(
            filter_engine_handle,
            name_raw,
            description_raw,
            GUID::from_u128(guid),
        );

        // Free string memory
        let _ = U16CString::from_raw(name_raw);
        let _ = U16CString::from_raw(description_raw);

        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(());
        }

        return Err(Error::NTStatus(status));
    }
}

pub fn unregister_sublayer(filter_engine_handle: HANDLE, guid: u128) -> Result<(), Error> {
    let guid = GUID::from_u128(guid);
    unsafe {
        let status = FwpmSubLayerDeleteByKey0(filter_engine_handle, ptr::addr_of!(guid));
        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(());
        }

        return Err(Error::NTStatus(status));
    }
}

pub fn register_callout(
    device_object: *mut DEVICE_OBJECT,
    filter_engine_handle: HANDLE,
    name: &str,
    description: &str,
    guid: u128,
    layer: Layer,
    callout_fn: unsafe extern "C" fn(
        *const u8,
        *const u8,
        *mut u8,
        *const u8,
        *const u8,
        u64,
        *mut u8,
    ),
) -> Result<u32, Error> {
    let Ok(name_cstr) = U16CString::from_str(name) else {
        return Err(Error::InvalidString("name".to_owned()));
    };
    let Ok(description_cstr) = U16CString::from_str(description) else {
        return Err(Error::InvalidString("description".to_owned()));
    };

    let name_raw = name_cstr.into_raw();
    let description_raw = description_cstr.into_raw();

    unsafe {
        let mut callout_id: u32 = 0;
        let status = pm_RegisterCallout(
            device_object,
            filter_engine_handle,
            name_raw,
            description_raw,
            GUID::from_u128(guid),
            layer.get_guid(),
            callout_fn,
            ptr::addr_of_mut!(callout_id),
        );

        // Free string memory
        let _ = U16CString::from_raw(name_raw);
        let _ = U16CString::from_raw(description_raw);
        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };

        if status == NtStatus::STATUS_SUCCESS {
            return Ok(callout_id);
        }

        return Err(Error::NTStatus(status));
    }
}

pub fn unregister_callout(callout_id: u32) -> Result<(), Error> {
    unsafe {
        let status = FwpsCalloutUnregisterById0(callout_id);

        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };

        if status == NtStatus::STATUS_SUCCESS {
            return Ok(());
        }

        return Err(Error::NTStatus(status));
    }
}

pub fn register_filter(
    filter_engine_handle: HANDLE,
    sublayer_guid: u128,
    name: &str,
    description: &str,
    callout_guid: u128,
    layer: Layer,
    action: u32,
) -> Result<u64, Error> {
    let Ok(name_cstr) = U16CString::from_str(name) else {
        return Err(Error::InvalidString("name".to_owned()));
    };
    let Ok(description_cstr) = U16CString::from_str(description) else {
        return Err(Error::InvalidString("description".to_owned()));
    };
    let name_raw = name_cstr.into_raw();
    let description_raw = description_cstr.into_raw();
    let mut filter_id: u64 = 0;
    unsafe {
        let status = pm_RegisterFilter(
            filter_engine_handle,
            GUID::from_u128(sublayer_guid),
            name_raw,
            description_raw,
            GUID::from_u128(callout_guid),
            layer.get_guid(),
            action,
            ptr::addr_of_mut!(filter_id),
        );

        // Free string memory
        let _ = U16CString::from_raw(name_raw);
        let _ = U16CString::from_raw(description_raw);

        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(filter_id);
        }

        return Err(Error::NTStatus(status));
    }
}

pub fn unregister_filter(filter_engine_handle: HANDLE, filter_id: u64) -> Result<(), Error> {
    unsafe {
        let status = FwpmFilterDeleteById0(filter_engine_handle, filter_id);
        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(());
        }

        return Err(Error::NTStatus(status));
    }
}

pub fn wdf_device_wdm_get_device_object(wdf_device: HANDLE) -> *mut DEVICE_OBJECT {
    unsafe {
        return pm_GetDeviceObject(wdf_device);
    }
}

pub fn filter_engine_close(filter_engine_handle: HANDLE) -> Result<(), Error> {
    unsafe {
        let status = FwpmEngineClose0(filter_engine_handle);
        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(());
        }
        return Err(Error::NTStatus(status));
    }
}

pub fn filter_engine_transaction_begin(
    filter_engine_handle: HANDLE,
    flags: u32,
) -> Result<(), Error> {
    unsafe {
        let status = FwpmTransactionBegin0(filter_engine_handle, flags);
        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(());
        }
        return Err(Error::NTStatus(status));
    }
}

pub fn filter_engine_transaction_commit(filter_engine_handle: HANDLE) -> Result<(), Error> {
    unsafe {
        let status = FwpmTransactionCommit0(filter_engine_handle);
        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(());
        }
        return Err(Error::NTStatus(status));
    }
}

pub fn filter_engine_transaction_abort(filter_engine_handle: HANDLE) -> Result<(), Error> {
    unsafe {
        let status = FwpmTransactionAbort0(filter_engine_handle);
        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };
        if let NtStatus::STATUS_SUCCESS = status {
            return Ok(());
        }
        return Err(Error::NTStatus(status));
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

        return Err(Error::NTStatus(status));
    }
}
