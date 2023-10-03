use crate::alloc::borrow::ToOwned;
use alloc::string::String;
use core::ffi::c_void;
use core::ptr;
use ntstatus::ntstatus::NtStatus;
use widestring::U16CString;
use windows_sys::core::PCWSTR;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::{
    core::GUID,
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE},
};

use super::classify::ClassifyOut;
use super::layer::{FwpsIncomingValues, Layer};
use super::metadata::FwpsIncomingMetadataValues;

pub(crate) type CalloutFunctionType = unsafe extern "C" fn(
    *const FwpsIncomingValues,
    *const FwpsIncomingMetadataValues,
    *mut c_void,
    *const c_void,
    *const c_void,
    u64,
    *mut ClassifyOut,
);

#[derive(Debug, onlyerror::Error)]
pub enum Error {
    #[error("invalid string argument: {0}")]
    InvalidString(String),
    #[error("ntstatus: {0}")]
    NTStatus(NtStatus),
    #[error("unknown result")]
    UnknownResult,
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
    fn pm_RegisterSublayer(
        filter_engine_handle: HANDLE,
        name: PCWSTR,
        description: PCWSTR,
        guid: GUID,
    ) -> NTSTATUS;
    fn pm_CreateFilterEngine(handle: *mut HANDLE) -> NTSTATUS;
    fn pm_RegisterCallout(
        device_object: *mut DEVICE_OBJECT,
        filter_engine_handle: HANDLE,
        name: PCWSTR,
        description: PCWSTR,
        guid: GUID,
        layer_guid: GUID,
        callout_fn: CalloutFunctionType,
        callout_id: *mut u32,
    ) -> NTSTATUS;

    fn pm_RegisterFilter(
        filter_negine_handle: HANDLE,
        sublayer_guid: GUID,
        name: PCWSTR,
        description: PCWSTR,
        callout_guid: GUID,
        layer_guid: GUID,
        action: u32,
        filter_id: *mut u64,
    ) -> NTSTATUS;

    fn pm_GetDeviceObject(wdf_device: HANDLE) -> *mut DEVICE_OBJECT;

    pub(crate) fn pm_GetFilterID(filter: *const c_void) -> u64;
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

pub(crate) fn create_filter_engine() -> Result<HANDLE, Error> {
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

pub(crate) fn register_sublayer(
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

pub(crate) fn unregister_sublayer(filter_engine_handle: HANDLE, guid: u128) -> Result<(), Error> {
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

pub(crate) fn register_callout(
    device_object: *mut DEVICE_OBJECT,
    filter_engine_handle: HANDLE,
    name: &str,
    description: &str,
    guid: u128,
    layer: Layer,
    callout_fn: CalloutFunctionType,
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

pub(crate) fn unregister_callout(callout_id: u32) -> Result<(), Error> {
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

pub(crate) fn register_filter(
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

pub(crate) fn unregister_filter(filter_engine_handle: HANDLE, filter_id: u64) -> Result<(), Error> {
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

pub(crate) fn wdf_device_wdm_get_device_object(wdf_device: HANDLE) -> *mut DEVICE_OBJECT {
    unsafe {
        return pm_GetDeviceObject(wdf_device);
    }
}

pub(crate) fn filter_engine_close(filter_engine_handle: HANDLE) -> Result<(), Error> {
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

pub(crate) fn filter_engine_transaction_begin(
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

pub(crate) fn filter_engine_transaction_commit(filter_engine_handle: HANDLE) -> Result<(), Error> {
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

pub(crate) fn filter_engine_transaction_abort(filter_engine_handle: HANDLE) -> Result<(), Error> {
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
