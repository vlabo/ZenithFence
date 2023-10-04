use crate::alloc::borrow::ToOwned;
use alloc::string::String;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;
use ntstatus::ntstatus::NtStatus;
use widestring::U16CString;
use windows_sys::core::PCWSTR;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFilterAdd0, FwpmSubLayerAdd0, FWPM_FILTER0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
    FWPM_PROVIDER_CONTEXT2, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
    FWP_CONDITION_VALUE0, FWP_MATCH_TYPE, FWP_UINT8, FWP_VALUE0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::{
    core::GUID,
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE},
};

use super::classify::ClassifyOut;
use super::layer::{FwpsIncomingValues, Layer};
use super::metadata::FwpsIncomingMetadataValues;

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub(crate) struct FWPS_ACTION0 {
    r#type: u32,
    calloutId: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub(crate) struct FWPS_FILTER_CONDITION0 {
    fieldId: u16,
    reserved: u16,
    matchType: FWP_MATCH_TYPE,
    conditionValue: FWP_CONDITION_VALUE0,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub(crate) struct FWPS_FILTER2 {
    pub(crate) filterId: u64,
    pub(crate) weight: FWP_VALUE0,
    pub(crate) subLayerWeight: u16,
    pub(crate) flags: u16,
    pub(crate) numFilterConditions: u32,
    pub(crate) filterCondition: *mut FWPS_FILTER_CONDITION0,
    pub(crate) action: FWPS_ACTION0,
    pub(crate) context: u64,
    pub(crate) providerContext: *mut FWPM_PROVIDER_CONTEXT2,
}

pub(crate) type CalloutFunctionType = unsafe extern "C" fn(
    inFixedValues: *const FwpsIncomingValues,
    inMetaValues: *const FwpsIncomingMetadataValues,
    layerData: *mut c_void,
    classifyContext: *const c_void,
    filter: *const FWPS_FILTER2,
    flowContext: u64,
    classifyOut: *mut ClassifyOut,
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
    // fn pm_CreateFilterEngine(handle: *mut HANDLE) -> NTSTATUS;
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
    fn FwpmEngineOpen0(
        serverName: PCWSTR,
        authnService: u32,
        authIdentity: *mut c_void,
        session: *const FWPM_SESSION0,
        engineHandle: *mut HANDLE,
    ) -> NTSTATUS;
}

pub(crate) fn create_filter_engine() -> Result<HANDLE, Error> {
    unsafe {
        let mut handle: HANDLE = INVALID_HANDLE_VALUE;
        let mut wdf_session: FWPM_SESSION0 = MaybeUninit::zeroed().assume_init();
        wdf_session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let status = FwpmEngineOpen0(
            core::ptr::null(),
            RPC_C_AUTHN_WINNT,
            core::ptr::null_mut(),
            &wdf_session,
            &mut handle,
        );
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
    let Ok(name) = U16CString::from_str(name) else {
        return Err(Error::InvalidString("name".to_owned()));
    };
    let Ok(description) = U16CString::from_str(description) else {
        return Err(Error::InvalidString("description".to_owned()));
    };

    unsafe {
        let mut sublayer: FWPM_SUBLAYER0 = MaybeUninit::zeroed().assume_init();
        sublayer.subLayerKey = GUID::from_u128(guid);
        sublayer.displayData.name = name.as_ptr() as _;
        sublayer.displayData.description = description.as_ptr() as _;
        sublayer.flags = 0;
        sublayer.weight = 0xFFFF;

        let status = FwpmSubLayerAdd0(filter_engine_handle, &sublayer, core::ptr::null_mut());
        let Some(status) = NtStatus::from_u32(status) else {
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
    let Ok(name) = U16CString::from_str(name) else {
        return Err(Error::InvalidString("name".to_owned()));
    };
    let Ok(description) = U16CString::from_str(description) else {
        return Err(Error::InvalidString("description".to_owned()));
    };
    let mut filter_id: u64 = 0;
    unsafe {
        let mut filter: FWPM_FILTER0 = MaybeUninit::zeroed().assume_init();
        filter.displayData.name = name.as_ptr() as _;
        filter.displayData.description = description.as_ptr() as _;
        filter.action.r#type = action; // Says this filter's callout MUST make a block/permit decision. Also see doc excerpts below.
        filter.subLayerKey = GUID::from_u128(sublayer_guid);
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = 15; // The weight of this filter within its sublayer
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        filter.numFilterConditions = 0; // If you specify 0, this filter invokes its callout for all traffic in its layer
        filter.layerKey = layer.get_guid(); // This layer must match the layer that ExampleCallout is registered to
        filter.action.Anonymous.calloutKey = GUID::from_u128(callout_guid);
        let status = FwpmFilterAdd0(
            filter_engine_handle,
            &filter,
            core::ptr::null_mut(),
            &mut filter_id,
        );

        let Some(status) = NtStatus::from_u32(status) else {
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
