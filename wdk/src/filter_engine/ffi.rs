use crate::alloc::borrow::ToOwned;
use alloc::string::String;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;
use ntstatus::ntstatus::NtStatus;
use widestring::U16CString;

use windows_sys::Wdk::Foundation::DEVICE_OBJECT;
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmCalloutAdd0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0, FWPM_CALLOUT0, FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_PROVIDER_CONTEXT2,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_CONDITION_VALUE0, FWP_MATCH_TYPE,
    FWP_UINT8, FWP_VALUE0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::{
    core::GUID,
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE},
};

use super::classify::ClassifyOut;
use super::layer::{FwpsIncomingValues, Layer};
use super::metadata::FwpsIncomingMetadataValues;

pub(crate) type FwpsCalloutClassifyFn = unsafe extern "C" fn(
    inFixedValues: *const FwpsIncomingValues,
    inMetaValues: *const FwpsIncomingMetadataValues,
    layerData: *mut c_void,
    classifyContext: *const c_void,
    filter: *const FWPS_FILTER2,
    flowContext: u64,
    classifyOut: *mut ClassifyOut,
);

type FwpsCalloutNotifyFn = unsafe extern "C" fn(
    notifyType: u32,
    filterKey: *const GUID,
    filter: *mut FWPS_FILTER2,
) -> NTSTATUS;

type FwpsCalloutFlowDeleteNotifyFn =
    unsafe extern "C" fn(layerId: u16, calloutId: u32, flowContext: u64);

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

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
struct FWPS_CALLOUT3 {
    calloutKey: GUID,
    flags: u32,
    classifyFn: Option<FwpsCalloutClassifyFn>,
    notifyFn: Option<FwpsCalloutNotifyFn>,
    flowDeleteFn: Option<FwpsCalloutFlowDeleteNotifyFn>,
}

#[derive(Debug, onlyerror::Error)]
pub enum Error {
    #[error("invalid string argument: {0}")]
    InvalidString(String),
    #[error("ntstatus: {0}")]
    NTStatus(NtStatus),
    #[error("unknown result")]
    UnknownResult,
}

#[link(name = "Fwpkclnt", kind = "static")]
#[link(name = "Fwpuclnt", kind = "static")]
extern "C" {
    fn FwpsCalloutUnregisterById0(id: u32) -> NTSTATUS;
    fn FwpsCalloutRegister1(
        deviceObject: *mut c_void,
        callout: *const FWPS_CALLOUT3,
        calloutId: *mut u32,
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
        let Some(status) = NtStatus::from_u32(status) else {
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
        let Some(status) = NtStatus::from_u32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(());
        }

        return Err(Error::NTStatus(status));
    }
}

unsafe extern "C" fn generic_notify(
    _notify_type: u32,
    _filter_key: *const GUID,
    _filter: *mut FWPS_FILTER2,
) -> NTSTATUS {
    return STATUS_SUCCESS;
}

unsafe extern "C" fn generic_delete_notify(_layer_id: u16, _callout_id: u32, _flow_context: u64) {}

pub(crate) fn register_callout(
    device_object: *mut DEVICE_OBJECT,
    filter_engine_handle: HANDLE,
    name: &str,
    description: &str,
    guid: u128,
    layer: Layer,
    callout_fn: FwpsCalloutClassifyFn,
) -> Result<u32, Error> {
    let s_callout = FWPS_CALLOUT3 {
        calloutKey: GUID::from_u128(guid),
        flags: 0,
        classifyFn: Some(callout_fn),
        notifyFn: Some(generic_notify),
        flowDeleteFn: Some(generic_delete_notify),
    };

    unsafe {
        let mut callout_id: u32 = 0;
        let status = FwpsCalloutRegister1(device_object as _, &s_callout, &mut callout_id);

        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };

        if status != NtStatus::STATUS_SUCCESS {
            return Err(Error::NTStatus(status));
        }

        if let Err(err) = callout_add(filter_engine_handle, guid, layer, name, description) {
            return Err(err);
        }

        return Ok(callout_id);
    }
}

fn callout_add(
    filter_engine_handle: HANDLE,
    guid: u128,
    layer: Layer,
    name: &str,
    description: &str,
) -> Result<(), Error> {
    let Ok(name) = U16CString::from_str(name) else {
        return Err(Error::InvalidString("name".to_owned()));
    };
    let Ok(description) = U16CString::from_str(description) else {
        return Err(Error::InvalidString("description".to_owned()));
    };
    let display_data = FWPM_DISPLAY_DATA0 {
        name: name.as_ptr() as _,
        description: description.as_ptr() as _,
    };

    unsafe {
        let mut callout: FWPM_CALLOUT0 = MaybeUninit::zeroed().assume_init();
        callout.calloutKey = GUID::from_u128(guid);
        callout.displayData = display_data;
        callout.applicableLayer = layer.get_guid();
        callout.flags = FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT;
        let status = FwpmCalloutAdd0(
            filter_engine_handle,
            &callout,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        let Some(status) = NtStatus::from_u32(status) else {
            return Err(Error::UnknownResult);
        };
        if status != NtStatus::STATUS_SUCCESS {
            return Err(Error::NTStatus(status));
        }
    };
    return Ok(());
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
    context: u64,
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
        filter.Anonymous.rawContext = context;
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
        let Some(status) = NtStatus::from_u32(status) else {
            return Err(Error::UnknownResult);
        };
        if status == NtStatus::STATUS_SUCCESS {
            return Ok(());
        }

        return Err(Error::NTStatus(status));
    }
}

pub(crate) fn filter_engine_close(filter_engine_handle: HANDLE) -> Result<(), Error> {
    unsafe {
        let status = FwpmEngineClose0(filter_engine_handle);
        let Some(status) = NtStatus::from_u32(status) else {
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
        let Some(status) = NtStatus::from_u32(status) else {
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
        let Some(status) = NtStatus::from_u32(status) else {
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
        let Some(status) = NtStatus::from_u32(status) else {
            return Err(Error::UnknownResult);
        };
        if let NtStatus::STATUS_SUCCESS = status {
            return Ok(());
        }
        return Err(Error::NTStatus(status));
    }
}
