use core::ffi::c_void;

use crate::alloc::borrow::ToOwned;
use crate::utils::Driver;
use alloc::ffi::CString;
use alloc::format;
use alloc::string::String;
use ntstatus::ntstatus::NtStatus;
use widestring::U16CString;
use windows_sys::{
    core::PCWSTR,
    Wdk::{
        Foundation::{DEVICE_OBJECT, DRIVER_OBJECT},
        System::SystemServices::DbgPrint,
    },
    Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, UNICODE_STRING},
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
    fn pm_InitDriverObject(
        driver_object: *mut DRIVER_OBJECT,
        registry_path: *mut UNICODE_STRING,
        wdf_driver: *mut HANDLE,
        wdf_device: *mut HANDLE,
        win_driver_path: PCWSTR,
        dos_driver_path: PCWSTR,
        object_attributes: *mut WdfObjectAttributes,
    ) -> NTSTATUS;

    fn pm_WdfObjectGetTypedContextWorker(
        wdf_object: HANDLE,
        type_info: *const WdfObjectContextTypeInfo,
    ) -> *mut c_void;

    fn pm_GetDeviceObject(wdf_device: HANDLE) -> *mut DEVICE_OBJECT;
}

// Debug
pub fn dbg_print(str: String) {
    if let Ok(c_str) = CString::new(str) {
        unsafe {
            DbgPrint(c_str.as_ptr() as _);
        }
    }
}

#[allow(dead_code)]
#[repr(C)]
enum WdfExecutionLevel {
    Invalid = 0,
    InheritFromParent,
    Passive,
    Dispatch,
}

#[allow(dead_code)]
#[repr(C)]
enum WdfSynchronizationScope {
    Invalid = 0x00,
    InheritFromParent,
    Device,
    Queue,
    None,
}

#[repr(C)]
pub struct WdfObjectContextTypeInfo {
    size: u32,
    context_name: *const u8,
    context_size: usize,
    unique_type: *const WdfObjectContextTypeInfo,
    _evt_driver_get_unique_context_type: *const c_void, // Internal use
}

unsafe impl Sync for WdfObjectContextTypeInfo {}

impl WdfObjectContextTypeInfo {
    pub const fn default(null_terminated_name: &'static str) -> Self {
        Self {
            size: core::mem::size_of::<WdfObjectContextTypeInfo>() as u32,
            context_name: null_terminated_name.as_ptr(),
            context_size: 0,
            unique_type: core::ptr::null(),
            _evt_driver_get_unique_context_type: core::ptr::null(),
        }
    }
}

#[repr(C)]
struct WdfObjectAttributes {
    size: u32,
    evt_cleanup_callback: Option<extern "C" fn(wdf_object: HANDLE)>,
    evt_destroy_callback: Option<extern "C" fn(wdf_object: HANDLE)>,
    execution_level: WdfExecutionLevel,
    synchronization_scope: WdfSynchronizationScope,
    parent_object: HANDLE,
    context_size_override: usize,
    context_type_info: *const WdfObjectContextTypeInfo,
}

impl WdfObjectAttributes {
    fn new() -> Self {
        Self {
            size: core::mem::size_of::<WdfObjectAttributes>() as u32,
            evt_cleanup_callback: None,
            evt_destroy_callback: None,
            execution_level: WdfExecutionLevel::InheritFromParent,
            synchronization_scope: WdfSynchronizationScope::InheritFromParent,
            parent_object: 0,
            context_size_override: 0,
            context_type_info: core::ptr::null(),
        }
    }

    fn add_context<T>(&mut self, context_info: &'static mut WdfObjectContextTypeInfo) {
        context_info.context_size = core::mem::size_of::<T>();
        context_info.unique_type = context_info;
        self.context_size_override = 0;
        self.context_type_info = context_info.unique_type;
    }
}

pub fn init_driver_object<'a, T>(
    driver_object: *mut DRIVER_OBJECT,
    registry_path: *mut UNICODE_STRING,
    driver_name: &str,
    context_info: &'static mut WdfObjectContextTypeInfo,
) -> Result<Driver, Error> {
    let win_driver_path = format!("\\Device\\{}", driver_name);
    let dos_driver_path = format!("\\??\\{}", driver_name);

    let mut wdf_driver_handle = INVALID_HANDLE_VALUE;
    let mut wdf_device_handle = INVALID_HANDLE_VALUE;

    let Ok(win_driver) = U16CString::from_str(win_driver_path) else {
        return Err(Error::InvalidString("win_driver_path".to_owned()));
    };
    let Ok(dos_driver) = U16CString::from_str(dos_driver_path) else {
        return Err(Error::InvalidString("dos_driver_path".to_owned()));
    };

    let win_driver_path = win_driver.into_raw();
    let dos_driver_path = dos_driver.into_raw();

    let mut object_attributes = WdfObjectAttributes::new();
    object_attributes.add_context::<T>(context_info);

    unsafe {
        let status = pm_InitDriverObject(
            driver_object,
            registry_path,
            &mut wdf_driver_handle,
            &mut wdf_device_handle,
            win_driver_path,
            dos_driver_path,
            &mut object_attributes,
        );

        // Free string memory
        let _ = U16CString::from_raw(win_driver_path);
        let _ = U16CString::from_raw(dos_driver_path);

        let Some(status) = NtStatus::from_i32(status) else {
            return Err(Error::UnknownResult);
        };

        if status == NtStatus::STATUS_SUCCESS {
            return Ok(Driver::new(
                driver_object,
                wdf_driver_handle,
                wdf_device_handle,
            ));
        }

        Err(Error::NTStatus(status))
    }
}

pub fn get_device_context_from_wdf_device<T>(
    wdf_device: HANDLE,
    type_info: &'static WdfObjectContextTypeInfo,
) -> &mut T {
    unsafe {
        return core::mem::transmute(pm_WdfObjectGetTypedContextWorker(wdf_device, type_info));
    }
}

pub(crate) fn wdf_device_wdm_get_device_object(wdf_device: HANDLE) -> *mut DEVICE_OBJECT {
    unsafe {
        return pm_GetDeviceObject(wdf_device);
    }
}

pub fn get_device_context_from_device_object<'a, T>(
    device_object: &mut DEVICE_OBJECT,
) -> Result<&'a mut T, ()> {
    unsafe {
        if let Some(context) = device_object.DeviceExtension.as_mut() {
            return Ok(core::mem::transmute(context));
        }
    }

    return Err(());
}
