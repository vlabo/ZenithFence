use crate::filter_engine::classify::ClassifyOut;
use crate::filter_engine::ffi;
use crate::filter_engine::layer::{Layer, Value};
use crate::filter_engine::metadata::FwpsIncomingMetadataValues;
use windows_sys::Wdk::Foundation::{DEVICE_OBJECT, DRIVER_OBJECT, IRP};
use windows_sys::Win32::Foundation::{
    HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, STATUS_END_OF_FILE, STATUS_SUCCESS, STATUS_TIMEOUT,
};

pub struct Driver {
    // driver_handle: HANDLE,
    _device_handle: HANDLE,
    driver_object: *mut DRIVER_OBJECT,
    wfp_handle: *mut DEVICE_OBJECT,
}

unsafe impl Sync for Driver {}

pub type UnloadFnType = unsafe extern "system" fn(driverobject: *const DRIVER_OBJECT);
pub type MjFnType = unsafe extern "system" fn(&mut DEVICE_OBJECT, &mut IRP) -> NTSTATUS;

impl Driver {
    pub(crate) const fn default() -> Self {
        Self {
            _device_handle: INVALID_HANDLE_VALUE,
            driver_object: core::ptr::null_mut(),
            wfp_handle: core::ptr::null_mut(),
        }
    }
    pub(crate) fn new(
        driver_object: *mut DRIVER_OBJECT,
        _driver_handle: HANDLE,
        device_handle: HANDLE,
    ) -> Driver {
        return Driver {
            // driver_handle,
            _device_handle: device_handle,
            driver_object,
            wfp_handle: ffi::wdf_device_wdm_get_device_object(device_handle),
        };
    }

    // pub fn get_device_context<'a, T: 'static>(
    //     &self,
    //     context_info: &'static WdfObjectContextTypeInfo,
    // ) -> &'a mut T {
    //     interface::get_device_context_from_wdf_device(self.device_handle, context_info)
    // }

    pub fn get_wfp_object(&self) -> *mut DEVICE_OBJECT {
        return self.wfp_handle;
    }

    pub fn set_driver_unload(&mut self, driver_unload: UnloadFnType) {
        if let Some(driver) = unsafe { self.driver_object.as_mut() } {
            driver.DriverUnload = Some(unsafe { core::mem::transmute(driver_unload) })
        }
    }

    pub fn set_read_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(windows_sys::Wdk::System::SystemServices::IRP_MJ_READ, mj_fn);
    }

    pub fn set_write_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(
            windows_sys::Wdk::System::SystemServices::IRP_MJ_WRITE,
            mj_fn,
        );
    }

    pub fn set_create_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(
            windows_sys::Wdk::System::SystemServices::IRP_MJ_CREATE,
            mj_fn,
        );
    }

    pub fn set_device_control_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(
            windows_sys::Wdk::System::SystemServices::IRP_MJ_DEVICE_CONTROL,
            mj_fn,
        );
    }

    pub fn set_close_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(
            windows_sys::Wdk::System::SystemServices::IRP_MJ_CLOSE,
            mj_fn,
        );
    }

    pub fn set_cleanup_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(
            windows_sys::Wdk::System::SystemServices::IRP_MJ_CLEANUP,
            mj_fn,
        );
    }

    fn set_major_fn(&mut self, fn_index: u32, mj_fn: MjFnType) {
        if let Some(driver) = unsafe { self.driver_object.as_mut() } {
            driver.MajorFunction[fn_index as usize] = Some(unsafe { core::mem::transmute(mj_fn) })
        }
    }
}

pub struct ReadRequest<'a> {
    irp: &'a mut IRP,
    buffer: &'a mut [u8],
    fill_index: usize,
}

impl ReadRequest<'_> {
    pub fn new(irp: &mut IRP) -> ReadRequest {
        unsafe {
            let irp_sp = irp.Tail.Overlay.Anonymous2.Anonymous.CurrentStackLocation;
            let device_io = (*irp_sp).Parameters.DeviceIoControl;

            let system_buffer = irp.AssociatedIrp.SystemBuffer;
            let buffer = core::slice::from_raw_parts_mut(
                system_buffer as *mut u8,
                device_io.OutputBufferLength as usize,
            );
            ReadRequest {
                irp,
                buffer,
                fill_index: 0,
            }
        }
    }

    pub fn free_space(&self) -> usize {
        self.buffer.len() - self.fill_index
    }

    pub fn complete(&mut self) {
        self.irp.IoStatus.Information = self.fill_index;
        self.irp.IoStatus.Anonymous.Status = STATUS_SUCCESS;
    }

    pub fn end_of_file(&mut self) {
        self.irp.IoStatus.Information = self.fill_index;
        self.irp.IoStatus.Anonymous.Status = STATUS_END_OF_FILE;
    }

    pub fn timeout(&mut self) {
        self.irp.IoStatus.Anonymous.Status = STATUS_TIMEOUT;
    }

    pub fn get_status(&self) -> NTSTATUS {
        unsafe { self.irp.IoStatus.Anonymous.Status }
    }

    pub fn write(&mut self, bytes: &[u8]) -> usize {
        let mut bytes_to_write: usize = bytes.len();

        // Check if we have enough space
        if bytes_to_write > self.free_space() {
            bytes_to_write = self.free_space();
        }

        for i in 0..bytes_to_write {
            self.buffer[self.fill_index + i] = bytes[i];
        }
        self.fill_index = self.fill_index + bytes_to_write;

        return bytes_to_write;
    }
}

pub struct WriteRequest<'a> {
    irp: &'a mut IRP,
    buffer: &'a mut [u8],
}

impl WriteRequest<'_> {
    pub fn new(irp: &mut IRP) -> WriteRequest {
        unsafe {
            let irp_sp = irp.Tail.Overlay.Anonymous2.Anonymous.CurrentStackLocation;
            let device_io = (*irp_sp).Parameters.DeviceIoControl;

            let system_buffer = irp.AssociatedIrp.SystemBuffer;
            let buffer = core::slice::from_raw_parts_mut(
                system_buffer as *mut u8,
                device_io.OutputBufferLength as usize,
            );
            WriteRequest { irp, buffer }
        }
    }

    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn mark_all_as_read(&mut self) {
        self.irp.IoStatus.Information = self.buffer.len();
    }

    pub fn complete(&mut self) {
        self.irp.IoStatus.Anonymous.Status = STATUS_SUCCESS;
    }

    pub fn get_status(&self) -> NTSTATUS {
        unsafe { self.irp.IoStatus.Anonymous.Status }
    }
}

pub struct CallData<'a> {
    pub layer: Layer,
    pub(crate) values: &'a [Value],
    metadata: *const FwpsIncomingMetadataValues,
    classify_out: *mut ClassifyOut,
}

impl<'a> CallData<'a> {
    pub(crate) fn new(
        layer: Layer,
        values: &'a [Value],
        metadata: *const FwpsIncomingMetadataValues,
        classify_out: *mut ClassifyOut,
    ) -> Self {
        Self {
            layer,
            values,
            metadata,
            classify_out,
        }
    }

    pub fn get_value_u8(&'a self, index: usize) -> u8 {
        unsafe {
            return self.values[index].value.uint8;
        };
    }

    pub fn get_value_u16(&'a self, index: usize) -> u16 {
        unsafe {
            return self.values[index].value.uint16;
        };
    }

    pub fn get_value_u32(&'a self, index: usize) -> u32 {
        unsafe {
            return self.values[index].value.uint32;
        };
    }

    pub fn get_process_id(&self) -> Option<u64> {
        unsafe { (*self.metadata).get_process_id() }
    }

    pub fn get_process_path(&self) -> Option<alloc::string::String> {
        unsafe {
            if let Some(path_slice) = (*self.metadata).get_process_path() {
                if let Ok(string) = alloc::string::String::from_utf8(path_slice.to_vec()) {
                    return Some(string);
                }
            }
        }
        return None;
    }

    pub fn permit(&mut self) {
        unsafe {
            (*self.classify_out).action_permit();
        }
    }

    pub fn block(&mut self) {
        unsafe {
            (*self.classify_out).action_block();
            // (*self.classify_out).set_absorb();
            (*self.classify_out).clear_write_flag();
        }
    }
}
