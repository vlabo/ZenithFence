use crate::filter_engine::ffi;
use crate::filter_engine::layer::{Layer, Value};
use crate::filter_engine::metadata::FwpsIncomingMetadataValues;
use windows_sys::Wdk::Foundation::{DEVICE_OBJECT, IRP};
// use winapi::km::wdm::IoGetCurrentIrpStackLocation;
// use winapi::km::wdm::{DEVICE_OBJECT, IRP};
// use winapi::shared::ntstatus::{STATUS_SUCCESS, STATUS_TIMEOUT};
use windows_sys::Win32::Foundation::{HANDLE, STATUS_SUCCESS, STATUS_TIMEOUT};

pub struct Driver {
    // driver_handle: HANDLE,
    // device_handle: HANDLE,
    wfp_handle: *mut DEVICE_OBJECT,
}

unsafe impl Sync for Driver {}

impl Driver {
    pub(crate) const fn default() -> Self {
        Self {
            wfp_handle: core::ptr::null_mut(),
        }
    }
    pub(crate) fn new(_driver_handle: HANDLE, device_handle: HANDLE) -> Driver {
        return Driver {
            // driver_handle,
            // device_handle,
            wfp_handle: ffi::wdf_device_wdm_get_device_object(device_handle),
        };
    }

    pub fn get_wfp_object(&self) -> *mut DEVICE_OBJECT {
        return self.wfp_handle;
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
        // *status = STATUS_SUCCESS;
    }

    pub fn timeout(&mut self) {
        // let status = self.irp.IoStatus.__bindgen_anon_1.Status_mut();
        self.irp.IoStatus.Anonymous.Status = STATUS_TIMEOUT;
    }
}

impl ciborium_io::Write for ReadRequest<'_> {
    type Error = ();

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        if self.fill_index + bytes.len() >= self.buffer.len() {
            return Err(());
        }

        for i in 0..bytes.len() {
            self.buffer[self.fill_index + i] = bytes[i];
        }
        self.fill_index = self.fill_index + bytes.len();

        return Ok(());
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        return Ok(());
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
}

pub struct CallData<'a> {
    pub layer: Layer,
    pub(crate) values: &'a [Value],
    metadata: *const FwpsIncomingMetadataValues,
}

impl<'a> CallData<'a> {
    pub(crate) fn new(
        layer: Layer,
        values: &'a [Value],
        metadata: *const FwpsIncomingMetadataValues,
    ) -> Self {
        Self {
            layer,
            values,
            metadata,
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
}
