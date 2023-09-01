use crate::interface;
use winapi::km::wdm::IoGetCurrentIrpStackLocation;
use winapi::km::wdm::{DEVICE_OBJECT, IRP};
use winapi::shared::ntstatus::STATUS_SUCCESS;
use windows_sys::Win32::Foundation::HANDLE;

pub struct Driver {
    // driver_handle: HANDLE,
    // device_handle: HANDLE,
    wfp_handle: *mut DEVICE_OBJECT,
}

impl Driver {
    pub(crate) fn new(_driver_handle: HANDLE, device_handle: HANDLE) -> Driver {
        return Driver {
            // driver_handle,
            // device_handle,
            wfp_handle: interface::wdf_device_wdm_get_device_object(device_handle),
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
            let irp_sp = IoGetCurrentIrpStackLocation(irp);
            let device_io = (*irp_sp).Parameters.DeviceIoControl_mut();

            let system_buffer = irp.AssociatedIrp.SystemBuffer();
            let buffer = core::slice::from_raw_parts_mut(
                *system_buffer as *mut u8,
                device_io.OutputBufferLength as usize,
            );
            ReadRequest {
                irp,
                buffer,
                fill_index: 0,
            }
        }
    }

    pub fn write<T: bytemuck::NoUninit>(&mut self, value: T) -> Result<(), ()> {
        let bytes = bytemuck::bytes_of(&value);

        if self.fill_index + bytes.len() >= self.buffer.len() {
            return Err(());
        }

        for i in 0..bytes.len() {
            self.buffer[self.fill_index + i] = bytes[i];
        }
        self.fill_index = self.fill_index + bytes.len();
        return Ok(());
    }

    pub fn free_space(&self) -> usize {
        self.buffer.len() - self.fill_index
    }

    pub fn complete(&mut self) {
        unsafe {
            self.irp.IoStatus.Information = self.fill_index;
            let status = self.irp.IoStatus.__bindgen_anon_1.Status_mut();
            *status = STATUS_SUCCESS;
        }
    }
}
