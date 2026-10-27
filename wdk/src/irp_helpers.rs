use windows_sys::{
    Wdk::{
        Foundation::{IO_STACK_LOCATION_0_4, IRP},
        Storage::FileSystem::IO_NO_INCREMENT,
        System::SystemServices::IofCompleteRequest,
    },
    Win32::Foundation::{
        NTSTATUS, STATUS_END_OF_FILE, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS, STATUS_TIMEOUT,
    },
};

/// Completes `irp` successfully without transferring data, for requests that need no work from the
/// driver (opening, cleaning up and closing a handle). Returns the status for the dispatch routine.
pub fn complete_empty(irp: &mut IRP) -> NTSTATUS {
    irp.IoStatus.Information = 0;
    irp.IoStatus.Anonymous.Status = STATUS_SUCCESS;
    unsafe { IofCompleteRequest(irp, IO_NO_INCREMENT as i8) };
    return STATUS_SUCCESS;
}

/// The buffered-I/O system buffer of a request, `length` bytes long. A zero-length request has no
/// system buffer, and a slice must not be built from a null pointer, even an empty one.
unsafe fn system_buffer<'a>(irp: &IRP, length: usize) -> &'a mut [u8] {
    let system_buffer = irp.AssociatedIrp.SystemBuffer as *mut u8;
    if system_buffer.is_null() || length == 0 {
        return &mut [];
    }
    core::slice::from_raw_parts_mut(system_buffer, length)
}

pub struct ReadRequest<'a> {
    irp: &'a mut IRP,
    buffer: &'a mut [u8],
    fill_index: usize,
}

impl ReadRequest<'_> {
    pub fn new(irp: &'_ mut IRP) -> ReadRequest<'_> {
        unsafe {
            let irp_sp = irp.Tail.Overlay.Anonymous2.Anonymous.CurrentStackLocation;
            let device_io = (*irp_sp).Parameters.Read;

            let buffer = system_buffer(irp, device_io.Length as usize);
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

        bytes_to_write
    }
}

pub struct WriteRequest<'a> {
    irp: &'a mut IRP,
    buffer: &'a mut [u8],
}

impl WriteRequest<'_> {
    pub fn new(irp: &'_ mut IRP) -> WriteRequest<'_> {
        unsafe {
            let irp_sp = irp.Tail.Overlay.Anonymous2.Anonymous.CurrentStackLocation;
            let device_io = (*irp_sp).Parameters.Write;

            let buffer = system_buffer(irp, device_io.Length as usize);
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

pub struct DeviceControlRequest<'a> {
    irp: &'a mut IRP,
    buffer: &'a mut [u8],
    fill_index: usize,
    control_code: u32,
}

// Windows-rs version of the struct is incorrect (18.01.2024).
// TODO: Use the official version when fixed.
// For future reference: https://github.com/microsoft/windows-rs/issues/2805
#[repr(C)]
struct DeviceIOControlParams {
    output_buffer_length: u32,
    _padding1: u32,
    input_buffer_length: u32,
    _padding2: u32,
    io_control_code: u32,
    _padding3: u32,
}

impl DeviceControlRequest<'_> {
    pub fn new(irp: &'_ mut IRP) -> DeviceControlRequest<'_> {
        unsafe {
            let irp_sp = irp.Tail.Overlay.Anonymous2.Anonymous.CurrentStackLocation;
            // Use the struct directly when replaced with proper version.
            let device_io: DeviceIOControlParams =
                core::mem::transmute::<IO_STACK_LOCATION_0_4, DeviceIOControlParams>(
                    (*irp_sp).Parameters.DeviceIoControl,
                );

            let buffer = system_buffer(irp, device_io.output_buffer_length as usize);
            DeviceControlRequest {
                irp,
                buffer,
                fill_index: 0,
                control_code: device_io.io_control_code,
            }
        }
    }

    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer
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

        bytes_to_write
    }

    /// Completes the request, returning the bytes written with `write`. Returns the status for the
    /// dispatch routine: the IRP belongs to the I/O manager once it is completed and must not be read.
    pub fn complete(self) -> NTSTATUS {
        // Only the bytes that were written: the I/O manager copies this many back to user space.
        self.irp.IoStatus.Information = self.fill_index;
        self.irp.IoStatus.Anonymous.Status = STATUS_SUCCESS;
        unsafe { IofCompleteRequest(self.irp, IO_NO_INCREMENT as i8) };
        return STATUS_SUCCESS;
    }

    /// Completes the request as not implemented. Returns the status for the dispatch routine.
    pub fn not_implemented(self) -> NTSTATUS {
        self.irp.IoStatus.Information = 0;
        self.irp.IoStatus.Anonymous.Status = STATUS_NOT_IMPLEMENTED;
        unsafe { IofCompleteRequest(self.irp, IO_NO_INCREMENT as i8) };
        return STATUS_NOT_IMPLEMENTED;
    }

    pub fn get_control_code(&self) -> u32 {
        self.control_code
    }

    pub fn free_space(&self) -> usize {
        self.buffer.len() - self.fill_index
    }
}
