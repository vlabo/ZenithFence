// Host mocks of the IRP request wrappers.
//
// They come in two flavours that share one struct:
//   * buffer-backed (`from_buffer` / `from_bytes` / `from_parts`) — a fuzz/test
//     harness feeds raw byte buffers straight into `Device::read` / `write` /
//     device control, with no IRP.
//   * IRP-backed (`new`) — mirrors the real wrappers: the buffer is taken from
//     the mock `IRP`'s system buffer, and the `set_*` outcomes and `complete`
//     write the transferred byte count and status back into the IRP so a
//     `DriverConnection` can read them, exactly as the kernel completes a request.
//
// As in the real wrappers, `complete` consumes the request and returns the
// status for the dispatch routine.

// Status values (i32) come from `kernel_types`, the single source of truth, so
// the channel client and the driver agree on, e.g., the end-of-file code used to
// stop a reader.
use crate::kernel_types::{
    IRP, NTSTATUS, STATUS_END_OF_FILE, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS, STATUS_TIMEOUT,
};

/// Completes `irp` successfully without transferring data, for requests that
/// need no work from the driver (opening, cleaning up and closing a handle).
/// Returns the status for the dispatch routine.
pub fn complete_empty(irp: &mut IRP) -> NTSTATUS {
    irp.information = 0;
    irp.status = STATUS_SUCCESS;
    STATUS_SUCCESS
}

pub struct ReadRequest<'a> {
    // Present for IRP-backed requests; the transferred count + status are mirrored
    // here on completion so a channel client sees them.
    irp: Option<&'a mut IRP>,
    buffer: &'a mut [u8],
    fill_index: usize,
    status: i32,
}

impl<'a> ReadRequest<'a> {
    /// Build a read request over a caller-owned output buffer (no IRP).
    pub fn from_buffer(buffer: &'a mut [u8]) -> ReadRequest<'a> {
        ReadRequest {
            irp: None,
            buffer,
            fill_index: 0,
            status: STATUS_SUCCESS,
        }
    }

    /// Build a read request from a mock IRP (the dispatch path). The output
    /// buffer is the IRP's system buffer, sized to `output_len`.
    pub fn new(irp: &'a mut IRP) -> ReadRequest<'a> {
        let buffer = unsafe { system_buffer(irp, irp.output_len) };
        let mut request = ReadRequest {
            irp: Some(irp),
            buffer,
            fill_index: 0,
            status: STATUS_SUCCESS,
        };
        // Succeeds with whatever was written, unless an outcome is set.
        request.set_success();
        request
    }

    pub fn free_space(&self) -> usize {
        self.buffer.len() - self.fill_index
    }

    /// The read succeeds, returning the bytes written with `write`.
    pub fn set_success(&mut self) {
        self.set_status(STATUS_SUCCESS, self.fill_index);
    }

    /// The read ends with end of file, returning the bytes written with `write`.
    pub fn set_end_of_file(&mut self) {
        self.set_status(STATUS_END_OF_FILE, self.fill_index);
    }

    /// The read times out.
    pub fn set_timeout(&mut self) {
        self.set_status(STATUS_TIMEOUT, 0);
    }

    /// Completes the request with the outcome that was set. Returns the status
    /// for the dispatch routine.
    pub fn complete(self) -> NTSTATUS {
        self.status
    }

    fn set_status(&mut self, status: NTSTATUS, information: usize) {
        self.status = status;
        if let Some(irp) = self.irp.as_mut() {
            irp.information = information;
            irp.status = status;
        }
    }

    pub fn write(&mut self, bytes: &[u8]) -> usize {
        let mut bytes_to_write: usize = bytes.len();
        if bytes_to_write > self.free_space() {
            bytes_to_write = self.free_space();
        }
        for i in 0..bytes_to_write {
            self.buffer[self.fill_index + i] = bytes[i];
        }
        self.fill_index += bytes_to_write;
        bytes_to_write
    }

    /// Lets `f` write straight into the free part of the buffer. `f` returns how many bytes it
    /// wrote, and those are kept. Returns the same count.
    pub fn write_with(&mut self, f: impl FnOnce(&mut [u8]) -> usize) -> usize {
        let free_space = self.free_space();
        let written = f(&mut self.buffer[self.fill_index..]).min(free_space);
        self.fill_index += written;
        written
    }

    /// Test helper: the bytes written so far.
    pub fn written(&self) -> &[u8] {
        &self.buffer[..self.fill_index]
    }
}

pub struct WriteRequest<'a> {
    irp: Option<&'a mut IRP>,
    buffer: &'a [u8],
    status: i32,
}

impl<'a> WriteRequest<'a> {
    /// Build a write request over a caller-supplied input buffer (no IRP). This
    /// is the entry point a fuzz target uses to feed arbitrary bytes into
    /// `Device::write`.
    pub fn from_bytes(buffer: &'a [u8]) -> WriteRequest<'a> {
        WriteRequest {
            irp: None,
            buffer,
            status: STATUS_SUCCESS,
        }
    }

    /// Build a write request from a mock IRP (the dispatch path). The input
    /// buffer is the IRP's system buffer, sized to `input_len`.
    pub fn new(irp: &'a mut IRP) -> WriteRequest<'a> {
        let buffer: &[u8] = unsafe { system_buffer(irp, irp.input_len) };
        irp.information = 0;
        WriteRequest {
            irp: Some(irp),
            buffer,
            status: STATUS_SUCCESS,
        }
    }

    pub fn get_buffer(&self) -> &[u8] {
        self.buffer
    }

    pub fn mark_all_as_read(&mut self) {
        if let Some(irp) = self.irp.as_mut() {
            irp.information = self.buffer.len();
        }
    }

    /// Completes the request successfully. Returns the status for the dispatch
    /// routine.
    pub fn complete(mut self) -> NTSTATUS {
        self.status = STATUS_SUCCESS;
        if let Some(irp) = self.irp.as_mut() {
            irp.status = STATUS_SUCCESS;
        }
        STATUS_SUCCESS
    }
}

pub struct DeviceControlRequest<'a> {
    irp: Option<&'a mut IRP>,
    buffer: &'a mut [u8],
    fill_index: usize,
    control_code: u32,
    status: i32,
}

impl<'a> DeviceControlRequest<'a> {
    pub fn from_parts(buffer: &'a mut [u8], control_code: u32) -> DeviceControlRequest<'a> {
        DeviceControlRequest {
            irp: None,
            buffer,
            fill_index: 0,
            control_code,
            status: STATUS_SUCCESS,
        }
    }

    /// Build a device-control request from a mock IRP (the dispatch path). The
    /// output buffer is the IRP's system buffer, sized to `output_len`.
    pub fn new(irp: &'a mut IRP) -> DeviceControlRequest<'a> {
        let control_code = irp.control_code;
        let buffer = unsafe { system_buffer(irp, irp.output_len) };
        DeviceControlRequest {
            irp: Some(irp),
            buffer,
            fill_index: 0,
            control_code,
            status: STATUS_SUCCESS,
        }
    }

    pub fn get_buffer(&self) -> &[u8] {
        self.buffer
    }

    pub fn write(&mut self, bytes: &[u8]) -> usize {
        let mut bytes_to_write: usize = bytes.len();
        if bytes_to_write > self.free_space() {
            bytes_to_write = self.free_space();
        }
        for i in 0..bytes_to_write {
            self.buffer[self.fill_index + i] = bytes[i];
        }
        self.fill_index += bytes_to_write;
        bytes_to_write
    }

    /// Completes the request, returning the bytes written with `write`. Returns
    /// the status for the dispatch routine.
    pub fn complete(mut self) -> NTSTATUS {
        self.status = STATUS_SUCCESS;
        if let Some(irp) = self.irp.as_mut() {
            irp.information = self.fill_index;
            irp.status = STATUS_SUCCESS;
        }
        STATUS_SUCCESS
    }

    /// Completes the request as not implemented. Returns the status for the
    /// dispatch routine.
    pub fn not_implemented(mut self) -> NTSTATUS {
        self.status = STATUS_NOT_IMPLEMENTED;
        if let Some(irp) = self.irp.as_mut() {
            irp.information = 0;
            irp.status = STATUS_NOT_IMPLEMENTED;
        }
        STATUS_NOT_IMPLEMENTED
    }

    pub fn get_control_code(&self) -> u32 {
        self.control_code
    }

    pub fn free_space(&self) -> usize {
        self.buffer.len() - self.fill_index
    }
}

/// The system buffer of a request, `length` bytes long. A zero-length request
/// may have no buffer, and a slice must not be built from a null pointer, even an
/// empty one.
unsafe fn system_buffer<'a>(irp: &IRP, length: usize) -> &'a mut [u8] {
    if irp.system_buffer.is_null() || length == 0 {
        return &mut [];
    }
    core::slice::from_raw_parts_mut(irp.system_buffer, length)
}
