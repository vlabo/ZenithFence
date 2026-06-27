// Host mocks of the IRP request wrappers.
//
// They come in two flavours that share one struct:
//   * buffer-backed (`from_buffer` / `from_bytes` / `from_parts`) — a fuzz/test
//     harness feeds raw byte buffers straight into `Device::read` / `write` /
//     device control, with no IRP.
//   * IRP-backed (`new`) — mirrors the real wrappers: the buffer is taken from
//     the mock `IRP`'s system buffer, and `complete`/`timeout`/etc. write the
//     transferred byte count and status back into the IRP so a `DriverConnection`
//     can read them, exactly as the kernel completes a request.

// Status values (i32) the driver reads back via `get_status`. Single source of
// truth in `kernel_types` so the channel client and the driver agree on, e.g.,
// the end-of-file code used to stop a reader.
use crate::kernel_types::{
    IRP, STATUS_END_OF_FILE, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS, STATUS_TIMEOUT,
};

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
        let buffer = unsafe { core::slice::from_raw_parts_mut(irp.system_buffer, irp.output_len) };
        ReadRequest {
            irp: Some(irp),
            buffer,
            fill_index: 0,
            status: STATUS_SUCCESS,
        }
    }

    pub fn free_space(&self) -> usize {
        self.buffer.len() - self.fill_index
    }

    pub fn complete(&mut self) {
        self.set_status(STATUS_SUCCESS);
    }

    pub fn end_of_file(&mut self) {
        self.set_status(STATUS_END_OF_FILE);
    }

    pub fn timeout(&mut self) {
        self.set_status(STATUS_TIMEOUT);
    }

    fn set_status(&mut self, status: i32) {
        self.status = status;
        if let Some(irp) = self.irp.as_mut() {
            irp.information = self.fill_index;
            irp.status = status;
        }
    }

    pub fn get_status(&self) -> i32 {
        self.status
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
        let buffer = unsafe { core::slice::from_raw_parts(irp.system_buffer, irp.input_len) };
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

    pub fn complete(&mut self) {
        self.status = STATUS_SUCCESS;
        if let Some(irp) = self.irp.as_mut() {
            irp.status = STATUS_SUCCESS;
        }
    }

    pub fn get_status(&self) -> i32 {
        self.status
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
        let buffer = unsafe { core::slice::from_raw_parts_mut(irp.system_buffer, irp.output_len) };
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

    pub fn complete(&mut self) {
        self.status = STATUS_SUCCESS;
        if let Some(irp) = self.irp.as_mut() {
            irp.information = self.fill_index;
            irp.status = STATUS_SUCCESS;
        }
    }

    pub fn not_implemented(&mut self) {
        self.status = STATUS_NOT_IMPLEMENTED;
        if let Some(irp) = self.irp.as_mut() {
            irp.status = STATUS_NOT_IMPLEMENTED;
        }
    }

    pub fn get_status(&self) -> i32 {
        self.status
    }

    pub fn get_control_code(&self) -> u32 {
        self.control_code
    }

    pub fn free_space(&self) -> usize {
        self.buffer.len() - self.fill_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_types::IRP;

    // A read request built from an IRP writes its bytes into the system buffer and
    // reports the transferred count + success back through the IRP.
    #[test]
    fn read_request_round_trips_through_irp() {
        let mut buf = [0u8; 16];
        let mut irp = IRP::for_read(buf.as_mut_ptr(), buf.len());
        {
            let mut rr = ReadRequest::new(&mut irp);
            assert_eq!(rr.write(&[1, 2, 3]), 3);
            rr.complete();
            assert_eq!(rr.get_status(), STATUS_SUCCESS);
        }
        assert_eq!(irp.information, 3);
        assert_eq!(irp.status, STATUS_SUCCESS);
        assert_eq!(&buf[..3], &[1, 2, 3]);
    }

    // A write request built from an IRP exposes the system buffer as input.
    #[test]
    fn write_request_reads_irp_input() {
        let mut buf = [7u8, 8, 9, 10];
        let mut irp = IRP::for_write(buf.as_mut_ptr(), buf.len());
        let mut wr = WriteRequest::new(&mut irp);
        assert_eq!(wr.get_buffer(), &[7, 8, 9, 10]);
        wr.mark_all_as_read();
        wr.complete();
        assert_eq!(irp.information, 4);
        assert_eq!(irp.status, STATUS_SUCCESS);
    }

    // A device-control request reports its control code and writes output back.
    #[test]
    fn device_control_round_trips_through_irp() {
        let mut buf = [0u8; 8];
        let mut irp = IRP::for_ioctl(buf.as_mut_ptr(), 0, buf.len(), 0x1234);
        {
            let mut cr = DeviceControlRequest::new(&mut irp);
            assert_eq!(cr.get_control_code(), 0x1234);
            cr.write(&[0xAA, 0xBB]);
            cr.complete();
        }
        assert_eq!(irp.information, 2);
        assert_eq!(irp.status, STATUS_SUCCESS);
        assert_eq!(&buf[..2], &[0xAA, 0xBB]);
    }
}
