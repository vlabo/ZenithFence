// Host mocks of the IRP request wrappers. Instead of an `IRP`, they wrap plain
// byte buffers so a fuzz/property harness can feed arbitrary input into
// `Device::read` / `Device::write` / device control.

// NTSTATUS-like values (i32) the driver may read back via `get_status`.
const STATUS_SUCCESS: i32 = 0;
const STATUS_END_OF_FILE: i32 = 0xC000_0011u32 as i32;
const STATUS_TIMEOUT: i32 = 0x0000_0102;
const STATUS_NOT_IMPLEMENTED: i32 = 0xC000_0002u32 as i32;

pub struct ReadRequest<'a> {
    buffer: &'a mut [u8],
    fill_index: usize,
    status: i32,
}

impl<'a> ReadRequest<'a> {
    /// Build a read request over a caller-owned output buffer.
    pub fn from_buffer(buffer: &'a mut [u8]) -> ReadRequest<'a> {
        ReadRequest {
            buffer,
            fill_index: 0,
            status: STATUS_SUCCESS,
        }
    }

    pub fn free_space(&self) -> usize {
        self.buffer.len() - self.fill_index
    }

    pub fn complete(&mut self) {
        self.status = STATUS_SUCCESS;
    }

    pub fn end_of_file(&mut self) {
        self.status = STATUS_END_OF_FILE;
    }

    pub fn timeout(&mut self) {
        self.status = STATUS_TIMEOUT;
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

    /// Test helper: how many bytes were written so far.
    pub fn written(&self) -> &[u8] {
        &self.buffer[..self.fill_index]
    }
}

pub struct WriteRequest<'a> {
    buffer: &'a [u8],
    status: i32,
}

impl<'a> WriteRequest<'a> {
    /// Build a write request over a caller-supplied input buffer. This is the
    /// entry point a fuzz target uses to feed arbitrary bytes into
    /// `Device::write`.
    pub fn from_bytes(buffer: &'a [u8]) -> WriteRequest<'a> {
        WriteRequest {
            buffer,
            status: STATUS_SUCCESS,
        }
    }

    pub fn get_buffer(&self) -> &[u8] {
        self.buffer
    }

    pub fn mark_all_as_read(&mut self) {}

    pub fn complete(&mut self) {
        self.status = STATUS_SUCCESS;
    }

    pub fn get_status(&self) -> i32 {
        self.status
    }
}

pub struct DeviceControlRequest<'a> {
    buffer: &'a mut [u8],
    fill_index: usize,
    control_code: u32,
    status: i32,
}

impl<'a> DeviceControlRequest<'a> {
    pub fn from_parts(buffer: &'a mut [u8], control_code: u32) -> DeviceControlRequest<'a> {
        DeviceControlRequest {
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
    }

    pub fn not_implemented(&mut self) {
        self.status = STATUS_NOT_IMPLEMENTED;
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
