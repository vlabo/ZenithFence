//! Host-only user-space client for the mocked driver.
//!
//! `DriverConnection` mirrors the Win32 device-handle API a real user-space
//! agent uses (`ReadFile` / `WriteFile` / `DeviceIoControl`): each call
//! synthesizes a mock `IRP` and invokes the dispatch handler the driver
//! registered in its `DRIVER_OBJECT`, exactly like the kernel I/O manager. This
//! is what lets the full-driver simulation talk to the driver "like a real
//! driver" instead of poking `Device` methods directly.
//!
//! Each connection owns its own `DEVICE_OBJECT`, and the dispatch methods take
//! `&mut self`, so the `&mut DEVICE_OBJECT`/`&mut IRP` a handler receives are
//! never shared across threads — every thread (producer, consumer) opens its own
//! connection from the same `DRIVER_OBJECT`.

use crate::kernel_types::{
    MjFnType, DEVICE_OBJECT, DRIVER_OBJECT, IRP, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE,
    NTSTATUS,
};

// Returned when a request type has no registered dispatch handler (e.g. an IOCTL
// on a driver that never set a device-control function).
const STATUS_NO_HANDLER: NTSTATUS = 0xC000_0002u32 as i32; // STATUS_NOT_IMPLEMENTED

pub struct DriverConnection {
    device_object: DEVICE_OBJECT,
    read_fn: MjFnType,
    write_fn: MjFnType,
    control_fn: Option<MjFnType>,
}

// Each connection is single-owner; methods take `&mut self`. Moving one into a
// worker thread is fine, sharing it is not (and the type system enforces that).
unsafe impl Send for DriverConnection {}

impl DriverConnection {
    /// Open a client against a driver that `driver_entry` has populated. Returns
    /// `None` if the read/write dispatch handlers are absent (driver not loaded).
    pub fn open(driver_object: &DRIVER_OBJECT) -> Option<Self> {
        let read_fn = driver_object.MajorFunction[IRP_MJ_READ]?;
        let write_fn = driver_object.MajorFunction[IRP_MJ_WRITE]?;
        let control_fn = driver_object.MajorFunction[IRP_MJ_DEVICE_CONTROL];
        Some(Self {
            device_object: DEVICE_OBJECT::new(),
            read_fn,
            write_fn,
            control_fn,
        })
    }

    /// `WriteFile` equivalent: hand `bytes` to the driver's write dispatch
    /// (the command channel). Returns the completion status.
    pub fn write(&mut self, bytes: &[u8]) -> NTSTATUS {
        // The write path only reads the input buffer; the const-cast to `*mut`
        // is sound because the handler never writes through it.
        let mut irp = IRP::for_write(bytes.as_ptr() as *mut u8, bytes.len());
        unsafe { (self.write_fn)(&mut self.device_object, &mut irp) }
    }

    /// `ReadFile` equivalent: drain pending events into `out`. Returns
    /// `(bytes_written, status)`. If the driver was loaded with blocking reads
    /// and the event queue is empty, this blocks until an event arrives or the
    /// queue is run down (shutdown), which returns end-of-file.
    pub fn read(&mut self, out: &mut [u8]) -> (usize, NTSTATUS) {
        let mut irp = IRP::for_read(out.as_mut_ptr(), out.len());
        let status = unsafe { (self.read_fn)(&mut self.device_object, &mut irp) };
        (irp.information, status)
    }

    /// `DeviceIoControl` equivalent (buffered method: input and output share one
    /// system buffer). Returns `(bytes_written_to_out, status)`.
    pub fn device_io_control(
        &mut self,
        control_code: u32,
        input: &[u8],
        out: &mut [u8],
    ) -> (usize, NTSTATUS) {
        let Some(control_fn) = self.control_fn else {
            return (0, STATUS_NO_HANDLER);
        };
        // Buffered IOCTL shares one buffer for in and out. Seed it with the input
        // (the handler reads `input_len` from the front) and let the handler
        // overwrite with output.
        let copy = input.len().min(out.len());
        out[..copy].copy_from_slice(&input[..copy]);
        let mut irp = IRP::for_ioctl(out.as_mut_ptr(), input.len(), out.len(), control_code);
        let status = unsafe { control_fn(&mut self.device_object, &mut irp) };
        (irp.information, status)
    }
}
