// These types deliberately keep the `windows_sys` spellings (`DRIVER_OBJECT`,
// `MajorFunction`, ...) so the driver's entry code reads identically in both
// builds.
#![allow(non_camel_case_types, non_snake_case)]

//! Host mocks of the kernel / Win32 types the driver's entry plumbing names.
//!
//! These mirror `wdk::kernel_types` (which on the real build re-exports the
//! `windows_sys` types) closely enough that the driver's `entry.rs` —
//! `DriverEntry` and the IRP dispatch handlers — compiles and runs unchanged
//! against the mock. They are deliberately minimal: only the fields the driver
//! actually touches exist.

/// Mirrors `windows_sys` `NTSTATUS` (an `i32`).
pub type NTSTATUS = i32;

pub const STATUS_SUCCESS: NTSTATUS = 0;
// Real value differs; the simulation only checks `== STATUS_SUCCESS`, so any
// non-zero status means "driver entry failed".
pub const STATUS_FAILED_DRIVER_ENTRY: NTSTATUS = 0xC000_0001u32 as i32;
pub const STATUS_END_OF_FILE: NTSTATUS = 0xC000_0011u32 as i32;
pub const STATUS_TIMEOUT: NTSTATUS = 0x0000_0102;
pub const STATUS_NOT_IMPLEMENTED: NTSTATUS = 0xC000_0002u32 as i32;

/// The registry path handed to `DriverEntry`. The driver never dereferences it
/// (it is passed straight through to `init_driver_object`), so the mock is an
/// opaque zero-sized stand-in.
pub struct UNICODE_STRING;

/// WDM device object. The driver's handlers take `&mut DEVICE_OBJECT` but ignore
/// it (they reach the device through the global slot), so the mock carries no
/// state. Each `DriverConnection` owns its own instance to avoid cross-thread
/// aliasing of a shared `&mut DEVICE_OBJECT`.
#[derive(Default)]
pub struct DEVICE_OBJECT;

impl DEVICE_OBJECT {
    pub fn new() -> Self {
        DEVICE_OBJECT
    }
}

/// IRP major function dispatch handler. Same shape as the real `MjFnType`, but
/// over the mock `DEVICE_OBJECT`/`IRP`/`NTSTATUS`.
pub type MjFnType = unsafe extern "system" fn(&mut DEVICE_OBJECT, &mut IRP) -> NTSTATUS;

/// Driver unload callback. Same shape as the real `UnloadFnType`.
pub type UnloadFnType = unsafe extern "system" fn(*const DRIVER_OBJECT);

// IRP major function codes (WDM values). Only the ones the driver registers are
// needed, but the array is sized to the full WDM range for index safety.
pub const IRP_MJ_CREATE: usize = 0x00;
pub const IRP_MJ_CLOSE: usize = 0x02;
pub const IRP_MJ_READ: usize = 0x03;
pub const IRP_MJ_WRITE: usize = 0x04;
pub const IRP_MJ_DEVICE_CONTROL: usize = 0x0e;
pub const IRP_MJ_CLEANUP: usize = 0x12;
pub const IRP_MJ_MAXIMUM_FUNCTION: usize = 0x1b;

/// WDM driver object. The real `Driver` registers handlers by writing function
/// pointers into `MajorFunction[IRP_MJ_*]` / `DriverUnload`; the mock `Driver`
/// does the same so a `DriverConnection` can read them back and dispatch exactly
/// like the kernel I/O manager.
///
/// `DeviceObject` models the WDM field of the same name: null until driver init
/// creates a device (`interface::init_driver_object` here, IoCreateDevice in the
/// kernel). The mock filter engine refuses callout registration without one,
/// like `FwpsCalloutRegister` does. Owned: freed on drop.
pub struct DRIVER_OBJECT {
    pub MajorFunction: [Option<MjFnType>; IRP_MJ_MAXIMUM_FUNCTION + 1],
    pub DriverUnload: Option<UnloadFnType>,
    pub DeviceObject: *mut DEVICE_OBJECT,
}

impl DRIVER_OBJECT {
    pub fn new() -> Self {
        Self {
            MajorFunction: [None; IRP_MJ_MAXIMUM_FUNCTION + 1],
            DriverUnload: None,
            DeviceObject: core::ptr::null_mut(),
        }
    }
}

// The raw `DeviceObject` pointer suppresses the auto impls the struct had before
// it existed. It is written once during init and freed on drop; `DEVICE_OBJECT`
// is a stateless ZST, so cross-thread moves of the owner stay sound.
unsafe impl Send for DRIVER_OBJECT {}
unsafe impl Sync for DRIVER_OBJECT {}

impl Drop for DRIVER_OBJECT {
    fn drop(&mut self) {
        if !self.DeviceObject.is_null() {
            unsafe { drop(Box::from_raw(self.DeviceObject)) };
            self.DeviceObject = core::ptr::null_mut();
        }
    }
}

impl Default for DRIVER_OBJECT {
    fn default() -> Self {
        Self::new()
    }
}

/// Host stand-in for the kernel IRP. Models a single buffered request: a system
/// buffer (the `AssociatedIrp.SystemBuffer` equivalent, shared by input and
/// output for buffered I/O) plus the lengths and the completion fields a handler
/// writes back (`information` = bytes transferred, `status` = NTSTATUS).
///
/// `system_buffer` points at caller-owned storage (a `DriverConnection`'s
/// buffer); the IRP and its request wrapper must not outlive it.
pub struct IRP {
    pub system_buffer: *mut u8,
    pub input_len: usize,
    pub output_len: usize,
    pub control_code: u32,
    pub information: usize,
    pub status: NTSTATUS,
}

impl IRP {
    /// IRP for a read (output-only): the handler fills up to `output_len` bytes.
    pub fn for_read(system_buffer: *mut u8, output_len: usize) -> Self {
        Self {
            system_buffer,
            input_len: 0,
            output_len,
            control_code: 0,
            information: 0,
            status: STATUS_SUCCESS,
        }
    }

    /// IRP for a write (input-only): the handler reads `input_len` bytes.
    pub fn for_write(system_buffer: *mut u8, input_len: usize) -> Self {
        Self {
            system_buffer,
            input_len,
            output_len: 0,
            control_code: 0,
            information: 0,
            status: STATUS_SUCCESS,
        }
    }

    /// IRP for a device-io-control request (buffered method): input and output
    /// share `system_buffer`.
    pub fn for_ioctl(
        system_buffer: *mut u8,
        input_len: usize,
        output_len: usize,
        control_code: u32,
    ) -> Self {
        Self {
            system_buffer,
            input_len,
            output_len,
            control_code,
            information: 0,
            status: STATUS_SUCCESS,
        }
    }
}
