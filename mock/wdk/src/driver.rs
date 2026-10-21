//! Host mock of `wdk::driver::Driver`.
//!
//! In production this wraps the WDM `DRIVER_OBJECT`/`DEVICE_OBJECT` and registers
//! IRP dispatch handlers by writing function pointers into
//! `DRIVER_OBJECT.MajorFunction[IRP_MJ_*]`. The mock mirrors that exactly so the
//! real `DriverEntry` runs unchanged and a `DriverConnection` can read the
//! handlers back from the `DRIVER_OBJECT` and dispatch like the I/O manager.
//!
//! `Driver::mock()` (carrying a null driver object) keeps the older
//! `Device::new(&Driver::mock())` fuzz/test path working: with no driver object,
//! the `set_*_fn` registrations are no-ops, which is fine because that path never
//! dispatches through the registered handlers. It does carry a (static, zero
//! sized) device object, because the mock filter engine — like the kernel's
//! `FwpsCalloutRegister` — refuses callout registration without one.

use core::ptr::null_mut;

use crate::kernel_types::{
    MjFnType, UnloadFnType, DEVICE_OBJECT, DRIVER_OBJECT, IRP_MJ_CLEANUP, IRP_MJ_CLOSE,
    IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE,
};

pub struct Driver {
    driver_object: *mut DRIVER_OBJECT,
    device_object: *mut DEVICE_OBJECT,
}

unsafe impl Sync for Driver {}
unsafe impl Send for Driver {}

impl Driver {
    /// Construct a driver with no backing driver object, for tests / fuzz
    /// harnesses that build a `Device` directly without going through
    /// `DriverEntry`. The device object is a process-wide stateless ZST so the
    /// filter engine's registration check passes.
    pub fn mock() -> Self {
        static MOCK_DEVICE_OBJECT: DEVICE_OBJECT = DEVICE_OBJECT;
        Driver {
            driver_object: null_mut(),
            device_object: core::ptr::addr_of!(MOCK_DEVICE_OBJECT) as *mut DEVICE_OBJECT,
        }
    }

    /// Bind a driver to a caller-owned `DRIVER_OBJECT` (used by
    /// `interface::init_driver_object`). Handler registration writes into it;
    /// the device object is the one driver init created in it, if any.
    pub(crate) fn from_driver_object(driver_object: *mut DRIVER_OBJECT) -> Self {
        let device_object = unsafe { driver_object.as_ref() }
            .map(|object| object.DeviceObject)
            .unwrap_or(null_mut());
        Driver {
            driver_object,
            device_object,
        }
    }

    pub fn get_device_object(&self) -> *mut DEVICE_OBJECT {
        self.device_object
    }

    pub fn get_device_object_ref(&self) -> Option<&mut DEVICE_OBJECT> {
        unsafe { self.device_object.as_mut() }
    }

    pub fn set_driver_unload(&mut self, driver_unload: UnloadFnType) {
        if let Some(driver) = unsafe { self.driver_object.as_mut() } {
            driver.DriverUnload = Some(driver_unload);
        }
    }

    pub fn set_read_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(IRP_MJ_READ, mj_fn);
    }

    pub fn set_write_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(IRP_MJ_WRITE, mj_fn);
    }

    pub fn set_create_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(IRP_MJ_CREATE, mj_fn);
    }

    pub fn set_device_control_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(IRP_MJ_DEVICE_CONTROL, mj_fn);
    }

    pub fn set_close_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(IRP_MJ_CLOSE, mj_fn);
    }

    pub fn set_cleanup_fn(&mut self, mj_fn: MjFnType) {
        self.set_major_fn(IRP_MJ_CLEANUP, mj_fn);
    }

    fn set_major_fn(&mut self, fn_index: usize, mj_fn: MjFnType) {
        if let Some(driver) = unsafe { self.driver_object.as_mut() } {
            driver.MajorFunction[fn_index] = Some(mj_fn);
        }
    }
}
