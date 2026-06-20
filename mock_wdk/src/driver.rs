/// Host mock of `wdk::driver::Driver`.
///
/// In production this wraps the WDM `DRIVER_OBJECT`/`DEVICE_OBJECT`. The
/// driver's packet-handling path only ever takes a `&Driver` and hands it to
/// `FilterEngine::new` / `Device::new`, both of which the mock treats as
/// no-ops, so the mock `Driver` carries no state.
pub struct Driver;

unsafe impl Sync for Driver {}
unsafe impl Send for Driver {}

impl Driver {
    /// Construct a mock driver for use in tests / fuzz harnesses.
    pub fn mock() -> Self {
        Driver
    }
}
