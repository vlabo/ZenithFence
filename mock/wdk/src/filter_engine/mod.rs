pub mod callout;
pub mod callout_data;
pub mod classify;
pub mod layer;
pub mod net_buffer;
pub mod packet;

use crate::driver::Driver;
use crate::kernel_types::DEVICE_OBJECT;

use self::callout::{Callout, FilterType};
use self::layer::Layer;

/// Host mock of `wdk::filter_engine::ResetError`.
pub enum ResetError {
    /// Another transaction is in progress on the filter engine session. The
    /// mock has no concurrent transactions, so it never produces this, but the
    /// driver matches on it.
    TransactionInProgress,
    Failed(String),
}

impl From<ResetError> for String {
    fn from(err: ResetError) -> Self {
        match err {
            ResetError::TransactionInProgress => {
                "filter-engine: failed to begin transaction: STATUS_FWP_TXN_IN_PROGRESS".into()
            }
            ResetError::Failed(message) => message,
        }
    }
}

/// One registered callout+filter pair, as the kernel would hold it after
/// `FwpsCalloutRegister` + `FwpmFilterAdd`. Exposed so harnesses can assert the
/// driver registered exactly the callouts it should, on the layers it should.
pub struct FilterRegistration {
    pub name: String,
    pub guid: u128,
    pub layer: Layer,
    pub callout_id: u32,
    /// 0 once the filter has been removed (`unregister_filters`).
    pub filter_id: u64,
    pub resettable: bool,
    /// Cleared by `unregister_callouts`.
    pub callout_registered: bool,
}

/// Host mock of `wdk::filter_engine::FilterEngine`.
///
/// Models the real registration sequence instead of no-op'ing it: `commit` is a
/// write transaction that registers the sublayer once, then every callout and
/// its filter — all-or-nothing, like the kernel transaction. Failure modes the
/// kernel would produce are reproduced: a second commit fails (sublayer
/// ALREADY_EXISTS), registration without a device object fails
/// (`FwpsCalloutRegister` needs one), and a duplicate callout GUID fails and
/// leaves no partial state behind.
pub struct FilterEngine {
    // Null-checked only, never dereferenced (the mock DEVICE_OBJECT is a ZST).
    device_object: *mut DEVICE_OBJECT,
    sublayer_guid: u128,
    committed: bool,
    // Keeps the callout vector (and its `callout_fn` pointers) alive for the
    // engine's lifetime, matching the real one.
    _callouts: Vec<Callout>,
    registrations: Vec<FilterRegistration>,
    // 0 means "unregistered" in the real code, so ids start at 1.
    next_filter_id: u64,
    next_callout_id: u32,
}

// The raw device-object pointer suppresses the auto impls; it is only ever
// null-checked, so sharing the engine across threads stays sound.
unsafe impl Send for FilterEngine {}
unsafe impl Sync for FilterEngine {}

impl FilterEngine {
    pub fn new(driver: &Driver, layer_guid: u128) -> Result<Self, String> {
        Ok(FilterEngine {
            device_object: driver.get_device_object(),
            sublayer_guid: layer_guid,
            committed: false,
            _callouts: Vec::new(),
            registrations: Vec::new(),
            next_filter_id: 0,
            next_callout_id: 0,
        })
    }

    pub fn commit(&mut self, callouts: Vec<Callout>) -> Result<(), String> {
        if self.committed {
            // A second commit re-registers the sublayer, which the kernel
            // rejects with FWP_E_ALREADY_EXISTS.
            return Err(format!(
                "filter engine: sublayer {:x} already registered",
                self.sublayer_guid
            ));
        }
        if self.device_object.is_null() {
            return Err("filter engine: callout registration requires a device object".into());
        }
        // Stage the whole batch before touching state: the kernel wraps
        // registration in a write transaction, so either every callout+filter
        // registers or none does.
        let mut staged: Vec<FilterRegistration> = Vec::with_capacity(callouts.len());
        for callout in &callouts {
            if staged.iter().any(|reg| reg.guid == callout.guid) {
                return Err(format!(
                    "filter engine: callout {} ({:x}) already registered",
                    callout.name, callout.guid
                ));
            }
            staged.push(FilterRegistration {
                name: callout.name.clone(),
                guid: callout.guid,
                layer: callout.layer,
                callout_id: 0,
                filter_id: 0,
                resettable: matches!(callout.filter_type, FilterType::Resettable),
                callout_registered: false,
            });
        }
        for reg in &mut staged {
            self.next_callout_id += 1;
            self.next_filter_id += 1;
            reg.callout_id = self.next_callout_id;
            reg.filter_id = self.next_filter_id;
            reg.callout_registered = true;
        }
        self.registrations = staged;
        self._callouts = callouts;
        self.committed = true;
        Ok(())
    }

    fn has_registered_filters(&self) -> bool {
        self.registrations.iter().any(|reg| reg.filter_id != 0)
    }

    /// Mirrors the real `unregister_filters`: removes every filter, leaving the
    /// callouts registered. A no-op once the filters are gone.
    pub fn unregister_filters(&mut self) -> Result<(), String> {
        for reg in self.registrations.iter_mut() {
            reg.filter_id = 0;
        }
        Ok(())
    }

    /// Mirrors the real `unregister_callouts`: unregisters every callout that is
    /// still registered. A no-op for the ones already gone.
    pub fn unregister_callouts(&mut self) -> Result<(), String> {
        for reg in self.registrations.iter_mut() {
            reg.callout_registered = false;
        }
        Ok(())
    }

    pub fn reset_all_filters(&mut self) -> Result<(), ResetError> {
        if !self.committed {
            // The real version begins a write transaction against the committed
            // engine; before commit there is nothing to reset.
            return Err(ResetError::Failed("filter engine: reset before commit".into()));
        }
        if !self.has_registered_filters() {
            // Like the real one: once the teardown removed the filters there is
            // nothing to reset, and re-adding them would revive the callouts.
            return Ok(());
        }
        for reg in self.registrations.iter_mut() {
            if !reg.resettable {
                continue;
            }
            if reg.filter_id == 0 {
                return Err(ResetError::Failed(format!(
                    "filter engine: {} has no registered filter",
                    reg.name
                )));
            }
            // Re-adding the filter assigns a fresh id, like FwpmFilterAdd.
            self.next_filter_id += 1;
            reg.filter_id = self.next_filter_id;
        }
        Ok(())
    }

    /// Whether the sublayer/callouts/filters transaction has been committed.
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// The registered callout+filter pairs, in registration order.
    pub fn registrations(&self) -> &[FilterRegistration] {
        &self.registrations
    }
}

#[cfg(test)]
mod tests {
    use super::callout_data::CalloutData;
    use super::*;
    use crate::kernel_types::DRIVER_OBJECT;

    fn noop(_data: CalloutData) {}

    fn callout(name: &str, guid: u128, filter_type: FilterType) -> Callout {
        Callout::new(name, "", guid, Layer::AleAuthConnectV4, 0, filter_type, noop)
    }

    fn engine() -> FilterEngine {
        FilterEngine::new(&Driver::mock(), 0xf19f).expect("new filter engine")
    }

    #[test]
    fn commit_registers_all_with_distinct_ids() {
        let mut fe = engine();
        assert!(!fe.is_committed());
        fe.commit(vec![
            callout("a", 1, FilterType::Resettable),
            callout("b", 2, FilterType::NonResettable),
            callout("c", 3, FilterType::Resettable),
        ])
        .expect("commit");
        assert!(fe.is_committed());
        let regs = fe.registrations();
        assert_eq!(regs.len(), 3);
        for reg in regs {
            assert_ne!(reg.callout_id, 0);
            assert_ne!(reg.filter_id, 0);
        }
        let mut filter_ids: Vec<u64> = regs.iter().map(|r| r.filter_id).collect();
        filter_ids.dedup();
        assert_eq!(filter_ids.len(), 3);
    }

    #[test]
    fn second_commit_fails() {
        let mut fe = engine();
        fe.commit(vec![callout("a", 1, FilterType::Resettable)]).expect("first commit");
        assert!(fe.commit(vec![callout("b", 2, FilterType::Resettable)]).is_err());
        assert_eq!(fe.registrations().len(), 1);
    }

    #[test]
    fn commit_without_device_object_fails() {
        // A DRIVER_OBJECT that never went through init_driver_object has no
        // device object, and callout registration must refuse it.
        let mut object = DRIVER_OBJECT::new();
        let driver = Driver::from_driver_object(&mut object);
        let mut fe = FilterEngine::new(&driver, 0xf19f).expect("new filter engine");
        assert!(fe.commit(vec![callout("a", 1, FilterType::Resettable)]).is_err());
        assert!(!fe.is_committed());
    }

    #[test]
    fn duplicate_guid_fails_atomically() {
        let mut fe = engine();
        let result = fe.commit(vec![
            callout("a", 1, FilterType::Resettable),
            callout("b", 1, FilterType::Resettable),
        ]);
        assert!(result.is_err());
        // Transaction semantics: nothing from the failed batch registered.
        assert!(!fe.is_committed());
        assert!(fe.registrations().is_empty());
    }

    #[test]
    fn reset_only_rotates_resettable_filter_ids() {
        let mut fe = engine();
        assert!(fe.reset_all_filters().is_err(), "reset before commit must fail");
        fe.commit(vec![
            callout("a", 1, FilterType::Resettable),
            callout("b", 2, FilterType::NonResettable),
        ])
        .expect("commit");
        let before: Vec<u64> = fe.registrations().iter().map(|r| r.filter_id).collect();
        assert!(fe.reset_all_filters().is_ok(), "reset");
        let after: Vec<u64> = fe.registrations().iter().map(|r| r.filter_id).collect();
        assert_ne!(before[0], after[0], "resettable filter must get a fresh id");
        assert_eq!(before[1], after[1], "non-resettable filter must keep its id");
    }

    #[test]
    fn teardown_removes_filters_then_callouts_and_stops_resets() {
        let mut fe = engine();
        fe.commit(vec![callout("a", 1, FilterType::Resettable)]).expect("commit");
        fe.unregister_filters().expect("unregister filters");
        assert!(fe.registrations().iter().all(|r| r.filter_id == 0));
        assert!(fe.registrations().iter().all(|r| r.callout_registered));
        // A reset after the filters are gone must not bring them back.
        assert!(fe.reset_all_filters().is_ok());
        assert!(fe.registrations().iter().all(|r| r.filter_id == 0));
        fe.unregister_callouts().expect("unregister callouts");
        assert!(fe.registrations().iter().all(|r| !r.callout_registered));
        // Both steps are idempotent.
        fe.unregister_filters().expect("second unregister filters");
        fe.unregister_callouts().expect("second unregister callouts");
    }
}
