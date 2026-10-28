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
