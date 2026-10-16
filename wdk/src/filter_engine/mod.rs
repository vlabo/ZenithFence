use core::ffi::c_void;

use crate::alloc::borrow::ToOwned;
use crate::driver::Driver;
use crate::ffi::FWPS_FILTER2;
use crate::filter_engine::transaction::Transaction;
use crate::{dbg, info};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::{format, vec::Vec};
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

use self::callout::{Callout, FilterType};
use self::callout_data::CalloutData;
use self::classify::ClassifyOut;
use self::layer::IncomingValues;
use self::metadata::FwpsIncomingMetadataValues;

pub mod callout;
pub mod callout_data;
pub(crate) mod classify;
#[allow(dead_code)]
pub mod ffi;
pub mod layer;
pub(crate) mod metadata;
pub mod net_buffer;
pub mod packet;
pub mod stream_data;
pub mod transaction;
// Helper functions for ALE Readirect layers. Not needed for the current implementation.
// pub mod connect_request;

/// Why `FilterEngine::reset_all_filters` did not apply the reset.
pub enum ResetError {
    /// Another transaction is in progress on the filter engine session and only one can be open at
    /// a time. Nothing was changed: no filter was removed and none was re-registered, so the reset
    /// can be repeated as-is once the other transaction is done.
    TransactionInProgress,
    /// Anything else. Not transient, repeating it is pointless.
    Failed(String),
}

impl From<ResetError> for String {
    fn from(err: ResetError) -> Self {
        match err {
            ResetError::TransactionInProgress => String::from(transaction::BeginError::InProgress),
            ResetError::Failed(message) => message,
        }
    }
}

pub struct FilterEngine {
    device_object: *mut DEVICE_OBJECT,
    handle: HANDLE,
    sublayer_guid: u128,
    committed: bool,
    callouts: Option<Vec<Box<Callout>>>,
}

impl FilterEngine {
    pub fn new(driver: &Driver, layer_guid: u128) -> Result<Self, String> {
        let filter_engine_handle: HANDLE;
        match ffi::create_filter_engine() {
            Ok(handle) => {
                filter_engine_handle = handle;
            }
            Err(code) => {
                return Err(format!("failed to initialize filter engine {}", code).to_owned());
            }
        }
        Ok(Self {
            device_object: driver.get_device_object(),
            handle: filter_engine_handle,
            sublayer_guid: layer_guid,
            committed: false,
            callouts: None,
        })
    }

    pub fn commit(&mut self, callouts: Vec<Callout>) -> Result<(), String> {
        {
            // Begin write transaction. This is also a lock guard.
            let mut filter_engine = match Transaction::begin_write_retrying(self) {
                Ok(transaction) => transaction,
                Err(err) => {
                    return Err(err);
                }
            };

            if let Err(err) = filter_engine.register_sublayer() {
                return Err(format!("filter_engine: {}", err));
            }

            dbg!("Callouts count: {}", callouts.len());
            let mut boxed_callouts = Vec::new();
            // Register all callouts
            for callout in callouts {
                let mut callout = Box::new(callout);
                callout.address = callout.as_ref() as *const Callout as u64;

                if let Err(err) = callout.register_callout(
                    filter_engine.handle,
                    filter_engine.device_object,
                    catch_all_callout,
                ) {
                    // This will destroy the callout structs.
                    return Err(err);
                }
                if let Err(err) =
                    callout.register_filter(filter_engine.handle, filter_engine.sublayer_guid)
                {
                    // This will destroy the callout structs.
                    return Err(err);
                }
                dbg!(
                    "registering callout: {} -> {}",
                    callout.name,
                    callout.filter_id
                );
                boxed_callouts.push(callout)
            }
            if let Some(callouts) = &mut filter_engine.callouts {
                callouts.append(&mut boxed_callouts);
            } else {
                filter_engine.callouts = Some(boxed_callouts);
            }

            if let Err(err) = filter_engine.commit() {
                return Err(err);
            }
        }
        self.committed = true;
        info!("transaction committed");

        return Ok(());
    }

    /// Reports whether any filter is still registered.
    fn has_registered_filters(&self) -> bool {
        match &self.callouts {
            Some(callouts) => callouts.iter().any(|callout| callout.filter_id != 0),
            None => false,
        }
    }

    /// Removes all registered filters, leaving the callouts in place. Once the transaction is
    /// committed no new classify call can reach the callouts. This is the first step of the
    /// teardown: complete the operations that are still pended, then call `unregister_callouts`,
    /// which `FwpsCalloutUnregisterById0` refuses to do while one is outstanding.
    ///
    /// Does nothing when the filters are already gone, so it is safe to call more than once.
    pub fn unregister_filters(&mut self) -> Result<(), String> {
        if !self.has_registered_filters() {
            // Nothing to remove; do not open a transaction for it.
            return Ok(());
        }

        // Begin to write transaction. This is also a lock guard. It will abort if transaction is not committed.
        // Waits out a transaction that is in progress instead of failing: leaving the filters
        // registered here would make `unregister_callouts` fail too, and the teardown has no
        // second chance to remove them.
        let mut filter_engine = match Transaction::begin_write_retrying(self) {
            Ok(transaction) => transaction,
            Err(err) => {
                return Err(err);
            }
        };

        let filter_engine_handle = filter_engine.handle;
        if let Some(callouts) = &mut filter_engine.callouts {
            for callout in callouts {
                if callout.filter_id != 0 {
                    if let Err(err) = ffi::unregister_filter(filter_engine_handle, callout.filter_id)
                    {
                        return Err(format!("filter_engine: {}", err));
                    }
                    callout.filter_id = 0;
                }
            }
        }

        // Commit transaction.
        if let Err(err) = filter_engine.commit() {
            return Err(err);
        }

        return Ok(());
    }

    /// Unregisters all registered callouts. This is the last step of the teardown and must run
    /// after `unregister_filters` and after every pended operation has been completed:
    /// `FwpsCalloutUnregisterById0` fails with STATUS_DEVICE_BUSY while an operation is still
    /// pended, and letting the driver unload over a callout that is still registered strands that
    /// operation for good — nothing can complete its IRP afterwards, so the thread waiting on it
    /// never returns from the kernel and its process can no longer be terminated.
    ///
    /// Skips the callouts that are already gone, so it is safe to call more than once.
    pub fn unregister_callouts(&mut self) -> Result<(), String> {
        let mut first_failure = None;

        if let Some(callouts) = &mut self.callouts {
            for callout in callouts {
                if !callout.registered {
                    continue;
                }

                match ffi::unregister_callout(callout.id) {
                    Ok(()) => callout.registered = false,
                    // Keep going so the remaining callouts are still removed, and report the first
                    // failure once the whole set has been tried.
                    Err(err) => {
                        if first_failure.is_none() {
                            first_failure = Some(format!("{}: {}", callout.name, err));
                        }
                    }
                }
            }
        }

        match first_failure {
            Some(err) => Err(format!("filter_engine: failed to unregister callout {}", err)),
            None => Ok(()),
        }
    }

    /// Removes and re-registers every resettable filter, which makes WFP reauthorize the existing
    /// connections against them. This is the only way to release a connection that was deferred
    /// without a completion handle (see `CalloutData::pend_filter_rest`), because a single filter
    /// cannot be reset on its own.
    ///
    /// Does not retry on its own. Only one transaction can be open on the filter engine session, so
    /// concurrent callers collide; `ResetError::TransactionInProgress` tells them apart from the
    /// real failures and leaves the decision of when to try again to the caller, which can batch
    /// several deferred connections into one reset instead of racing per connection.
    pub fn reset_all_filters(&mut self) -> Result<(), ResetError> {
        if !self.has_registered_filters() {
            // The filters are gone, which only happens once the teardown has removed them. There
            // is nothing to reset, and re-registering them here would bring the callouts back to
            // life right before they are unregistered.
            return Ok(());
        }

        // Begin to write transaction. This is also a lock guard. It will abort if transaction is not committed.
        let mut filter_engine = match Transaction::begin_write(self) {
            Ok(transaction) => transaction,
            Err(transaction::BeginError::InProgress) => {
                return Err(ResetError::TransactionInProgress)
            }
            Err(err) => return Err(ResetError::Failed(String::from(err))),
        };
        let filter_engine_handle = filter_engine.handle;
        let sublayer_guid = filter_engine.sublayer_guid;
        if let Some(callouts) = &mut filter_engine.callouts {
            for callout in callouts {
                if let FilterType::Resettable = callout.filter_type {
                    if callout.filter_id != 0 {
                        // Remove old filter.
                        if let Err(err) =
                            ffi::unregister_filter(filter_engine_handle, callout.filter_id)
                        {
                            return Err(ResetError::Failed(format!("filter_engine: {}", err)));
                        }
                        callout.filter_id = 0;
                    }
                    // Create new filter.
                    if let Err(err) = callout.register_filter(filter_engine_handle, sublayer_guid) {
                        return Err(ResetError::Failed(format!("filter_engine: {}", err)));
                    }
                }
            }
        }
        // Commit transaction.
        if let Err(err) = filter_engine.commit() {
            return Err(ResetError::Failed(err));
        }
        return Ok(());
    }

    fn register_sublayer(&self) -> Result<(), String> {
        let result = ffi::register_sublayer(
            self.handle,
            "ZenithFenceSublayer",
            "The ZenithFence sublayer holds all it's filters.",
            self.sublayer_guid,
        );
        if let Err(code) = result {
            return Err(format!("failed to register sublayer: {}", code));
        }

        return Ok(());
    }
}

impl Drop for FilterEngine {
    fn drop(&mut self) {
        dbg!("Unregistering callouts");

        // Failsafe only. The teardown in Device::shutdown removes the filters and the callouts
        // explicitly, in the order that lets the pended operations be completed in between, so
        // both calls below are no-ops by the time we get here. They only do anything if the
        // teardown never ran, and then the order still matters: filters first, so no new classify
        // call can arrive while the callouts are being unregistered.
        if let Err(err) = self.unregister_filters() {
            dbg!("failed to unregister filters: {}", err);
        }
        if let Err(err) = self.unregister_callouts() {
            // Reaching this means a pended operation was never completed and the driver is about
            // to unload over a live callout, which leaves the thread waiting on that operation
            // stuck in the kernel for good. Report it through DbgPrint directly, because the log
            // macros are compiled out in release builds and the event queue that carries the
            // driver log to user space is already gone by this point.
            crate::interface::dbg_print(format!("ERROR ZenithFence: {}\n", err));
        }

        if self.committed {
            if let Err(code) = ffi::unregister_sublayer(self.handle, self.sublayer_guid) {
                dbg!("Failed to unregister sublayer: {}", code);
            }
        }

        if self.handle != 0 && self.handle != INVALID_HANDLE_VALUE {
            _ = ffi::filter_engine_close(self.handle);
        }
    }
}

#[no_mangle]
unsafe extern "C" fn catch_all_callout(
    fixed_values: *const IncomingValues,
    meta_values: *const FwpsIncomingMetadataValues,
    layer_data: *mut c_void,
    _context: *mut c_void,
    filter: *const FWPS_FILTER2,
    _flow_context: u64,
    classify_out: *mut ClassifyOut,
) {
    let filter = &(*filter);
    // Filter context is the address of the callout.
    let callout = filter.context as *mut Callout;

    if let Some(callout) = callout.as_ref() {
        // Setup callout data.
        let array = core::slice::from_raw_parts(
            (*fixed_values).incoming_value_array,
            (*fixed_values).value_count as usize,
        );
        let data = CalloutData {
            layer: callout.layer,
            callout_id: filter.context as usize,
            values: array,
            metadata: meta_values,
            classify_out,
            layer_data,
        };
        // Call the defined function.
        (callout.callout_fn)(data);
    }
}
