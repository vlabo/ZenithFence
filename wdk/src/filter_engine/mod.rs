use core::ffi::c_void;

use crate::alloc::borrow::ToOwned;
use crate::rw_spin_lock::RwSpinLock;
use crate::utils::{CallData, Driver};
use crate::{dbg, info};
use alloc::string::String;
use alloc::{format, vec::Vec};
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

use self::callout::Callout;
use self::classify::ClassifyOut;
use self::ffi::FWPS_FILTER2;
use self::layer::FwpsIncomingValues;
use self::metadata::FwpsIncomingMetadataValues;

pub mod callout;
pub(crate) mod classify;
pub mod ffi;
pub mod layer;
pub(crate) mod metadata;

pub struct FilterEngine {
    device_object: *mut DEVICE_OBJECT,
    filter_engine_handle: HANDLE,
    sublayer_guid: u128,
    commited: bool,
    lock: RwSpinLock,
}

impl FilterEngine {
    // pub const fn default() -> Self {
    //     Self {
    //         device_object: core::ptr::null_mut(),
    //         filter_engine_handle: INVALID_HANDLE_VALUE,
    //         sublayer_guid: 0,
    //         commited: false,
    //         lock: RwSpinLock::default(),
    //     }
    // }

    pub fn init(&mut self, driver: &Driver, layer_guid: u128) -> Result<(), String> {
        self.lock = RwSpinLock::default();
        let filter_engine_handle: HANDLE;
        match ffi::create_filter_engine() {
            Ok(handle) => {
                filter_engine_handle = handle;
            }
            Err(code) => {
                return Err(format!("failed to initialize filter engine {}", code).to_owned());
            }
        }
        self.device_object = driver.get_device_object();
        self.filter_engine_handle = filter_engine_handle;
        self.sublayer_guid = layer_guid;
        return Ok(());
    }

    pub fn commit(&mut self, mut callouts: Vec<Callout>) -> Result<(), String> {
        // let _guard = self.lock.write_lock();
        if let Err(code) = ffi::filter_engine_transaction_begin(self.filter_engine_handle, 0) {
            return Err(format!(
                "filter-engine: failed to begin transaction: {}",
                code
            ));
        }

        if let Err(err) = self.register_sublayer() {
            _ = ffi::filter_engine_transaction_abort(self.filter_engine_handle);
            return Err(format!("filter_engine: {}", err));
        }

        dbg!("Callouts count: {}", callouts.len());
        // Register all callouts
        for (i, callout) in callouts.iter_mut().enumerate() {
            callout.index = i as u64;

            if let Err(err) = callout.register_callout(self, catch_all_callout) {
                // This will destroy the callout structs.
                _ = ffi::filter_engine_transaction_abort(self.filter_engine_handle);
                return Err(err);
            }
            if let Err(err) = callout.register_filter(self) {
                // This will destory the callout structs.
                _ = ffi::filter_engine_transaction_abort(self.filter_engine_handle);
                return Err(err);
            }
            dbg!(
                "registerging callout: {} -> {}",
                callout.name,
                callout.filter_id
            );
        }
        unsafe { CALLOUTS.replace(callouts) };

        if let Err(code) = ffi::filter_engine_transaction_commit(self.filter_engine_handle) {
            return Err(format!(
                "filter-engine: failed to commit transaction: {}",
                code
            ));
        }

        // TODO: auto abort on error

        self.commited = true;
        info!("transaction commited");

        return Ok(());
    }

    pub(crate) fn reset_callout_filter(&self, _callout_index: usize) -> Result<(), String> {
        let _guard = self.lock.write_lock();
        if let Err(code) = ffi::filter_engine_transaction_begin(self.filter_engine_handle, 0) {
            return Err(format!(
                "filter-engine: failed to begin transaction: {}",
                code
            ));
        }
        _ = ffi::filter_engine_transaction_abort(self.filter_engine_handle);
        // unsafe {
        // if let Some(_callouts) = CALLOUTS.as_ref() {
        // if let Some(callout) = callouts.get_mut(callout_index) {
        // if callout.filter_id != 0 {
        //     // Remove old filter.
        //     if let Err(err) =
        //         ffi::unregister_filter(self.filter_engine_handle, callout.filter_id)
        //     {
        //         // _ = ffi::filter_engine_transaction_abort(self.filter_engine_handle);
        //         return Err(format!("filter_engine: {}", err));
        //     }
        // callout.filter_id = 0;
        // }
        // }
        // // Create new filter.
        // if let Err(err) = callout.register_filter(self) {
        //     _ = ffi::filter_engine_transaction_abort(self.filter_engine_handle);
        //     return Err(format!("filter_engine: {}", err));
        // }
        // }
        // }
        // Commit transaction.
        // if let Err(code) = ffi::filter_engine_transaction_commit(self.filter_engine_handle) {
        //     return Err(format!(
        //         "filter-engine: failed to commit transaction: {}",
        //         code
        //     ));
        // }
        return Ok(());
    }

    fn register_sublayer(&self) -> Result<(), String> {
        let result = ffi::register_sublayer(
            self.filter_engine_handle,
            "PortmasterSublayer",
            "The Portmaster sublayer holds all it's filters.",
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
        unsafe {
            if let Some(callouts) = CALLOUTS.take() {
                for ele in callouts {
                    if ele.registerd {
                        if let Err(code) = ffi::unregister_callout(ele.id) {
                            dbg!("faild to unregister callout: {}", code);
                        }
                        if let Err(code) =
                            ffi::unregister_filter(self.filter_engine_handle, ele.filter_id)
                        {
                            dbg!("failed to unregister filter: {}", code)
                        }
                    }
                }
            }
        }

        if self.commited {
            if let Err(code) =
                ffi::unregister_sublayer(self.filter_engine_handle, self.sublayer_guid)
            {
                dbg!("Failed to unregister sublayer: {}", code);
            }
        }

        if self.filter_engine_handle != INVALID_HANDLE_VALUE {
            _ = ffi::filter_engine_close(self.filter_engine_handle);
        }
    }
}

static mut CALLOUTS: Option<Vec<Callout>> = None;

#[no_mangle]
unsafe extern "C" fn catch_all_callout(
    fixed_values: *const FwpsIncomingValues,
    meta_values: *const FwpsIncomingMetadataValues,
    _layer_data: *mut c_void,
    context: *mut c_void,
    filter: *const FWPS_FILTER2,
    _flow_context: u64,
    classify_out: *mut ClassifyOut,
) {
    let filter = &(*filter);
    if let Some(callouts) = CALLOUTS.as_ref() {
        if let Some(callout) = callouts.get(filter.context as usize) {
            let array = core::slice::from_raw_parts(
                (*fixed_values).incoming_value_array,
                (*fixed_values).value_count as usize,
            );
            let data = CallData {
                callout_index: filter.context as usize,
                layer: callout.layer,
                values: array,
                metadata: meta_values,
                classify_out,
                classify_context: context,
                filter_id: callout.filter_id,
            };
            if let Some(device_object) = callout.device_object.as_mut() {
                (callout.callout_fn)(data, device_object);
            }
        }
    }
}
