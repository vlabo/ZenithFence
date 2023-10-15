use core::ffi::c_void;

use crate::alloc::borrow::ToOwned;
use crate::driver::Driver;
use crate::filter_engine::transaction::Transaction;
use crate::{dbg, info};
use alloc::string::String;
use alloc::{format, vec::Vec};
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

use self::callout::Callout;
use self::callout_data::CalloutData;
use self::classify::ClassifyOut;
use self::ffi::FWPS_FILTER2;
use self::layer::FwpsIncomingValues;
use self::metadata::FwpsIncomingMetadataValues;

pub mod callout;
pub mod callout_data;
pub(crate) mod classify;
pub mod connect_request;
#[allow(dead_code)]
pub mod ffi;
pub mod layer;
pub(crate) mod metadata;
pub mod packet;
pub mod transaction;

pub struct FilterEngine {
    device_object: *mut DEVICE_OBJECT,
    filter_engine_handle: HANDLE,
    sublayer_guid: u128,
    commited: bool,
}

impl FilterEngine {
    pub fn init(&mut self, driver: &Driver, layer_guid: u128) -> Result<(), String> {
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
        {
            // Begin write trasacction. This is also a lock guard.
            let mut transaction = match Transaction::begin_write(self) {
                Ok(transaction) => transaction,
                Err(err) => {
                    return Err(err);
                }
            };

            if let Err(err) = self.register_sublayer() {
                return Err(format!("filter_engine: {}", err));
            }

            dbg!("Callouts count: {}", callouts.len());
            // Register all callouts
            for (i, callout) in callouts.iter_mut().enumerate() {
                callout.index = i as u64;

                if let Err(err) = callout.register_callout(self, catch_all_callout) {
                    // This will destroy the callout structs.
                    return Err(err);
                }
                if let Err(err) = callout.register_filter(self) {
                    // This will destory the callout structs.
                    return Err(err);
                }
                dbg!(
                    "registerging callout: {} -> {}",
                    callout.name,
                    callout.filter_id
                );
            }
            unsafe { CALLOUTS.replace(callouts) };

            if let Err(err) = transaction.commit() {
                return Err(err);
            }
        }
        self.commited = true;
        info!("transaction commited");

        return Ok(());
    }

    pub(crate) fn reset_callout_filter(&self, callout_index: usize) -> Result<(), String> {
        // Begin write trasacction. This is also a lock guard.
        let mut transaction = match Transaction::begin_write(self) {
            Ok(transaction) => transaction,
            Err(err) => {
                return Err(err);
            }
        };
        unsafe {
            if let Some(callouts) = CALLOUTS.as_mut() {
                if let Some(callout) = callouts.get_mut(callout_index) {
                    if callout.filter_id != 0 {
                        // Remove old filter.
                        if let Err(err) =
                            ffi::unregister_filter(self.filter_engine_handle, callout.filter_id)
                        {
                            return Err(format!("filter_engine: {}", err));
                        }
                        callout.filter_id = 0;
                    }
                    // Create new filter.
                    if let Err(err) = callout.register_filter(self) {
                        return Err(format!("filter_engine: {}", err));
                    }
                }
            }
        }
        // Commit transaction.
        if let Err(err) = transaction.commit() {
            return Err(err);
        }
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
                        if ele.filter_id != 0 {
                            if let Err(code) =
                                ffi::unregister_filter(self.filter_engine_handle, ele.filter_id)
                            {
                                dbg!("failed to unregister filter: {}", code)
                            }
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
    layer_data: *mut c_void,
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
            let data = CalloutData {
                callout_index: filter.context as usize,
                layer: callout.layer,
                values: array,
                metadata: meta_values,
                classify_out,
                classify_context: context,
                filter_id: callout.filter_id,
                layer_data,
            };
            if let Some(device_object) = callout.device_object.as_mut() {
                (callout.callout_fn)(data, device_object);
            }
        }
    }
}
