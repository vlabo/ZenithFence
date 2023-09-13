use core::cell::RefCell;

use crate::alloc::borrow::ToOwned;
use crate::utils::{CallData, Driver};
use crate::{dbg, info};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::{format, vec::Vec};
use winapi::shared::ntdef::{PCVOID, PVOID};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

use self::callout::Callout;
use self::layer::FwpsIncomingValues;

pub mod callout;
pub mod ffi;
pub mod layer;

pub struct FilterEngineInternal {
    driver: Driver,
    filter_engine_handle: HANDLE,
    sublayer_guid: u128,
    commited: bool,
    callouts: BTreeMap<u64, Callout>,
}

impl FilterEngineInternal {
    pub const fn default() -> Self {
        Self {
            driver: Driver::default(),
            filter_engine_handle: INVALID_HANDLE_VALUE,
            sublayer_guid: 0,
            commited: false,
            callouts: BTreeMap::new(),
        }
    }

    pub fn init(&mut self, driver: Driver, layer_guid: u128) -> Result<(), String> {
        let filter_engine_handle: HANDLE;
        match ffi::create_filter_engine() {
            Ok(handle) => {
                filter_engine_handle = handle;
            }
            Err(code) => {
                return Err(format!("failed to initialize filter engine {}", code).to_owned());
            }
        }
        self.driver = driver;
        self.filter_engine_handle = filter_engine_handle;
        self.sublayer_guid = layer_guid;
        return Ok(());
    }

    pub fn commit(&mut self, callouts: Vec<Callout>) -> Result<(), String> {
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
        for mut callout in callouts {
            if let Err(err) = callout.register_callout(self, test_callout) {
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

            self.callouts.insert(callout.filter_id, callout);
        }

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

impl Drop for FilterEngineInternal {
    fn drop(&mut self) {
        dbg!("Unregistering callouts");
        for (_id, ele) in &mut self.callouts {
            if ele.registerd {
                if let Err(code) = ffi::unregister_callout(ele.callout_id) {
                    dbg!("faild to unregister callout: {}", code);
                }
                if let Err(code) = ffi::unregister_filter(self.filter_engine_handle, ele.filter_id)
                {
                    dbg!("failed to unregister filter: {}", code)
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

pub struct FilterEngine {
    imp: RefCell<FilterEngineInternal>,
}

impl FilterEngine {
    const fn default() -> Self {
        return Self {
            imp: RefCell::new(FilterEngineInternal::default()),
        };
    }

    pub fn init(&self, driver: Driver, layer_guid: u128) -> Result<(), String> {
        if let Ok(mut fe) = self.imp.try_borrow_mut() {
            if let Err(err) = fe.init(driver, layer_guid) {
                return Err(err);
            }

            return Ok(());
        }

        return Err("failed to borrow filter engine".to_owned());
    }

    pub fn commit(&self, callouts: Vec<Callout>) -> Result<(), String> {
        if let Ok(mut fe) = self.imp.try_borrow_mut() {
            fe.commit(callouts)?;
            return Ok(());
        }
        return Err("failed to borrow filter engine".to_owned());
    }

    pub fn deinit(&self) {
        let _ = self.imp.replace(FilterEngineInternal::default());
    }
}

unsafe impl Sync for FilterEngine {}

// Global Singleton Filter Engine
pub static FILTER_ENGINE: FilterEngine = FilterEngine::default();

#[no_mangle]
unsafe extern "C" fn test_callout(
    fixed_values: *const FwpsIncomingValues,
    _meta_values: PCVOID,
    _layer_data: PVOID,
    _context: PCVOID,
    filter: PCVOID,
    _flow_context: u64,
    _classify_out: PVOID,
) {
    let filter_id = ffi::pm_GetFilterID(filter);

    if let Ok(fe) = FILTER_ENGINE.imp.try_borrow() {
        let callout = &fe.callouts[&filter_id];
        let array = core::slice::from_raw_parts(
            (*fixed_values).incoming_value_array,
            (*fixed_values).value_count as usize,
        );
        let data = CallData::new(callout.layer, array);
        (callout.callout_fn)(data);
    }
}
