use super::layer::FwpsIncomingValues;
use super::{ffi, layer::Layer};
use crate::{filter_engine::FilterEngineInternal, utils::CallData};
use alloc::{borrow::ToOwned, format, string::String};
use winapi::shared::ntdef::{PCVOID, PVOID};

pub struct Callout {
    pub name: String,
    pub description: String,
    pub guid: u128,
    pub layer: Layer,
    pub registerd: bool,
    pub filter_id: u64,
    pub callout_id: u32,
    pub callout_fn: fn(CallData),
}

impl Callout {
    pub fn new(
        name: &str,
        description: &str,
        guid: u128,
        layer: Layer,
        callout_fn: fn(CallData),
    ) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            guid,
            layer,
            registerd: false,
            filter_id: 0,
            callout_id: 0,
            callout_fn,
        }
    }

    pub fn register_filter(&mut self, filter_engine: &FilterEngineInternal) -> Result<(), String> {
        match ffi::register_filter(
            filter_engine.filter_engine_handle,
            filter_engine.sublayer_guid,
            &format!("{}-filter", self.name),
            &self.description,
            self.guid,
            self.layer,
            crate::consts::FWP_ACTION_CALLOUT_INSPECTION,
        ) {
            Ok(id) => {
                self.filter_id = id;
            }
            Err(error) => {
                return Err(format!("faield to register filter: {}", error));
            }
        };

        return Ok(());
    }

    pub(crate) fn register_callout(
        &mut self,
        filter_engine: &FilterEngineInternal,
        callout_fn: unsafe extern "C" fn(
            *const FwpsIncomingValues,
            PCVOID,
            PVOID,
            PCVOID,
            PCVOID,
            u64,
            PVOID,
        ),
    ) -> Result<(), String> {
        match ffi::register_callout(
            filter_engine.driver.get_wfp_object(),
            filter_engine.filter_engine_handle,
            &format!("{}-callout", self.name),
            &self.description,
            self.guid,
            self.layer,
            callout_fn,
        ) {
            Ok(id) => {
                self.registerd = true;
                self.callout_id = id;
            }
            Err(code) => {
                return Err(format!("faield to register callout: {}", code));
            }
        };
        return Ok(());
    }
}
