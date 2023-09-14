use super::{ffi, layer::Layer};
use crate::{filter_engine::FilterEngineInternal, utils::CallData};
use alloc::{borrow::ToOwned, format, string::String};

pub struct Callout {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) guid: u128,
    pub(crate) layer: Layer,
    pub(crate) action: u32,
    pub(crate) registerd: bool,
    pub(crate) filter_id: u64,
    pub(crate) callout_id: u32,
    pub(crate) callout_fn: fn(CallData),
}

impl Callout {
    pub fn new(
        name: &str,
        description: &str,
        guid: u128,
        layer: Layer,
        action: u32,
        callout_fn: fn(CallData),
    ) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            guid,
            layer,
            action,
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
            self.action,
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
        callout_fn: ffi::CalloutFunctionType,
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
