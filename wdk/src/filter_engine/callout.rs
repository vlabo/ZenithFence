use super::{callout_data::CalloutData, ffi, layer::Layer};
use crate::{ffi::FwpsCalloutClassifyFn, filter_engine::FilterEngine};
use alloc::{borrow::ToOwned, format, string::String};
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

pub struct Callout {
    pub(crate) id: u32,
    pub(super) index: u64,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) guid: u128,
    pub(crate) layer: Layer,
    pub(crate) action: u32,
    pub(crate) registered: bool,
    pub(crate) filter_id: u64,
    pub(crate) device_object: *mut DEVICE_OBJECT,
    pub(crate) callout_fn: fn(CalloutData, &mut DEVICE_OBJECT),
}

impl Callout {
    pub fn new(
        name: &str,
        description: &str,
        guid: u128,
        layer: Layer,
        action: u32,
        callout_fn: fn(CalloutData, &mut DEVICE_OBJECT),
    ) -> Self {
        Self {
            id: 0,
            index: 0,
            name: name.to_owned(),
            description: description.to_owned(),
            guid,
            layer,
            action,
            registered: false,
            filter_id: 0,
            device_object: core::ptr::null_mut(),
            callout_fn,
        }
    }

    pub fn register_filter(&mut self, filter_engine: &FilterEngine) -> Result<(), String> {
        match ffi::register_filter(
            filter_engine.filter_engine_handle,
            filter_engine.sublayer_guid,
            &format!("{}-filter", self.name),
            &self.description,
            self.guid,
            self.layer,
            self.action,
            self.index,
        ) {
            Ok(id) => {
                self.filter_id = id;
            }
            Err(error) => {
                return Err(format!("failed to register filter: {}", error));
            }
        };

        return Ok(());
    }

    pub(crate) fn register_callout(
        &mut self,
        filter_engine: &FilterEngine,
        callout_fn: FwpsCalloutClassifyFn,
    ) -> Result<(), String> {
        self.device_object = filter_engine.device_object;
        match ffi::register_callout(
            self.device_object,
            filter_engine.filter_engine_handle,
            &format!("{}-callout", self.name),
            &self.description,
            self.guid,
            self.layer,
            callout_fn,
        ) {
            Ok(id) => {
                self.registered = true;
                self.id = id;
            }
            Err(code) => {
                return Err(format!("failed to register callout: {}", code));
            }
        };
        return Ok(());
    }
}
