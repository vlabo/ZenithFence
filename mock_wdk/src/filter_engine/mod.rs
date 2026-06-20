pub mod callout;
pub mod callout_data;
pub mod classify;
pub mod layer;
pub mod net_buffer;
pub mod packet;

use crate::driver::Driver;

use self::callout::Callout;

/// Host mock of `wdk::filter_engine::FilterEngine`. Registration is a no-op;
/// it just owns the callout vector so its lifetime matches the real one.
pub struct FilterEngine {
    _callouts: Vec<Callout>,
}

impl FilterEngine {
    pub fn new(_driver: &Driver, _layer_guid: u128) -> Result<Self, String> {
        Ok(FilterEngine {
            _callouts: Vec::new(),
        })
    }

    pub fn commit(&mut self, callouts: Vec<Callout>) -> Result<(), String> {
        self._callouts = callouts;
        Ok(())
    }

    pub fn reset_all_filters(&mut self) -> Result<(), String> {
        Ok(())
    }
}
