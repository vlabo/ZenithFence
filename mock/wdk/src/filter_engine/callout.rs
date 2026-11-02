use super::callout_data::CalloutData;
use super::layer::Layer;

pub enum FilterType {
    Resettable,
    NonResettable,
}

/// Host mock of `wdk::filter_engine::callout::Callout`. Stores the same fields
/// the driver passes to `Callout::new` (in particular the `callout_fn` pointer,
/// whose type must match so `callouts::get_callout_vec` type-checks).
/// Registration is a no-op handled by the mock `FilterEngine`.
pub struct Callout {
    pub name: String,
    pub description: String,
    pub guid: u128,
    pub layer: Layer,
    pub action: u32,
    pub filter_type: FilterType,
    pub callout_fn: fn(CalloutData),
}

impl Callout {
    pub fn new(
        name: &str,
        description: &str,
        guid: u128,
        layer: Layer,
        action: u32,
        filter_type: FilterType,
        callout_fn: fn(CalloutData),
    ) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            guid,
            layer,
            action,
            filter_type,
            callout_fn,
        }
    }
}
