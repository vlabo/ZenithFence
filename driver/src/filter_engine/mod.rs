use crate::alloc::borrow::ToOwned;
use crate::driver::IO_QUEUE;
use alloc::string::String;
use alloc::{format, vec::Vec};
use data_types::PacketInfo;
use wdk::layer::Layer;
use wdk::utils::Driver;
use wdk::{interface, log};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

// const OUTBOUND_V4_NAME: &str = "PortmasterOutboundV4Filter";
// const OUTBOUND_V4_DESCRIPTION: &str =
//     "This filter is used by the Portmaster to intercept inbound IPv4 traffic.";
// const OUBTOUND_V4_CALLOUT_NAME: &str = "PortmasterInboundV4Callout";
// const OUBTOUND_V4_CALLOUT_DESCRIPTION: &str =
//     "This callout is used by the Portmaster to intercept inbound IPv4 traffic.";
// const OUTBOUND_V4_GUID: GUID = GUID::from_u128(0x05c55149_4732_4857_8d10_f178f3a06f8c);

// const INBOUND_V4_GUID: GUID = GUID::from_u128(0x05c55149_4732_4857_8d10_f178f3a06f8c);

#[no_mangle]
extern "C" fn test_callout(
    _infixed_values: *const u8,
    _in_meta_values: *const u8,
    _layer_data: *mut u8,
    _context: *const u8,
    _filter: *const u8,
    _flow_context: u64,
    _classify_out: *mut u8,
) {
    let packet = PacketInfo {
        id: 1,
        process_id: 2,
        direction: 3,
        ip_v6: false,
        protocol: 4,
        flags: 5,
        local_ip: [1, 2, 3, 4],
        remote_ip: [4, 5, 6, 7],
        local_port: 8,
        remote_port: 9,
        compartment_id: 10,
        interface_index: 11,
        sub_interface_index: 12,
        packet_size: 13,
    };
    unsafe {
        if let Err(err) = IO_QUEUE.push(packet) {
            log!("callout failed to push packet: {}", err);
        }
    }
}

type Guid = u128;

struct Callout {
    name: String,
    description: String,
    guid: Guid,
    layer: Layer,
    registerd: bool,
    filter_id: u64,
    callout_id: u32,
}

pub struct FilterEngine {
    driver: Driver,
    filter_engine_handle: HANDLE,
    callouts: Option<Vec<Callout>>,
    sublayer_guid: Guid,
    commited: bool,
}

impl FilterEngine {
    pub fn new(driver: Driver) -> Result<Self, String> {
        let filter_engine_handle: HANDLE;
        match interface::create_filter_engine() {
            Ok(handle) => {
                filter_engine_handle = handle;
            }
            Err(code) => {
                return Err(format!("failed to initialize filter engine {}", code).to_owned());
            }
        }

        let engine = Self {
            driver,
            filter_engine_handle,
            callouts: Some(Vec::new()),
            sublayer_guid: 0xa87fb472_fc68_4805_8559_c6ae774773e0,
            commited: false,
        };

        return Ok(engine);
    }

    pub fn commit(&mut self) -> Result<(), String> {
        if let Err(code) = interface::filter_engine_transaction_begin(self.filter_engine_handle, 0)
        {
            return Err(format!(
                "filter-engine: faield to begin transaction: {}",
                code
            ));
        }

        if let Err(err) = self.register_sublayer() {
            _ = interface::filter_engine_transaction_abort(self.filter_engine_handle);
            return Err(format!("filter_engine: {}", err));
        }

        // Barrow the callouts vec from the filter engine.
        if let Some(mut callouts) = self.callouts.take() {
            // Register all callouts
            for callout in &mut callouts {
                if let Err(err) = callout.register_callout(self) {
                    // This will destroy the callout structs.
                    _ = interface::filter_engine_transaction_abort(self.filter_engine_handle);
                    return Err(err);
                }
                if let Err(err) = callout.register_filter(self) {
                    // This will destory the callout structs.
                    _ = interface::filter_engine_transaction_abort(self.filter_engine_handle);
                    return Err(err);
                }
            }

            // Return the callout vec to the filter engine
            self.callouts = Some(callouts);
        }

        if let Err(code) = interface::filter_engine_transaction_commit(self.filter_engine_handle) {
            return Err(format!(
                "filter-engine: failed to commit transaction: {}",
                code
            ));
        }

        // TODO: auto abort on error

        self.commited = true;

        return Ok(());
    }

    pub fn register_test_callout(&mut self) {
        if let Err(err) = self.add_callout(
            "TestCallout",
            "Testing callout",
            0x6f996fe2_3a8f_43be_b578_e01480f2b1a1,
            Layer::FwpmLayerOutboundIppacketV4,
        ) {
            log!("filter engine: {}", err);
        }
    }

    fn add_callout(
        &mut self,
        name: &str,
        description: &str,
        guid: Guid,
        layer: Layer,
    ) -> Result<(), String> {
        let callout: Callout = Callout {
            name: name.to_owned(),
            description: description.to_owned(),
            guid,
            layer,
            registerd: false,
            filter_id: 0,
            callout_id: 0,
        };

        if let Some(callouts) = &mut self.callouts {
            callouts.push(callout);
        }
        return Ok(());
    }

    fn register_sublayer(&self) -> Result<(), String> {
        let result = interface::register_sublayer(
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

impl Callout {
    fn register_filter(&mut self, filter_engine: &FilterEngine) -> Result<(), String> {
        match interface::register_filter(
            filter_engine.filter_engine_handle,
            filter_engine.sublayer_guid,
            &format!("{}-filter", self.name),
            &self.description,
            self.guid,
            self.layer,
            wdk::consts::FWP_ACTION_CALLOUT_INSPECTION,
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

    fn register_callout(&mut self, filter_engine: &FilterEngine) -> Result<(), String> {
        match interface::register_callout(
            filter_engine.driver.get_wfp_object(),
            filter_engine.filter_engine_handle,
            &format!("{}-callout", self.name),
            &self.description,
            self.guid,
            self.layer,
            test_callout,
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

impl Drop for FilterEngine {
    fn drop(&mut self) {
        if let Some(callouts) = &mut self.callouts {
            for ele in callouts {
                if ele.registerd {
                    if let Err(code) = interface::unregister_callout(ele.callout_id) {
                        log!("faild to unregister callout: {}", code);
                    }
                    if let Err(code) =
                        interface::unregister_filter(self.filter_engine_handle, ele.filter_id)
                    {
                        log!("failed to unregister filter: {}", code)
                    }
                }
            }
        }

        if self.commited {
            if let Err(code) =
                interface::unregister_sublayer(self.filter_engine_handle, self.sublayer_guid)
            {
                log!("Failed to unregister sublayer: {}", code);
            }
        }

        if self.filter_engine_handle != INVALID_HANDLE_VALUE {
            _ = interface::filter_engine_close(self.filter_engine_handle);
        }
    }
}
