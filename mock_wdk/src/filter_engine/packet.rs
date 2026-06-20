use super::callout_data::CalloutData;
use super::net_buffer::{NetBufferList, NET_BUFFER_LIST};

/// Host mock of `wdk::filter_engine::packet::InjectInfo`.
/// `compartment_id` is `i32` to match the real `COMPARTMENT_ID` type alias.
pub struct InjectInfo {
    pub ipv6: bool,
    pub inbound: bool,
    pub loopback: bool,
    pub interface_index: u32,
    pub sub_interface_index: u32,
    pub compartment_id: i32,
}

/// Host mock of `wdk::filter_engine::packet::TransportPacketList`.
/// `net_buffer_list_queue` is public because `id_cache::get_payload` reads it.
#[allow(dead_code)]
pub struct TransportPacketList {
    pub net_buffer_list_queue: NetBufferList,
    pub(crate) ipv6: bool,
    pub(crate) inbound: bool,
}

/// Host mock of `wdk::filter_engine::packet::Injector`. Injection is a no-op;
/// the supplied `NetBufferList`/`TransportPacketList` is simply dropped (which
/// is the right behaviour for a fuzz harness -- we only care that the driver
/// reached the inject call without panicking).
pub struct Injector;

impl Injector {
    pub fn new() -> Self {
        Injector
    }

    pub fn was_network_packet_injected_by_self(
        &self,
        _nbl: *const NET_BUFFER_LIST,
        _ipv6: bool,
    ) -> bool {
        false
    }

    pub fn was_network_packet_injected_by_self_ale(&self, _nbl: *const NET_BUFFER_LIST) -> bool {
        false
    }

    pub fn inject_net_buffer_list(
        &self,
        _net_buffer_list: NetBufferList,
        _inject_info: InjectInfo,
    ) -> Result<(), String> {
        Ok(())
    }

    pub fn inject_packet_list_transport(
        &self,
        _packet_list: TransportPacketList,
    ) -> Result<(), String> {
        Ok(())
    }

    pub fn from_ale_callout(
        ipv6: bool,
        _callout_data: &CalloutData,
        net_buffer_list: NetBufferList,
        _remote_ip_slice: &[u8],
        inbound: bool,
        _interface_index: u32,
        _sub_interface_index: u32,
    ) -> TransportPacketList {
        TransportPacketList {
            net_buffer_list_queue: net_buffer_list,
            ipv6,
            inbound,
        }
    }
}

impl Default for Injector {
    fn default() -> Self {
        Self::new()
    }
}
