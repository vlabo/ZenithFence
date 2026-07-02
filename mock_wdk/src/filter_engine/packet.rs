use std::collections::VecDeque;
use std::sync::Mutex;

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

/// One packet the driver handed to the injector, as a harness can observe it.
/// `transport` distinguishes the ALE/transport-layer inject (a pended flow's
/// first packet being released) from the network/packet-layer inject (a cloned
/// or redirected IP packet). `loopback` is only meaningful for network injects.
#[derive(Clone)]
pub struct InjectedPacket {
    pub ipv6: bool,
    pub inbound: bool,
    pub loopback: bool,
    pub transport: bool,
    pub data: Vec<u8>,
}

/// Host mock of `wdk::filter_engine::packet::Injector`.
///
/// The kernel version hands packets back to the network stack; the mock records
/// them instead, so a harness can drain the queue and — mimicking the OS — feed
/// them back through the packet-layer callouts (see the sim's reinjector).
pub struct Injector {
    injected: Mutex<VecDeque<InjectedPacket>>,
}

impl Injector {
    pub fn new() -> Self {
        Injector {
            injected: Mutex::new(VecDeque::new()),
        }
    }

    pub fn was_network_packet_injected_by_self(
        &self,
        nbl: *const NET_BUFFER_LIST,
        ipv6: bool,
    ) -> bool {
        // The real check queries FWPS per injection handle: the v4 and v6
        // network handles are distinct, so a marked packet of the wrong family
        // reports NOT_INJECTED. The mock stores the mark (with its family) on
        // the NBL itself.
        unsafe {
            match nbl.as_ref() {
                Some(nbl) => matches!(nbl.injected_by_self, Some(family) if family == ipv6),
                None => false,
            }
        }
    }

    pub fn was_network_packet_injected_by_self_ale(&self, _nbl: *const NET_BUFFER_LIST) -> bool {
        // Transport-handle injection state: packets the mock harness replays at
        // the packet layer were network-injected (or fresh), never transport
        // ones (a transport re-inject reaches the network layer as
        // INJECTED_BY_OTHER, which maps to false).
        false
    }

    pub fn inject_net_buffer_list(
        &self,
        net_buffer_list: NetBufferList,
        inject_info: InjectInfo,
    ) -> Result<(), String> {
        // Network injects always carry an owned clone (the driver clones before
        // pending); one that lost its bytes is a bug worth failing on.
        let Some(data) = net_buffer_list.get_data() else {
            return Err("inject_net_buffer_list: no owned packet data".to_string());
        };
        if data.is_empty() {
            return Err("inject_net_buffer_list: empty packet".to_string());
        }
        self.push(InjectedPacket {
            ipv6: inject_info.ipv6,
            inbound: inject_info.inbound,
            loopback: inject_info.loopback,
            transport: false,
            data: data.to_vec(),
        });
        Ok(())
    }

    pub fn inject_packet_list_transport(
        &self,
        packet_list: TransportPacketList,
    ) -> Result<(), String> {
        // ALE defers for outbound TCP connects legitimately carry no packet
        // data (the connect had none); nothing to record then.
        if let Some(data) = packet_list.net_buffer_list_queue.get_data() {
            if !data.is_empty() {
                self.push(InjectedPacket {
                    ipv6: packet_list.ipv6,
                    inbound: packet_list.inbound,
                    loopback: false,
                    transport: true,
                    data: data.to_vec(),
                });
            }
        }
        Ok(())
    }

    /// Take every packet injected since the last drain, in injection order.
    pub fn drain_injected(&self) -> Vec<InjectedPacket> {
        match self.injected.lock() {
            Ok(mut queue) => queue.drain(..).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Number of injected packets not yet drained.
    pub fn injected_len(&self) -> usize {
        self.injected.lock().map(|queue| queue.len()).unwrap_or(0)
    }

    fn push(&self, packet: InjectedPacket) {
        if let Ok(mut queue) = self.injected.lock() {
            queue.push_back(packet);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn info(ipv6: bool, inbound: bool) -> InjectInfo {
        InjectInfo {
            ipv6,
            inbound,
            loopback: false,
            interface_index: 0,
            sub_interface_index: 0,
            compartment_id: 0,
        }
    }

    #[test]
    fn network_inject_records_and_drains() {
        let injector = Injector::new();
        let nbl = NetBufferList::owned_from_bytes(vec![1, 2, 3]);
        injector.inject_net_buffer_list(nbl, info(false, true)).expect("inject");
        assert_eq!(injector.injected_len(), 1);
        let packets = injector.drain_injected();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].data, vec![1, 2, 3]);
        assert!(packets[0].inbound);
        assert!(!packets[0].ipv6);
        assert!(!packets[0].transport);
        assert_eq!(injector.injected_len(), 0);
    }

    #[test]
    fn network_inject_without_data_fails() {
        let injector = Injector::new();
        let nbl = NetBufferList::new(core::ptr::null_mut()); // borrowed, no bytes
        assert!(injector.inject_net_buffer_list(nbl, info(false, false)).is_err());
    }

    #[test]
    fn transport_inject_without_data_is_ok_and_records_nothing() {
        let injector = Injector::new();
        let packet_list = TransportPacketList {
            net_buffer_list_queue: NetBufferList::new(core::ptr::null_mut()),
            ipv6: false,
            inbound: false,
        };
        injector.inject_packet_list_transport(packet_list).expect("inject");
        assert_eq!(injector.injected_len(), 0);
    }

    #[test]
    fn self_inject_mark_honors_family() {
        let injector = Injector::new();
        let marked_v4 = NET_BUFFER_LIST::new_box_injected(vec![0u8; 20], 0, false);
        let raw = marked_v4.as_ref() as *const NET_BUFFER_LIST;
        assert!(injector.was_network_packet_injected_by_self(raw, false));
        assert!(!injector.was_network_packet_injected_by_self(raw, true), "wrong family");

        let unmarked = NET_BUFFER_LIST::new_box(vec![0u8; 20], 0);
        let raw = unmarked.as_ref() as *const NET_BUFFER_LIST;
        assert!(!injector.was_network_packet_injected_by_self(raw, false));
        assert!(!injector.was_network_packet_injected_by_self(core::ptr::null(), false));
    }
}
