use std::collections::VecDeque;
use std::sync::Mutex;

use super::callout_data::CalloutData;
use super::net_buffer::{NetBuffer, NetBufferList, NetworkAllocator, NET_BUFFER_LIST};

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

    /// Copies `net_buffer` for a later transport injection. The real one also keeps the remote
    /// address and the control data in the copy; the mock injector reads neither.
    pub fn from_ale_callout(
        ipv6: bool,
        _callout_data: &CalloutData,
        net_buffer: &NetBuffer,
        net_allocator: &NetworkAllocator,
        _remote_ip_slice: &[u8],
        inbound: bool,
        _interface_index: u32,
        _sub_interface_index: u32,
    ) -> Result<TransportPacketList, String> {
        Ok(TransportPacketList {
            net_buffer_list_queue: net_buffer.clone_as_nbl(net_allocator)?,
            ipv6,
            inbound,
        })
    }
}

impl Default for Injector {
    fn default() -> Self {
        Self::new()
    }
}
