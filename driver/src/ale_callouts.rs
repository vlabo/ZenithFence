use core::sync::atomic::Ordering;

use crate::connection::{Connection, ConnectionV4, ConnectionV6, Direction, Key, Verdict};
use crate::device::{Device, Packet};

use crate::id_cache;
use crate::info;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{
    self, FieldsAleAuthConnectV4, FieldsAleAuthConnectV6, FieldsAleAuthRecvAcceptV4,
    FieldsAleAuthRecvAcceptV6, ValueType,
};
use wdk::filter_engine::net_buffer::NetBufferList;
use wdk::filter_engine::packet::{Injector, TransportPacketList};

// ALE Layers

#[derive(Debug)]
#[allow(dead_code)]
struct AleLayerData {
    is_ipv6: bool,
    reauthorize: bool,
    process_id: u64,
    protocol: IpProtocol,
    direction: Direction,
    local_ip: IpAddress,
    local_port: u16,
    remote_ip: IpAddress,
    remote_port: u16,
    interface_index: u32,
    sub_interface_index: u32,
}

impl AleLayerData {
    fn as_key(&self) -> Key {
        let mut local_port = 0;
        let mut remote_port = 0;
        match self.protocol {
            IpProtocol::Tcp | IpProtocol::Udp => {
                local_port = self.local_port;
                remote_port = self.remote_port;
            }
            _ => {}
        }

        Key {
            protocol: self.protocol,
            local_address: self.local_ip,
            local_port,
            remote_address: self.remote_ip,
            remote_port,
        }
    }
}

fn get_protocol(data: &CalloutData, index: usize) -> IpProtocol {
    IpProtocol::from(data.get_value_u8(index))
}

fn get_ipv4_address(data: &CalloutData, index: usize) -> IpAddress {
    IpAddress::Ipv4(Ipv4Address::from_octets(
        data.get_value_u32(index).to_be_bytes(),
    ))
}

fn get_ipv6_address(data: &CalloutData, index: usize) -> IpAddress {
    IpAddress::Ipv6(Ipv6Address::from_octets(
        *data.get_value_byte_array16(index),
    ))
}

pub fn ale_layer_connect_v4(data: CalloutData) {
    type Fields = FieldsAleAuthConnectV4;
    let ale_data = AleLayerData {
        is_ipv6: false,
        reauthorize: data.is_reauthorize(Fields::Flags as usize),
        process_id: data.get_process_id().unwrap_or(0),
        protocol: get_protocol(&data, Fields::IpProtocol as usize),
        direction: Direction::Outbound,
        local_ip: get_ipv4_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv4_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        interface_index: 0,
        sub_interface_index: 0,
    };

    ale_layer_auth(data, ale_data);
}

// Inbound ALE layer is currently disabled (its callout is not registered, see callouts.rs).
// Inbound connections are handled entirely by the packet layer. These accept callouts are kept
// for reference, but note that `ale_layer_auth` has since been simplified to the outbound path
// only, so re-enabling the inbound ALE layer also requires restoring its inbound handling.
#[allow(dead_code)]
pub fn ale_layer_accept_v4(data: CalloutData) {
    type Fields = FieldsAleAuthRecvAcceptV4;
    let ale_data = AleLayerData {
        is_ipv6: false,
        reauthorize: data.is_reauthorize(Fields::Flags as usize),
        process_id: data.get_process_id().unwrap_or(0),
        protocol: get_protocol(&data, Fields::IpProtocol as usize),
        direction: Direction::Inbound,
        local_ip: get_ipv4_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv4_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        interface_index: data.get_value_u32(Fields::InterfaceIndex as usize),
        sub_interface_index: data.get_value_u32(Fields::SubInterfaceIndex as usize),
    };
    ale_layer_auth(data, ale_data);
}

pub fn ale_layer_connect_v6(data: CalloutData) {
    type Fields = FieldsAleAuthConnectV6;

    let ale_data = AleLayerData {
        is_ipv6: true,
        reauthorize: data.is_reauthorize(Fields::Flags as usize),
        process_id: data.get_process_id().unwrap_or(0),
        protocol: get_protocol(&data, Fields::IpProtocol as usize),
        direction: Direction::Outbound,
        local_ip: get_ipv6_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv6_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        interface_index: data.get_value_u32(Fields::InterfaceIndex as usize),
        sub_interface_index: data.get_value_u32(Fields::SubInterfaceIndex as usize),
    };

    ale_layer_auth(data, ale_data);
}

// Disabled together with `ale_layer_accept_v4`; kept for the same reason.
#[allow(dead_code)]
pub fn ale_layer_accept_v6(data: CalloutData) {
    type Fields = FieldsAleAuthRecvAcceptV6;
    let ale_data = AleLayerData {
        is_ipv6: true,
        reauthorize: data.is_reauthorize(Fields::Flags as usize),
        process_id: data.get_process_id().unwrap_or(0),
        protocol: get_protocol(&data, Fields::IpProtocol as usize),
        direction: Direction::Inbound,
        local_ip: get_ipv6_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv6_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        interface_index: data.get_value_u32(Fields::InterfaceIndex as usize),
        sub_interface_index: data.get_value_u32(Fields::SubInterfaceIndex as usize),
    };
    ale_layer_auth(data, ale_data);
}

fn ale_layer_auth(mut data: CalloutData, ale_data: AleLayerData) {
    let Some(device) = crate::entry::get_device() else {
        return;
    };

    // Only TCP and UDP are associated with a connection and handled here. Everything else is
    // permitted and handled by the packet layer.
    if !matches!(ale_data.protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        data.action_permit();
        return;
    }

    let key = ale_data.as_key();

    // Check if connection is already in cache.
    let verdict = device.connection_cache.get_verdict(&key);

    // Connection already in cache.
    if let Some(verdict) = verdict {
        crate::dbg!("processing existing connection: {} {}", key, verdict);
        match verdict {
            // No verdict yet. User space may not know about this connection at all (e.g. it
            // existed before the driver was loaded), so send an info-only event that carries the
            // process id (missing packet id, nothing to reinject) and permit. The packet layer
            // sends the real packet and applies the actual verdict after user space decides.
            Verdict::Undecided => {
                if let Some(info) =
                    id_cache::build_info_only(&key, ale_data.process_id, ale_data.direction)
                {
                    let _ = device.event_queue.push(info);
                }
                data.action_permit();
            }
            // A verdict exists: let the packet layer enforce it. For outbound connections the
            // temporary verdicts (Accept, Block, Drop) and the redirects are all applied there.
            Verdict::PermanentAccept
            | Verdict::Accept
            | Verdict::RedirectNameServer
            | Verdict::RedirectTunnel
            | Verdict::Block
            | Verdict::Drop => {
                data.action_permit();
            }
            Verdict::PermanentBlock | Verdict::Undeterminable | Verdict::Failed => {
                // Packet layer will not see this connection.
                crate::dbg!("permanent block {}", key);
                data.action_block();
            }
            Verdict::PermanentDrop => {
                // Packet layer will not see this connection.
                crate::dbg!("permanent drop {}", key);
                data.block_and_absorb();
            }
        }
    } else {
        // New connection.
        if ale_data.reauthorize {
            // A reauthorized connection cannot be pended: there is no completion handle during
            // reauthorization, and resetting all filters to apply the verdict later races into
            // STATUS_FWP_TXN_IN_PROGRESS (see device.rs inject_packet). Just capture the process
            // id, inform user space with an info-only event (missing packet id) and permit. The
            // packet layer sends the real packet and reinjects it after the verdict.
            crate::dbg!(
                "reauthorized connection: {} PID: {}",
                key,
                ale_data.process_id
            );
            add_connection(device, &key, &ale_data);
            if let Some(info) =
                id_cache::build_info_only(&key, ale_data.process_id, ale_data.direction)
            {
                let _ = device.event_queue.push(info);
            }
            data.action_permit();
        } else {
            // First packet of a new connection (a genuine connect()). Pend it so the verdict can
            // be returned as the result of the connect call; the packet is reinjected once user
            // space decides.
            crate::dbg!("pending connection: {} PID: {}", key, ale_data.process_id);
            match save_packet(device, &mut data, &ale_data) {
                Ok(packet) => {
                    let info = device.packet_cache.push(
                        (key, packet),
                        ale_data.process_id,
                        ale_data.direction,
                        true,
                    );
                    if let Some(info) = info {
                        let _ = device.event_queue.push(info);
                    }
                }
                Err(err) => {
                    crate::err!("failed to pend packet: {}", err);
                }
            };
            add_connection(device, &key, &ale_data);

            // Drop the packet. It will be re-injected after user space returns a verdict.
            data.block_and_absorb();
        }
    }
}

// Adds a new connection to the cache for the given key.
fn add_connection(device: &Device, key: &Key, ale_data: &AleLayerData) {
    if ale_data.is_ipv6 {
        let conn = ConnectionV6::from_key(key, ale_data.process_id, ale_data.direction).unwrap();
        device.connection_cache.add_v6(conn);
    } else {
        let conn = ConnectionV4::from_key(key, ale_data.process_id, ale_data.direction).unwrap();
        device.connection_cache.add_v4(conn);
    }
}

// Pends the outbound connect operation, capturing the packet so it can be reinjected after the
// verdict. Only called for a genuine new connection (reauthorize == false).
fn save_packet(
    device: &Device,
    callout_data: &mut CalloutData,
    ale_data: &AleLayerData,
) -> Result<Packet, alloc::string::String> {
    // During the connect state of an outbound TCP connection there is no packet data yet, so
    // nothing is captured. UDP carries the datagram, which is captured for reinjection.
    let packet_list = match ale_data.protocol {
        IpProtocol::Udp => create_packet_list(device, callout_data, ale_data),
        _ => None,
    };
    match callout_data.pend_operation(packet_list) {
        Ok(classify_defer) => Ok(Packet::AleLayer(classify_defer)),
        Err(err) => Err(alloc::format!("failed to defer connection: {}", err)),
    }
}

fn create_packet_list(
    device: &Device,
    callout_data: &mut CalloutData,
    ale_data: &AleLayerData,
) -> Option<TransportPacketList> {
    // Outbound only: no header retreat is needed (that was required for inbound packets).
    let nbl = NetBufferList::new(callout_data.get_layer_data() as _);

    let address: &[u8] = match &ale_data.remote_ip {
        IpAddress::Ipv4(address) => &address.octets(),
        IpAddress::Ipv6(address) => &address.octets(),
    };
    if let Ok(clone) = nbl.clone(&device.network_allocator) {
        return Some(Injector::from_ale_callout(
            ale_data.is_ipv6,
            callout_data,
            clone,
            address,
            false, // outbound
            ale_data.interface_index,
            ale_data.sub_interface_index,
        ));
    }
    return None;
}

pub fn endpoint_closure_v4(data: CalloutData) {
    type Fields = layer::FieldsAleEndpointClosureV4;
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    let ip_address_type = data.get_value_type(Fields::IpLocalAddress as usize);
    if let ValueType::FwpUint32 = ip_address_type {
        let key = Key {
            protocol: get_protocol(&data, Fields::IpProtocol as usize),
            local_address: get_ipv4_address(&data, Fields::IpLocalAddress as usize),
            local_port: data.get_value_u16(Fields::IpLocalPort as usize),
            remote_address: get_ipv4_address(&data, Fields::IpRemoteAddress as usize),
            remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        };

        if let Some(conn) = device.connection_cache.end_v4(key) {
            let info = protocol::info::connection_end_event_v4_info(
                data.get_process_id().unwrap_or(0),
                conn.get_direction() as u8,
                u8::from(get_protocol(&data, Fields::IpProtocol as usize)),
                conn.local_address.octets(),
                conn.remote_address.octets(),
                conn.local_port,
                conn.remote_port,
                conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
            );
            let _ = device.event_queue.push(info);
        }
    } else {
        // Invalid ip address type. Just ignore the error.
        // err!(
        //     device.logger,
        //     "unknown ipv4 address type: {:?}",
        //     ip_address_type
        // );
    }
}

pub fn endpoint_closure_v6(data: CalloutData) {
    type Fields = layer::FieldsAleEndpointClosureV6;
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    let local_ip_address_type = data.get_value_type(Fields::IpLocalAddress as usize);
    let remote_ip_address_type = data.get_value_type(Fields::IpRemoteAddress as usize);

    if let ValueType::FwpByteArray16Type = local_ip_address_type {
        if let ValueType::FwpByteArray16Type = remote_ip_address_type {
            let key = Key {
                protocol: get_protocol(&data, Fields::IpProtocol as usize),
                local_address: get_ipv6_address(&data, Fields::IpLocalAddress as usize),
                local_port: data.get_value_u16(Fields::IpLocalPort as usize),
                remote_address: get_ipv6_address(&data, Fields::IpRemoteAddress as usize),
                remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
            };

            if let Some(conn) = device.connection_cache.end_v6(key) {
                let info = protocol::info::connection_end_event_v6_info(
                    data.get_process_id().unwrap_or(0),
                    conn.get_direction() as u8,
                    u8::from(get_protocol(&data, Fields::IpProtocol as usize)),
                    conn.local_address.octets(),
                    conn.remote_address.octets(),
                    conn.local_port,
                    conn.remote_port,
                    conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                    conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                    conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                    conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
                );
                let _ = device.event_queue.push(info);
            }
        }
    }
}

pub fn ale_resource_monitor(data: CalloutData) {
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    match data.layer {
        layer::Layer::AleResourceAssignmentV4Discard => {
            type Fields = layer::FieldsAleResourceAssignmentV4;
            if let Some(conns) = device.connection_cache.end_all_on_port_v4((
                get_protocol(&data, Fields::IpProtocol as usize),
                data.get_value_u16(Fields::IpLocalPort as usize),
            )) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    "Port {}/{} Ipv4 assign request discarded pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = protocol::info::connection_end_event_v4_info(
                        process_id,
                        conn.get_direction() as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.octets(),
                        conn.remote_address.octets(),
                        conn.local_port,
                        conn.remote_port,
                        conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
                    );
                    let _ = device.event_queue.push(info);
                }
            }
        }
        layer::Layer::AleResourceAssignmentV6Discard => {
            type Fields = layer::FieldsAleResourceAssignmentV6;
            if let Some(conns) = device.connection_cache.end_all_on_port_v6((
                get_protocol(&data, Fields::IpProtocol as usize),
                data.get_value_u16(Fields::IpLocalPort as usize),
            )) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    "Port {}/{} Ipv6 assign request discarded pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = protocol::info::connection_end_event_v6_info(
                        process_id,
                        conn.get_direction() as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.octets(),
                        conn.remote_address.octets(),
                        conn.local_port,
                        conn.remote_port,
                        conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
                    );
                    let _ = device.event_queue.push(info);
                }
            }
        }
        layer::Layer::AleResourceReleaseV4 => {
            type Fields = layer::FieldsAleResourceReleaseV4;
            if let Some(conns) = device.connection_cache.end_all_on_port_v4((
                get_protocol(&data, Fields::IpProtocol as usize),
                data.get_value_u16(Fields::IpLocalPort as usize),
            )) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    "Port {}/{} released pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = protocol::info::connection_end_event_v4_info(
                        process_id,
                        conn.get_direction() as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.octets(),
                        conn.remote_address.octets(),
                        conn.local_port,
                        conn.remote_port,
                        conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
                    );
                    let _ = device.event_queue.push(info);
                }
            }
        }
        layer::Layer::AleResourceReleaseV6 => {
            type Fields = layer::FieldsAleResourceReleaseV6;
            if let Some(conns) = device.connection_cache.end_all_on_port_v6((
                get_protocol(&data, Fields::IpProtocol as usize),
                data.get_value_u16(Fields::IpLocalPort as usize),
            )) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    "Port {}/{} released pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = protocol::info::connection_end_event_v6_info(
                        process_id,
                        conn.get_direction() as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.octets(),
                        conn.remote_address.octets(),
                        conn.local_port,
                        conn.remote_port,
                        conn.bandwidth_usage.rx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.rx_packets.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_bytes.load(Ordering::SeqCst),
                        conn.bandwidth_usage.tx_packets.load(Ordering::SeqCst),
                    );
                    let _ = device.event_queue.push(info);
                }
            }
        }
        _ => {}
    }
}
