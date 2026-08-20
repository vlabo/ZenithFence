use core::sync::atomic::Ordering;

use crate::connection::{Connection, ConnectionV4, ConnectionV6, Direction, Key, Verdict};
use crate::device::{Device, Packet};

use crate::dbg;
use crate::id_cache;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv6Address, IPV4_HEADER_LEN, IPV6_HEADER_LEN,
};
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

    fn is_loopback(&self) -> bool {
        match (self.local_ip, self.remote_ip) {
            (IpAddress::Ipv4(local), IpAddress::Ipv4(remote)) => {
                local.is_loopback() || remote.is_loopback()
            }
            (IpAddress::Ipv6(local), IpAddress::Ipv6(remote)) => {
                local.is_loopback() || remote.is_loopback()
            }
            _ => false,
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

    ale_layer_auth_outbound(data, ale_data);
}

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
    ale_layer_auth_inbound(data, ale_data);
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

    ale_layer_auth_outbound(data, ale_data);
}

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
    ale_layer_auth_inbound(data, ale_data);
}

// Outbound connections (ALE Auth Connect layers).
//
// The ALE layer runs *before* the packet layer for outbound traffic, so permitting here means the
// packet layer gets the chance to send the real packet to user space and reinject it.
fn ale_layer_auth_outbound(mut data: CalloutData, ale_data: AleLayerData) {
    crate::trace!(
        "ALE Outbound: {} PID: {} reauth: {}",
        ale_data.as_key(),
        ale_data.process_id,
        ale_data.reauthorize
    );

    let Some(device) = crate::entry::get_device() else {
        return;
    };

    // Never pend once the teardown has started. The packet cache is being drained and user space
    // is gone, so a pend made now would never be answered: its IRP would stay alive inside a
    // callout that is about to be unregistered, leaving the connecting thread stuck in the kernel.
    // Permit instead, the filters are being removed anyway.
    if device.is_shutting_down() {
        // This makes the connections created between driver unload and system shutdown invisible to user-space.
        // TODO: Is there anything we can do about it?
        data.action_permit();
        return;
    }

    // Only TCP and UDP are associated with a connection and handled here. Everything else is
    // permitted and handled by the packet layer.
    if !matches!(ale_data.protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        crate::trace!(
            "ALE {}: protocol {} -> permit, packet layer decides",
            ale_data.direction,
            ale_data.protocol
        );
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
            // A verdict exists:
            // Temporary verdicts are applied in the packet layer
            Verdict::Accept
            | Verdict::RedirectNameServer
            | Verdict::RedirectTunnel
            | Verdict::Block
            | Verdict::Drop => {
                data.action_permit();
            }
            // Permanent verdicts are applied here.
            Verdict::PermanentAccept => {
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
            // reauthorization. Resetting all filters to release it later works (that is what the
            // inbound path does) but the outbound packet layer runs after this one and can hold the
            // real packet without any of that, so it is the cheaper way round here. Just capture
            // the process id, inform user space with an info-only event (missing packet id) and
            // permit. The packet layer sends the real packet and reinjects it after the verdict.
            crate::dbg!(
                "reauthorized connection: {} PID: {}",
                key,
                ale_data.process_id
            );
            add_connection(device, &key, &ale_data, None);
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
            match save_packet_outbound(device, &mut data, &ale_data) {
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
            add_connection(device, &key, &ale_data, None);

            // Drop the packet. It will be re-injected after user space returns a verdict.
            data.block_and_absorb();
        }
    }
}

// Inbound connections (ALE Auth Recv-Accept layers).
//
// Note that the ordering is the opposite of the outbound case: the inbound packet layer runs
// *before* this layer, and it only forwards packets that have no connection in the cache. So this
// callout is the entry point for new inbound connections; once a cache entry exists, following
// packets are handled by the packet layer and mostly never reach this layer.
fn ale_layer_auth_inbound(mut data: CalloutData, ale_data: AleLayerData) {
    crate::trace!(
        "ALE Inbound: {} PID: {} reauth: {}",
        ale_data.as_key(),
        ale_data.process_id,
        ale_data.reauthorize
    );

    let Some(device) = crate::entry::get_device() else {
        return;
    };

    // Never pend once the teardown has started. The packet cache is being drained and user space
    // is gone, so a pend made now would never be answered: its IRP would stay alive inside a
    // callout that is about to be unregistered, leaving the accepting thread stuck in the kernel.
    // Permit instead, the filters are being removed anyway.
    if device.is_shutting_down() {
        // This makes the connections created between driver unload and system shutdown invisible to user-space.
        // TODO: Is there anything we can do about it?
        data.action_permit();
        return;
    }

    // Only TCP and UDP are associated with a connection and handled here. Everything else was
    // already handled by the packet layer.
    if !matches!(ale_data.protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        crate::trace!(
            "ALE {}: protocol {} -> permit, packet layer decides",
            ale_data.direction,
            ale_data.protocol
        );
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
            // No verdict yet: the connection is already pended and user space has not decided.
            // Save this packet too so it is sent to user space and reinjected with the verdict.
            Verdict::Undecided => {
                crate::dbg!("saving packet: {}", key);
                match save_packet_inbound(device, &mut data, &ale_data, false) {
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
                data.block_and_absorb();
            }
            // Accepting verdicts continue to the packet layer, which applies the redirects and
            // keeps counting bandwidth.
            Verdict::PermanentAccept
            | Verdict::Accept
            | Verdict::RedirectNameServer
            | Verdict::RedirectTunnel => {
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
            // Unlike the outbound case, blocking temporary verdicts are enforced here: the packet
            // layer already ran for this packet, so permitting would let it through.
            Verdict::Block => {
                data.action_block();
            }
            Verdict::Drop => {
                data.block_and_absorb();
            }
        }
    } else {
        // Special case for incoming loopback connections.
        if ale_data.is_loopback() {
            // Pending an inbound loopback connection does not work. Set the verdict to accept and
            // send an info-only event (missing packet id, nothing to reinject) to user space.
            crate::dbg!(
                "loopback inbound connection: {} PID: {}",
                key,
                ale_data.process_id
            );
            add_connection(device, &key, &ale_data, Some(Verdict::Accept));

            if let Some(info) =
                id_cache::build_info_only(&key, ale_data.process_id, ale_data.direction)
            {
                let _ = device.event_queue.push(info);
            }

            data.action_permit();
            return;
        }

        // Only the first packet of a connection can be pended: reauthorize == false. A
        // reauthorized connection has no completion handle, so the packet is instead held by
        // resetting all filters once the verdict arrives (see `pend_filter_rest`). That reset
        // opens a WFP write transaction, of which only one can be open at a time, so it can lose
        // the race against a concurrent reset; the verdict path queues those and retries them
        // (see `Device::reset_filters_and_inject`) instead of dropping the packet.
        crate::dbg!("pending connection: {} {}", key, ale_data.direction);
        let can_pend_connection = !ale_data.reauthorize;
        match save_packet_inbound(device, &mut data, &ale_data, can_pend_connection) {
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

        // Connection is not in cache, add it.
        crate::dbg!("adding connection: {} PID: {}", key, ale_data.process_id);
        add_connection(device, &key, &ale_data, None);

        // Drop the packet. It will be re-injected after user space returns a verdict.
        data.block_and_absorb();
    }
}

fn add_connection(device: &Device, key: &Key, ale_data: &AleLayerData, verdict: Option<Verdict>) {
    if ale_data.is_ipv6 {
        if let Ok(conn) = ConnectionV6::from_key(key, ale_data.process_id, ale_data.direction) {
            if let Some(verdict) = verdict {
                conn.set_verdict(verdict);
            }
            device.connection_cache.add_v6(conn);
        } else {
            crate::err!("failed to add ipv6 connection");
        }
    } else {
        if let Ok(conn) = ConnectionV4::from_key(key, ale_data.process_id, ale_data.direction) {
            if let Some(verdict) = verdict {
                conn.set_verdict(verdict);
            }
            device.connection_cache.add_v4(conn);
        } else {
            crate::err!("failed to add ipv4 connection");
        }
    }
}

// Pends the outbound connect operation, capturing the packet so it can be reinjected after the
// verdict. Only called for a genuine new connection (reauthorize == false).
fn save_packet_outbound(
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

// Captures the inbound packet so it can be reinjected after the verdict.
//
// `pend` selects how the operation is deferred: with a completion handle (only available when
// reauthorize == false) or, when there is none, by resetting the filters once the verdict arrives.
fn save_packet_inbound(
    device: &Device,
    callout_data: &mut CalloutData,
    ale_data: &AleLayerData,
    pend: bool,
) -> Result<Packet, alloc::string::String> {
    // Inbound packets always carry data, unlike the connect state of an outbound TCP connection.
    let packet_list = create_packet_list(device, callout_data, ale_data);

    if pend {
        match callout_data.pend_operation(packet_list) {
            Ok(classify_defer) => Ok(Packet::AleLayer(classify_defer)),
            Err(err) => Err(alloc::format!("failed to defer connection: {}", err)),
        }
    } else {
        Ok(Packet::AleLayer(callout_data.pend_filter_rest(packet_list)))
    }
}

fn create_packet_list(
    device: &Device,
    callout_data: &mut CalloutData,
    ale_data: &AleLayerData,
) -> Option<TransportPacketList> {
    let nbl = NetBufferList::new(callout_data.get_layer_data() as _);

    // The ALE layers hand over a single packet, so only the first net buffer of the list is ever
    // relevant here (unlike the packet layers, which walk the whole chain).
    let Some(mut nb) = nbl.iter_net_buffers().next() else {
        crate::err!("no net buffer in ale layer data");
        return None;
    };

    let mut inbound = false;
    if let Direction::Inbound = ale_data.direction {
        // At this layer the net buffer starts at the transport payload. Retreat it back over the
        // transport and IP headers so the whole packet can be cloned and reinjected. The net
        // buffer will auto advance after it loses scope.
        //
        // The IP header is not a fixed size: IPv4 may carry options and IPv6 a chain of extension
        // headers. WFP reports the real size in the ip header size metadata field; fall back to
        // the fixed length only when the field is absent, and ignore values smaller than it as
        // malformed (same handling as the inbound packet layer).
        let fixed_ip_header_len = if ale_data.is_ipv6 {
            IPV6_HEADER_LEN as u32
        } else {
            IPV4_HEADER_LEN as u32
        };
        let ip_header_size = match callout_data.get_ip_header_size() {
            Some(size) if size >= fixed_ip_header_len => size,
            _ => fixed_ip_header_len,
        };
        let retreat_size = ip_header_size + callout_data.get_transport_header_size();
        // A failed retreat leaves the offset at the transport header, so the clone would be
        // missing the headers it has to be reinjected with.
        if let Err(err) = nb.retreat(retreat_size, true) {
            crate::err!("failed to retreat net buffer: {}", err);
            return None;
        }
        inbound = true;
    }

    let address: &[u8] = match &ale_data.remote_ip {
        IpAddress::Ipv4(address) => &address.octets(),
        IpAddress::Ipv6(address) => &address.octets(),
    };
    if let Ok(clone) = nb.clone_as_nbl(&device.network_allocator) {
        return Some(Injector::from_ale_callout(
            ale_data.is_ipv6,
            callout_data,
            clone,
            address,
            inbound,
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
                dbg!(
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
                dbg!(
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
                dbg!(
                    "Port {}/{} ipv4 released pid={}",
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
                dbg!(
                    "Port {}/{} ipv6 released pid={}",
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
