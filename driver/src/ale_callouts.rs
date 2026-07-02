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

    ale_layer_auth(data, ale_data);
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

    match ale_data.protocol {
        IpProtocol::Tcp | IpProtocol::Udp => {
            // Only TCP and UDP make sense to be supported in the ALE layer.
            // Everything else is not associated with a connection and will be handled in the packet layer.
        }
        _ => {
            // Outbound: Will be handled by packet layer next.
            // Inbound: Was already handled by the packet layer.
            data.action_permit();
            return;
        }
    }

    let key = ale_data.as_key();

    // Check if connection is already in cache.
    let verdict = device.connection_cache.get_verdict(&key);

    // Connection already in cache.
    if let Some(verdict) = verdict {
        crate::dbg!("processing existing connection: {} {}", key, verdict);
        match verdict {
            // No verdict yet
            Verdict::Undecided => {
                crate::dbg!("saving packet: {}", key);
                // Connection is already pended. Save packet and wait for verdict.
                match save_packet(device, &mut data, &ale_data, false) {
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
            // There is a verdict
            Verdict::PermanentAccept
            | Verdict::Accept
            | Verdict::RedirectNameServer
            | Verdict::RedirectTunnel => {
                // Continue to packet layer.
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
            Verdict::Block => {
                if let Direction::Outbound = ale_data.direction {
                    // Handled by packet layer.
                    data.action_permit();
                } else {
                    // packet layer will still see the packets.
                    data.action_block();
                }
            }
            Verdict::Drop => {
                if let Direction::Outbound = ale_data.direction {
                    // Handled by packet layer.
                    data.action_permit();
                } else {
                    // packet layer will still see the packets.
                    data.block_and_absorb();
                }
            }
        }
    } else {
        // Special case for incoming loopback connection
        if ale_data.is_loopback() && matches!(ale_data.direction, Direction::Inbound) {
            // Pending connection for inbound loopback does not work.
            // Set the verdict to accept and send info only event to userspace.
            crate::dbg!(
                "loopback inbound connection: {} PID: {}",
                key,
                ale_data.process_id
            );
            if ale_data.is_ipv6 {
                let conn =
                    ConnectionV6::from_key(&key, ale_data.process_id, ale_data.direction).unwrap();
                conn.set_verdict(Verdict::Accept);
                device.connection_cache.add_v6(conn);
            } else {
                let conn =
                    ConnectionV4::from_key(&key, ale_data.process_id, ale_data.direction).unwrap();
                conn.set_verdict(Verdict::Accept);
                device.connection_cache.add_v4(conn);
            }

            if let Some(info) =
                id_cache::build_loopback_info(&key, ale_data.process_id, ale_data.direction)
            {
                let _ = device.event_queue.push(info);
            }

            data.action_permit();
            return;
        }

        crate::dbg!("pending connection: {} {}", key, ale_data.direction);
        // Only first packet of a connection can be pended: reauthorize == false
        let can_pend_connection = !ale_data.reauthorize;
        match save_packet(device, &mut data, &ale_data, can_pend_connection) {
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
        if ale_data.is_ipv6 {
            let conn =
                ConnectionV6::from_key(&key, ale_data.process_id, ale_data.direction).unwrap();
            device.connection_cache.add_v6(conn);
        } else {
            let conn =
                ConnectionV4::from_key(&key, ale_data.process_id, ale_data.direction).unwrap();
            device.connection_cache.add_v4(conn);
        }

        // Drop packet. It will be re-injected after user space returns a verdict.
        data.block_and_absorb();
    }
}

fn save_packet(
    device: &Device,
    callout_data: &mut CalloutData,
    ale_data: &AleLayerData,
    pend: bool,
) -> Result<Packet, alloc::string::String> {
    let mut packet_list = None;
    let mut save_packet_list = true;
    match ale_data.protocol {
        IpProtocol::Tcp => {
            if let Direction::Outbound = ale_data.direction {
                // Only time a packet data is missing is during connect state of outbound TCP connection.
                // Don't save packet list only if connection is outbound, reauthorize is false and the protocol is TCP.
                save_packet_list = ale_data.reauthorize;
            }
        }
        _ => {}
    };
    if save_packet_list {
        packet_list = create_packet_list(device, callout_data, ale_data);
    }
    if pend && matches!(ale_data.protocol, IpProtocol::Tcp | IpProtocol::Udp) {
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
    let mut nbl = NetBufferList::new(callout_data.get_layer_data() as _);
    let mut inbound = false;
    if let Direction::Inbound = ale_data.direction {
        let retreat_size =
            callout_data.get_ip_header_size() + callout_data.get_transport_header_size();
        nbl.retreat(retreat_size, true);
        inbound = true;
    }

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

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::ale_layer_accept_v4;
    use crate::connection::{Key, Verdict};
    use crate::device::Device;
    use crate::entry::{clear_device, get_device, set_device};
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address};
    use wdk::driver::Driver;
    use wdk::filter_engine::callout_data::{CalloutData, Value};
    use wdk::filter_engine::classify::{ClassifyOut, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT};
    use wdk::filter_engine::layer::{FieldsAleAuthRecvAcceptV4, FieldsInboundIppacketV4, Layer};
    use wdk::filter_engine::net_buffer::NET_BUFFER_LIST;
    use wdk::irp_helpers::WriteRequest;

    // Callouts reach the device through the global `static mut DEVICE`, so tests
    // that install a device must not run concurrently -- with each other or with
    // the global-slot tests in other modules (entry, fuzz_api, sim), hence the
    // shared process-wide lock.
    use crate::entry::DEVICE_TEST_LOCK as DEVICE_LOCK;

    fn install_device() {
        let device = Box::new(Device::new(&Driver::mock()).expect("mock device"));
        set_device(Box::into_raw(device));
    }

    fn uninstall_device() {
        let ptr = clear_device();
        if !ptr.is_null() {
            unsafe { drop(Box::from_raw(ptr)) };
        }
    }

    fn ale_recv_v4_values(
        proto: u8,
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> Vec<Value> {
        type F = FieldsAleAuthRecvAcceptV4;
        let mut v = vec![Value::U32(0); F::Max as usize];
        v[F::IpProtocol as usize] = Value::U8(proto);
        v[F::IpLocalAddress as usize] = Value::U32(u32::from_be_bytes(local_ip));
        v[F::IpLocalPort as usize] = Value::U16(local_port);
        v[F::IpRemoteAddress as usize] = Value::U32(u32::from_be_bytes(remote_ip));
        v[F::IpRemotePort as usize] = Value::U16(remote_port);
        v[F::Flags as usize] = Value::U32(0);
        v
    }

    fn inbound_ippacket_v4_values() -> Vec<Value> {
        vec![Value::U32(0); FieldsInboundIppacketV4::Max as usize]
    }

    // Minimal IPv4 + TCP header carrying the given addresses/ports. Only the
    // fields `get_key_from_nbl_v4` reads are populated.
    fn ipv4_tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45; // version 4, IHL 5
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&src_port.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    fn ale_key() -> Key {
        Key {
            protocol: IpProtocol::Tcp,
            local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 5)),
            local_port: 8080,
            remote_address: IpAddress::Ipv4(Ipv4Address::new(93, 184, 216, 34)),
            remote_port: 12345,
        }
    }

    // Full pipeline: inbound ALE accept (pends) -> user-space PermanentAccept
    // verdict -> packet layer permits the matching flow. Asserts the verdict set
    // via the command channel is the one observed at the packet layer.
    #[test]
    fn ale_accept_verdict_packet_pipeline() {
        let _g = DEVICE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_device();

        // 1. New inbound connection -> block + absorb, pended for user space.
        let mut co = ClassifyOut::new();
        let mut ale_nbl = NET_BUFFER_LIST::new_box(vec![0u8; 60], 40);
        let data = CalloutData::mock(
            Layer::AleAuthRecvAcceptV4,
            ale_recv_v4_values(6, [10, 0, 0, 5], 8080, [93, 184, 216, 34], 12345),
            Some(4321),
            &mut co as *mut _,
            ale_nbl.as_mut() as *mut _,
            20,
            20,
        );
        ale_layer_accept_v4(data);

        assert_eq!(co.action(), FWP_ACTION_BLOCK);
        assert!(co.is_absorb());
        {
            let device = get_device().unwrap();
            assert_eq!(
                device.connection_cache.get_verdict(&ale_key()).map(|v| v as u8),
                Some(Verdict::Undecided as u8),
            );
            assert_eq!(device.packet_cache.get_entries_count(), 1);
        }

        // 2. User space returns PermanentAccept for packet id 1.
        let mut cmd = vec![1u8]; // CommandType::Verdict
        cmd.extend_from_slice(&1u64.to_le_bytes());
        cmd.push(Verdict::PermanentAccept as u8);
        {
            let device = get_device().unwrap();
            let mut wr = WriteRequest::from_bytes(&cmd);
            device.write(&mut wr);
            assert_eq!(
                device.connection_cache.get_verdict(&ale_key()).map(|v| v as u8),
                Some(Verdict::PermanentAccept as u8),
            );
            assert_eq!(device.packet_cache.get_entries_count(), 0);
        }

        // 3. Packet layer sees the same flow and permits it.
        let mut co2 = ClassifyOut::new();
        let mut pkt_nbl = NET_BUFFER_LIST::new_box(
            ipv4_tcp_packet([93, 184, 216, 34], [10, 0, 0, 5], 12345, 8080),
            20,
        );
        let data2 = CalloutData::mock(
            Layer::InboundIppacketV4,
            inbound_ippacket_v4_values(),
            None,
            &mut co2 as *mut _,
            pkt_nbl.as_mut() as *mut _,
            0,
            0,
        );
        crate::packet_callouts::ip_packet_layer_inbound_v4(data2);
        assert_eq!(co2.action(), FWP_ACTION_PERMIT);

        uninstall_device();
    }

    // The ALE accept callout must not panic for any protocol value, and must
    // always set some action.
    #[test]
    fn ale_accept_never_panics_across_protocols() {
        let _g = DEVICE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_device();
        for proto in [6u8, 17, 1, 0, 255] {
            let mut co = ClassifyOut::new();
            let mut nbl = NET_BUFFER_LIST::new_box(vec![0u8; 60], 40);
            let data = CalloutData::mock(
                Layer::AleAuthRecvAcceptV4,
                ale_recv_v4_values(proto, [10, 0, 0, 9], 1111, [1, 2, 3, 4], 2222),
                Some(7),
                &mut co as *mut _,
                nbl.as_mut() as *mut _,
                20,
                20,
            );
            ale_layer_accept_v4(data);
            assert_ne!(co.action(), 0);
        }
        uninstall_device();
    }

    // Sanity check that the `fuzz_api` callout harness actually links the
    // pipeline (ALE pend -> verdict command -> packet layer reads the verdict)
    // and that its Tier-3 oracle is not vacuous. Shares DEVICE_LOCK with the
    // other global-device tests. Mirrors what the `callouts` fuzz target asserts.
    #[test]
    fn fuzz_api_pipeline_links_and_oracle_holds() {
        use crate::fuzz_api;
        let _g = DEVICE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_device();

        // PermanentAccept pipeline on pool connection 0 (v4 TCP).
        let r = fuzz_api::run_ale_accept_v4(0, 0, false, 100, &[], false);
        assert_ne!(r.action, 0, "ALE accept must set an action");
        let ids = fuzz_api::live_ids();
        assert_eq!(ids.len(), 1, "ALE accept must pend exactly one packet");
        fuzz_api::device_write_verdict(ids[0], Verdict::PermanentAccept as u8);
        assert_eq!(
            fuzz_api::verdict_for_v4(0, 0),
            Some(Verdict::PermanentAccept as u8),
            "verdict command must reach the connection cache",
        );
        let r = fuzz_api::run_packet_in_v4(0, 0, &[], false);
        assert_eq!(r.action, FWP_ACTION_PERMIT, "PermanentAccept must permit");
        assert!(!r.absorb);

        // PermanentBlock pipeline on pool connection 1 (v4 UDP).
        let r = fuzz_api::run_ale_accept_v4(1, 1, false, 100, &[], false);
        assert_ne!(r.action, 0);
        let ids = fuzz_api::live_ids();
        assert_eq!(ids.len(), 1, "previous packet should have been consumed");
        fuzz_api::device_write_verdict(ids[0], Verdict::PermanentBlock as u8);
        let r = fuzz_api::run_packet_in_v4(1, 1, &[], false);
        assert_eq!(r.action, FWP_ACTION_BLOCK, "PermanentBlock must block");
        assert!(!r.absorb, "PermanentBlock must not absorb");

        uninstall_device();
    }

    // One worker thread: a deterministic, varied mix of every callout + command
    // op, all aimed at a small "hot" set of connection slots so threads collide
    // hard on the same RCU ports and the packet cache. The only per-call
    // invariant asserted is that an ALE callout always sets an action -- true
    // regardless of how the threads interleave.
    fn mt_worker(tid: u64, iters: u64) {
        use crate::fuzz_api as api;
        // Inline xorshift64, seeded per thread (deterministic per run).
        let mut st = tid.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        const HOT: u8 = 6; // few connections -> maximum contention
        for _ in 0..iters {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            let r = st;
            let conn = (r as u8) % HOT;
            let proto = (r >> 8) as u8;
            let pid = (r >> 16) as u16 as u64;
            let verdict = ((r >> 32) as u8) % 10;
            match ((r >> 24) as u8) % 14 {
                0 => assert_ne!(
                    api::run_ale_connect_v4(conn, proto, false, pid, &[], false).action,
                    0
                ),
                1 => assert_ne!(
                    api::run_ale_accept_v4(conn, proto, false, pid, &[], false).action,
                    0
                ),
                2 => assert_ne!(
                    api::run_ale_connect_v6(conn, proto, false, pid, &[], false).action,
                    0
                ),
                3 => assert_ne!(
                    api::run_ale_accept_v6(conn, proto, false, pid, &[], false).action,
                    0
                ),
                4 => {
                    api::run_packet_in_v4(conn, proto, &[], false);
                }
                5 => {
                    api::run_packet_out_v4(conn, proto, &[], false);
                }
                6 => {
                    api::run_packet_in_v6(conn, proto, &[], false);
                }
                7 => {
                    api::run_packet_out_v6(conn, proto, &[], false);
                }
                8 => {
                    let ids = api::live_ids();
                    let id = if ids.is_empty() {
                        r
                    } else {
                        ids[(r as usize) % ids.len()]
                    };
                    api::device_write_verdict(id, verdict);
                }
                9 => api::device_write_update_v4(conn, proto, verdict),
                10 => api::device_write_update_v6(conn, proto, verdict),
                11 => api::run_endpoint_close_v4(conn, proto, pid),
                12 => api::run_resource_v4((r >> 40) as u8, proto, (r >> 48) as u16),
                _ => api::drain_events(2),
            }
        }
    }

    // Stress: many threads pounding ONE shared device with concurrent callouts +
    // commands in every combination. This is the "should never fail" check, and
    // it runs natively on Windows via `just test-driver`. It exercises the real
    // reader-writer lock in mock_wdk and the RCU reclamation path under genuine
    // contention; it catches panics, deadlocks (test hang), use-after-free /
    // double-free, and the kind of duplicate-id race the atomic IdCache fix
    // closed. If the mock lock were still a no-op this test would corrupt/crash.
    #[test]
    fn callouts_mt_shared_device_stress() {
        let _g = DEVICE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_device();

        const THREADS: usize = 8;
        const ITERS: u64 = 10_000;

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);
        for t in 0..THREADS {
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait(); // release all workers together for maximum overlap
                mt_worker(t as u64 + 1, ITERS);
            }));
        }
        for h in handles {
            h.join()
                .expect("a worker thread panicked under concurrent callouts");
        }

        // Quiesce oracle: with all workers joined, a shutdown must fully drain
        // the packet cache regardless of how the threads interleaved.
        crate::fuzz_api::device_shutdown();
        assert_eq!(
            crate::fuzz_api::packet_cache_len(),
            0,
            "packet cache not drained after MT quiesce + shutdown"
        );

        uninstall_device();
    }
}
