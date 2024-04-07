use crate::connection::{ConnectionV4, ConnectionV6, Direction, Verdict};
use crate::connection_map::Key;
use crate::device::{Device, Packet};

use crate::packet_util::key_to_connection_info;
use alloc::boxed::Box;
use protocol::info::{ConnectionInfoV4, ConnectionInfoV6, Info};
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv6Address, IPV4_HEADER_LEN, IPV6_HEADER_LEN,
};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{
    FieldsAleAuthConnectV4, FieldsAleAuthConnectV6, FieldsAleAuthRecvAcceptV4,
    FieldsAleAuthRecvAcceptV6,
};
use wdk::filter_engine::net_buffer::NetBufferList;
use wdk::filter_engine::packet::Injector;

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

#[allow(dead_code)]
impl AleLayerData {
    fn as_connection_info_v4(&self, id: u64) -> Option<Box<dyn Info>> {
        let mut local_port = 0;
        let mut remote_port = 0;
        match self.protocol {
            IpProtocol::Tcp | IpProtocol::Udp => {
                local_port = self.local_port;
                remote_port = self.remote_port;
            }
            _ => {}
        }
        let IpAddress::Ipv4(local_ip) = self.local_ip else {
            return None;
        };
        let IpAddress::Ipv4(remote_ip) = self.remote_ip else {
            return None;
        };

        Some(Box::new(ConnectionInfoV4::new(
            id,
            self.process_id,
            self.direction as u8,
            u8::from(self.protocol),
            local_ip.0,
            remote_ip.0,
            local_port,
            remote_port,
        )))
    }

    fn as_connection_info_v6(&self, id: u64) -> Option<Box<dyn Info>> {
        let mut local_port = 0;
        let mut remote_port = 0;
        match self.protocol {
            IpProtocol::Tcp | IpProtocol::Udp => {
                local_port = self.local_port;
                remote_port = self.remote_port;
            }
            _ => {}
        }
        let IpAddress::Ipv6(local_ip) = self.local_ip else {
            return None;
        };
        let IpAddress::Ipv6(remote_ip) = self.remote_ip else {
            return None;
        };

        Some(Box::new(ConnectionInfoV6::new(
            id,
            self.process_id,
            self.direction as u8,
            u8::from(self.protocol),
            local_ip.0,
            remote_ip.0,
            local_port,
            remote_port,
        )))
    }

    fn as_key(&self) -> Key {
        Key {
            protocol: self.protocol,
            local_address: self.local_ip,
            local_port: self.local_port,
            remote_address: self.remote_ip,
            remote_port: self.remote_port,
        }
    }
}

fn get_protocol(data: &CalloutData, index: usize) -> IpProtocol {
    IpProtocol::from(data.get_value_u8(index))
}

fn get_ipv4_address(data: &CalloutData, index: usize) -> IpAddress {
    IpAddress::Ipv4(Ipv4Address::from_bytes(
        &data.get_value_u32(index).to_be_bytes(),
    ))
}

fn get_ipv6_address(data: &CalloutData, index: usize) -> IpAddress {
    IpAddress::Ipv6(Ipv6Address::from_bytes(data.get_value_byte_array16(index)))
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
    // Check if packet was previously injected from the packet layer.
    if device
        .injector
        .was_network_packet_injected_by_self(data.get_layer_data() as _, ale_data.is_ipv6)
    {
        // data.action_permit();
        return;
    }
    let key = ale_data.as_key();
    if ale_data.process_id == 0 {
        crate::crit!("ALE process id is 0: {}", key);
    }

    struct Info {
        verdict: Verdict,
        process_id: u64,
    }

    // Check if protocol is supported
    let info = if ale_data.is_ipv6 {
        device
            .connection_cache
            .read_connection_v6(&key, |conn| -> Option<Info> {
                // Function is behind spin lock, just copy and return.
                Some(Info {
                    verdict: conn.verdict,
                    process_id: conn.process_id,
                })
            })
    } else {
        device
            .connection_cache
            .read_connection_v4(&ale_data.as_key(), |conn| -> Option<Info> {
                // Function is behind spin lock, just copy and return.
                Some(Info {
                    verdict: conn.verdict,
                    process_id: conn.process_id,
                })
            })
    };
    if let Some(info) = &info {
        if info.process_id == 0 {
            device
                .connection_cache
                .set_process_id(&key, ale_data.process_id);
        }
    }

    if !ale_data.reauthorize && info.is_none() {
        // First packet of connection.
        // Pend and create postmaster request.
        crate::dbg!("pending connection: {} {}", key, ale_data.direction);
        match save_packet(device, &mut data, &ale_data, true) {
            Ok(packet) => {
                let packet_id = device.packet_cache.push((key, packet));
                if let Some(info) =
                    key_to_connection_info(&key, packet_id, ale_data.process_id, ale_data.direction)
                {
                    let _ = device.event_queue.push(info);
                }
            }
            Err(err) => {
                crate::err!("failed to pend packet: {}", err);
            }
        };

        data.block_and_absorb();
    } else {
        if let Some(info) = info {
            match info.verdict {
                Verdict::PermanentAccept => {
                    data.action_permit();
                }
                Verdict::PermanentBlock | Verdict::Undeterminable => {
                    crate::dbg!("permanent block {}", key);
                    data.action_block();
                }
                Verdict::PermanentDrop => {
                    crate::dbg!("permanent drop {}", key);
                    data.block_and_absorb();
                }
                Verdict::Undecided => {
                    crate::dbg!("saving packet: {}", key);
                    match save_packet(device, &mut data, &ale_data, false) {
                        Ok(packet) => {
                            let packet_id = device.packet_cache.push((key, packet));
                            if let Some(info) = key_to_connection_info(
                                &key,
                                packet_id,
                                ale_data.process_id,
                                ale_data.direction,
                            ) {
                                let _ = device.event_queue.push(info);
                            }
                        }
                        Err(err) => {
                            crate::err!("failed to pend packet: {}", err);
                        }
                    };
                }
                Verdict::Accept => {
                    data.action_permit();
                }
                Verdict::Block => {
                    data.action_block();
                }
                Verdict::Drop => {
                    data.block_and_absorb();
                }
                Verdict::RedirectNameServer => {
                    data.action_permit();
                }
                Verdict::RedirectTunnel => {
                    data.action_permit();
                }
                Verdict::Failed => {
                    data.block_and_absorb();
                }
            }
        }
        return;
    }
    if info.is_none() {
        crate::dbg!("adding connection: {} PID: {}", key, ale_data.process_id);
        if ale_data.is_ipv6 {
            let conn =
                ConnectionV6::from_key(&key, ale_data.process_id, ale_data.direction).unwrap();
            device.connection_cache.add_connection_v6(conn);
        } else {
            let conn =
                ConnectionV4::from_key(&key, ale_data.process_id, ale_data.direction).unwrap();
            device.connection_cache.add_connection_v4(conn);
        }
    }
}

fn save_packet(
    device: &Device,
    callout_data: &mut CalloutData,
    ale_data: &AleLayerData,
    pend: bool,
) -> Result<Packet, alloc::string::String> {
    let mut packet_list = None;
    match ale_data.protocol {
        IpProtocol::Tcp => {
            // Does not contain payload
        }
        _ => {
            let mut nbl = NetBufferList::new(callout_data.get_layer_data() as _);
            let mut inbound = false;
            if let Direction::Inbound = ale_data.direction {
                if ale_data.is_ipv6 {
                    nbl.retreat(IPV6_HEADER_LEN as u32, true);
                } else {
                    nbl.retreat(IPV4_HEADER_LEN as u32, true);
                }
                inbound = true;
            }

            let address: &[u8] = match &ale_data.remote_ip {
                IpAddress::Ipv4(address) => &address.0,
                IpAddress::Ipv6(address) => &address.0,
            };
            if let Ok(clone) = nbl.clone(&device.network_allocator) {
                packet_list = Some(Injector::from_ale_callout(
                    ale_data.is_ipv6,
                    callout_data,
                    clone,
                    address,
                    inbound,
                    ale_data.interface_index,
                    ale_data.sub_interface_index,
                ));
            }
        }
    }

    if pend {
        match callout_data.pend_operation(None) {
            Ok(classify_defer) => return Ok(Packet::AleLayer(classify_defer, packet_list)),
            Err(err) => return Err(alloc::format!("failed to defer connection: {}", err)),
        }
    }
    if let Some(packet_list) = packet_list {
        Ok(Packet::TransportPacketList(packet_list))
    } else {
        Err("".into())
    }
}

pub fn endpoint_closure_v4(data: CalloutData) {
    // type Fields = layer::FieldsAleEndpointClosureV4;
    // let Some(device) = crate::entry::get_device() else {
    //     return;
    // };
    // let ip_address_type = data.get_value_type(Fields::IpLocalAddress as usize);
    // if let ValueType::FwpUint32 = ip_address_type {
    //     let key = Key {
    //         protocol: get_protocol(&data, Fields::IpProtocol as usize),
    //         local_address: get_ipv4_address(&data, Fields::IpLocalAddress as usize),
    //         local_port: data.get_value_u16(Fields::IpLocalPort as usize),
    //         remote_address: get_ipv4_address(&data, Fields::IpRemoteAddress as usize),
    //         remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
    //     };

    //     let conn = device.connection_cache.remove_connection_v4(key);
    //     if let Some(conn) = conn {
    //         let info = Box::new(ConnectionEndEventV4Info::new(
    //             data.get_process_id().unwrap_or(0),
    //             conn.direction as u8,
    //             u8::from(get_protocol(&data, Fields::IpProtocol as usize)),
    //             conn.local_address.0,
    //             conn.remote_address.0,
    //             conn.local_port,
    //             conn.remote_port,
    //         ));
    //         let _ = device.event_queue.push(info);
    //     }
    // } else {
    //     // Invalid ip address type. Just ignore the error.
    //     // err!(
    //     //     device.logger,
    //     //     "unknown ipv4 address type: {:?}",
    //     //     ip_address_type
    //     // );
    // }
}

pub fn endpoint_closure_v6(data: CalloutData) {
    // type Fields = layer::FieldsAleEndpointClosureV6;
    // let Some(device) = crate::entry::get_device() else {
    //     return;
    // };
    // let local_ip_address_type = data.get_value_type(Fields::IpLocalAddress as usize);
    // let remote_ip_address_type = data.get_value_type(Fields::IpRemoteAddress as usize);

    // if let ValueType::FwpByteArray16Type = local_ip_address_type {
    //     if let ValueType::FwpByteArray16Type = remote_ip_address_type {
    //         let key = Key {
    //             protocol: get_protocol(&data, Fields::IpProtocol as usize),
    //             local_address: get_ipv6_address(&data, Fields::IpLocalAddress as usize),
    //             local_port: data.get_value_u16(Fields::IpLocalPort as usize),
    //             remote_address: get_ipv6_address(&data, Fields::IpRemoteAddress as usize),
    //             remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
    //         };

    //         let conn = device.connection_cache.remove_connection_v6(key);
    //         if let Some(conn) = conn {
    //             let info = Box::new(ConnectionEndEventV6Info::new(
    //                 data.get_process_id().unwrap_or(0),
    //                 conn.direction as u8,
    //                 u8::from(get_protocol(&data, Fields::IpProtocol as usize)),
    //                 conn.local_address.0,
    //                 conn.remote_address.0,
    //                 conn.local_port,
    //                 conn.remote_port,
    //             ));
    //             let _ = device.event_queue.push(info);
    //         }
    //     }
    // }
}

pub fn ale_resource_monitor(data: CalloutData) {
    // let Some(device) = crate::entry::get_device() else {
    //     return;
    // };
    // match data.layer {
    //     layer::Layer::AleResourceAssignmentV4Discard => {
    //         type Fields = layer::FieldsAleResourceAssignmentV4;
    //         if let Some(conns) = device.connection_cache.unregister_port_v4((
    //             get_protocol(&data, Fields::IpProtocol as usize),
    //             data.get_value_u16(Fields::IpLocalPort as usize),
    //         )) {
    //             let process_id = data.get_process_id().unwrap_or(0);
    //             info!(
    //                 device.logger,
    //                 "Port {}/{} Ipv4 assign request discarded pid={}",
    //                 data.get_value_u16(Fields::IpLocalPort as usize),
    //                 get_protocol(&data, Fields::IpProtocol as usize),
    //                 process_id,
    //             );
    //             for conn in conns {
    //                 let info = Box::new(ConnectionEndEventV4Info::new(
    //                     process_id,
    //                     conn.direction as u8,
    //                     data.get_value_u8(Fields::IpProtocol as usize),
    //                     conn.local_address.0,
    //                     conn.remote_address.0,
    //                     conn.local_port,
    //                     conn.remote_port,
    //                 ));
    //                 let _ = device.event_queue.push(info);
    //             }
    //         }
    //     }
    //     layer::Layer::AleResourceAssignmentV6Discard => {
    //         type Fields = layer::FieldsAleResourceAssignmentV6;
    //         if let Some(conns) = device.connection_cache.unregister_port_v6((
    //             get_protocol(&data, Fields::IpProtocol as usize),
    //             data.get_value_u16(Fields::IpLocalPort as usize),
    //         )) {
    //             let process_id = data.get_process_id().unwrap_or(0);
    //             info!(
    //                 device.logger,
    //                 "Port {}/{} Ipv6 assign request discarded pid={}",
    //                 data.get_value_u16(Fields::IpLocalPort as usize),
    //                 get_protocol(&data, Fields::IpProtocol as usize),
    //                 process_id,
    //             );
    //             for conn in conns {
    //                 let info = Box::new(ConnectionEndEventV6Info::new(
    //                     process_id,
    //                     conn.direction as u8,
    //                     data.get_value_u8(Fields::IpProtocol as usize),
    //                     conn.local_address.0,
    //                     conn.remote_address.0,
    //                     conn.local_port,
    //                     conn.remote_port,
    //                 ));
    //                 let _ = device.event_queue.push(info);
    //             }
    //         }
    //     }
    //     layer::Layer::AleResourceReleaseV4 => {
    //         type Fields = layer::FieldsAleResourceReleaseV4;
    //         if let Some(conns) = device.connection_cache.unregister_port_v4((
    //             get_protocol(&data, Fields::IpProtocol as usize),
    //             data.get_value_u16(Fields::IpLocalPort as usize),
    //         )) {
    //             let process_id = data.get_process_id().unwrap_or(0);
    //             info!(
    //                 device.logger,
    //                 "Port {}/{} released pid={}",
    //                 data.get_value_u16(Fields::IpLocalPort as usize),
    //                 get_protocol(&data, Fields::IpProtocol as usize),
    //                 process_id,
    //             );
    //             for conn in conns {
    //                 let info = Box::new(ConnectionEndEventV4Info::new(
    //                     process_id,
    //                     conn.direction as u8,
    //                     data.get_value_u8(Fields::IpProtocol as usize),
    //                     conn.local_address.0,
    //                     conn.remote_address.0,
    //                     conn.local_port,
    //                     conn.remote_port,
    //                 ));
    //                 let _ = device.event_queue.push(info);
    //             }
    //         }
    //     }
    //     layer::Layer::AleResourceReleaseV6 => {
    //         type Fields = layer::FieldsAleResourceReleaseV6;
    //         if let Some(conns) = device.connection_cache.unregister_port_v6((
    //             get_protocol(&data, Fields::IpProtocol as usize),
    //             data.get_value_u16(Fields::IpLocalPort as usize),
    //         )) {
    //             let process_id = data.get_process_id().unwrap_or(0);
    //             info!(
    //                 device.logger,
    //                 "Port {}/{} released pid={}",
    //                 data.get_value_u16(Fields::IpLocalPort as usize),
    //                 get_protocol(&data, Fields::IpProtocol as usize),
    //                 process_id,
    //             );
    //             for conn in conns {
    //                 let info = Box::new(ConnectionEndEventV6Info::new(
    //                     process_id,
    //                     conn.direction as u8,
    //                     data.get_value_u8(Fields::IpProtocol as usize),
    //                     conn.local_address.0,
    //                     conn.remote_address.0,
    //                     conn.local_port,
    //                     conn.remote_port,
    //                 ));
    //                 let _ = device.event_queue.push(info);
    //             }
    //         }
    //     }
    //     _ => {}
    // }
}
