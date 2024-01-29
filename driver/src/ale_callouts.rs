use alloc::boxed::Box;
use protocol::info::{
    ConnectionEndEventV4Info, ConnectionEndEventV6Info, ConnectionInfoV4, ConnectionInfoV6, Info,
};
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv6Address, IPV4_HEADER_LEN, IPV6_HEADER_LEN,
};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{
    self, FieldsAleAuthConnectV4, FieldsAleAuthConnectV6, FieldsAleAuthRecvAcceptV4,
    FieldsAleAuthRecvAcceptV6,
};
use wdk::filter_engine::net_buffer::NetBufferList;
use wdk::filter_engine::packet::Injector;
use wdk::interface;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::connection::{
    ConnectionAction, ConnectionExtra, ConnectionV4, ConnectionV6, Direction, Verdict,
};
use crate::connection_cache::Key;
use crate::info;
use crate::{dbg, device::Device, err};

// ALE Layers

#[derive(Debug)]
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
    fn as_connection_info_v4(&self, id: u64) -> Option<Box<dyn Info>> {
        let mut local_port = 0;
        let mut remote_port = 0;
        match IpProtocol::from(self.protocol) {
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
        match IpProtocol::from(self.protocol) {
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

pub fn ale_layer_connect_v4(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
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

    ale_layer_auth(data, device_object, ale_data);
}

pub fn ale_layer_accept_v4(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
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
    ale_layer_auth(data, device_object, ale_data);
}

pub fn ale_layer_connect_v6(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
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

    ale_layer_auth(data, device_object, ale_data);
}

pub fn ale_layer_accept_v6(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
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
    ale_layer_auth(data, device_object, ale_data);
}

fn ale_layer_auth(
    mut data: CalloutData,
    device_object: &mut DEVICE_OBJECT,
    ale_data: AleLayerData,
) {
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };
    // Check if packet was previously injected from the packet layer.
    if device
        .injector
        .was_network_packet_injected_by_self(data.get_layer_data() as _, ale_data.is_ipv6)
    {
        data.action_permit();
        return;
    }

    // Check if protocol is supported
    match IpProtocol::from(ale_data.protocol) {
        IpProtocol::Tcp | IpProtocol::Udp => {}
        _ => {
            // Not supported. Send event and permit.
            let conn_info: Option<Box<dyn Info>> = if ale_data.is_ipv6 {
                ale_data.as_connection_info_v6(0)
            } else {
                ale_data.as_connection_info_v4(0)
            };
            if let Some(conn_info) = conn_info {
                let _ = device.event_queue.push(conn_info);
            } else {
                err!(device.logger, "Failed to build ConnectionInfo");
            }
            data.action_permit();
            return;
        }
    }

    let action = if ale_data.is_ipv6 {
        device.connection_cache.get_connection_action_v6(
            &ale_data.as_key(),
            |conn| -> Option<ConnectionAction> {
                // Function is behind spin lock, just copy and return.
                Some(conn.action.clone())
            },
        )
    } else {
        device.connection_cache.get_connection_action_v4(
            &ale_data.as_key(),
            |conn| -> Option<ConnectionAction> {
                // Function is behind spin lock, just copy and return.
                Some(conn.action.clone())
            },
        )
    };

    if let Some(action) = action {
        // We already have a verdict for it.
        dbg!(
            device.logger,
            "{:?} Verdict: {} {}",
            data.layer,
            action,
            ale_data.as_key()
        );
        match action {
            ConnectionAction::Verdict(verdict) => match verdict {
                Verdict::Accept | Verdict::Redirect | Verdict::RedirectTunnel => {
                    data.action_permit()
                }
                Verdict::Block => data.action_block(),
                Verdict::Drop | Verdict::Undeterminable | Verdict::Failed => {
                    data.block_and_absorb();
                }
                Verdict::Undecided => {
                    if ale_data.protocol == IpProtocol::Udp || ale_data.reauthorize {
                        let mut nbl = NetBufferList::new(data.get_layer_data() as _);
                        if let Direction::Inbound = ale_data.direction {
                            if ale_data.is_ipv6 {
                                nbl.retreat(IPV6_HEADER_LEN as u32, true);
                            } else {
                                nbl.retreat(IPV4_HEADER_LEN as u32, true);
                            }
                        }
                        if let Ok(clone) = nbl.clone(&device.network_allocator) {
                            device
                                .connection_cache
                                .push_packet_to_connection(ale_data.as_key(), clone);
                        }
                    }
                    data.block_and_absorb();
                }
            },
            ConnectionAction::RedirectIP {
                redirect_address: _,
                redirect_port: _,
            } => {
                data.action_permit();
            }
        }
    } else {
        // Pend decision of connection.
        let mut packet_list = None;
        if ale_data.protocol == IpProtocol::Udp || ale_data.reauthorize {
            let mut nbl = NetBufferList::new(data.get_layer_data() as _);
            if let Direction::Inbound = ale_data.direction {
                if ale_data.is_ipv6 {
                    nbl.retreat(IPV6_HEADER_LEN as u32, true);
                } else {
                    nbl.retreat(IPV4_HEADER_LEN as u32, true);
                }
            }
            let mut inbound = false;
            if let Direction::Inbound = ale_data.direction {
                inbound = true;
            }

            let address: &[u8] = match &ale_data.remote_ip {
                IpAddress::Ipv4(address) => &address.0,
                IpAddress::Ipv6(address) => &address.0,
            };
            if let Ok(clone) = nbl.clone(&device.network_allocator) {
                packet_list = Some(Injector::from_ale_callout(
                    ale_data.is_ipv6,
                    &data,
                    clone,
                    address,
                    inbound,
                    ale_data.interface_index,
                    ale_data.sub_interface_index,
                ));
            }
        }
        let promise = if ale_data.reauthorize {
            data.pend_filter_rest(packet_list)
        } else {
            match data.pend_operation(packet_list) {
                Ok(cc) => cc,
                Err(error) => {
                    err!(device.logger, "failed to postpone decision: {}", error);
                    data.action_permit(); // TODO: should error action be permit?
                    return;
                }
            }
        };

        // Send request to user-space.
        let id = device.packet_cache.push(ale_data.as_key());
        let conn_info: Option<Box<dyn Info>> = if ale_data.is_ipv6 {
            ale_data.as_connection_info_v6(id)
        } else {
            ale_data.as_connection_info_v4(id)
        };
        if let Some(conn_info) = conn_info {
            let _ = device.event_queue.push(conn_info);
        } else {
            err!(device.logger, "Failed to build ConnectionInfo");
        }
        let extra = Box::new(ConnectionExtra {
            direction: ale_data.direction,
            endpoint_handle: data.get_transport_endpoint_handle().unwrap_or(0),
            packet_queue: Some(promise),
            callout_id: data.get_callout_id(),
        });
        data.block_and_absorb();

        if ale_data.is_ipv6 {
            let IpAddress::Ipv6(local_address) = ale_data.local_ip else {
                err!(device.logger, "Failed to build ConnectionV6");
                return;
            };

            let IpAddress::Ipv6(remote_address) = ale_data.remote_ip else {
                err!(device.logger, "Failed to build ConnectionV6");
                return;
            };

            let conn = ConnectionV6 {
                protocol: ale_data.protocol,
                local_address,
                local_port: ale_data.local_port,
                remote_address,
                remote_port: ale_data.remote_port,
                action: ConnectionAction::Verdict(Verdict::Undecided),
                extra,
            };

            device.connection_cache.add_connection_v6(conn);
        } else {
            let IpAddress::Ipv4(local_address) = ale_data.local_ip else {
                err!(device.logger, "Failed to build ConnectionV4");
                return;
            };

            let IpAddress::Ipv4(remote_address) = ale_data.remote_ip else {
                err!(device.logger, "Failed to build ConnectionV4");
                return;
            };

            let conn = ConnectionV4 {
                protocol: ale_data.protocol,
                local_address,
                local_port: ale_data.local_port,
                remote_address,
                remote_port: ale_data.remote_port,
                action: ConnectionAction::Verdict(Verdict::Undecided),
                extra,
            };

            device.connection_cache.add_connection_v4(conn);
        }
    }
}

pub fn endpoint_closure_v4(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FieldsAleEndpointClosureV4;
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    let conn = device.connection_cache.remove_connection_v4(
        (
            get_protocol(&data, Fields::IpProtocol as usize),
            data.get_value_u16(Fields::IpLocalPort as usize),
        ),
        data.get_transport_endpoint_handle().unwrap_or(0),
    );
    if let Some(conn) = conn {
        let info = Box::new(ConnectionEndEventV4Info::new(
            data.get_process_id().unwrap_or(0),
            conn.extra.direction as u8,
            u8::from(get_protocol(&data, Fields::IpProtocol as usize)),
            conn.local_address.0,
            conn.remote_address.0,
            conn.local_port,
            conn.remote_port,
        ));
        let _ = device.event_queue.push(info);
    }
}

pub fn endpoint_closure_v6(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FieldsAleEndpointClosureV6;
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    let conn = device.connection_cache.remove_connection_v6(
        (
            get_protocol(&data, Fields::IpProtocol as usize),
            data.get_value_u16(Fields::IpLocalPort as usize),
        ),
        data.get_transport_endpoint_handle().unwrap_or(0),
    );
    if let Some(conn) = conn {
        let info = Box::new(ConnectionEndEventV6Info::new(
            data.get_process_id().unwrap_or(0),
            conn.extra.direction as u8,
            u8::from(get_protocol(&data, Fields::IpProtocol as usize)),
            conn.local_address.0,
            conn.remote_address.0,
            conn.local_port,
            conn.remote_port,
        ));
        let _ = device.event_queue.push(info);
    }
}

pub fn ale_resource_monitor(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };
    match data.layer {
        layer::Layer::AleResourceAssignmentV4 => {
            type Fields = layer::FieldsAleResourceAssignmentV4;
            info!(
                device.logger,
                "Port {}/{} Ipv4 assigned pid={}",
                data.get_value_u16(Fields::IpLocalPort as usize),
                get_protocol(&data, Fields::IpProtocol as usize),
                data.get_process_id().unwrap_or(0),
            );
        }
        layer::Layer::AleResourceAssignmentV6 => {
            type Fields = layer::FieldsAleResourceAssignmentV6;
            info!(
                device.logger,
                "Port {}/{} Ipv6 assigned pid={}",
                data.get_value_u16(Fields::IpLocalPort as usize),
                get_protocol(&data, Fields::IpProtocol as usize),
                data.get_process_id().unwrap_or(0),
            );
        }
        layer::Layer::AleResourceReleaseV4 => {
            type Fields = layer::FieldsAleResourceReleaseV4;
            if let Some(conns) = device.connection_cache.unregister_port_v4((
                get_protocol(&data, Fields::IpProtocol as usize),
                data.get_value_u16(Fields::IpLocalPort as usize),
            )) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    device.logger,
                    "Port {}/{} released pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = Box::new(ConnectionEndEventV4Info::new(
                        process_id,
                        conn.extra.direction as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.0,
                        conn.remote_address.0,
                        conn.local_port,
                        conn.remote_port,
                    ));
                    let _ = device.event_queue.push(info);
                }
            }
        }
        layer::Layer::AleResourceReleaseV6 => {
            type Fields = layer::FieldsAleResourceReleaseV6;
            if let Some(conns) = device.connection_cache.unregister_port_v6((
                get_protocol(&data, Fields::IpProtocol as usize),
                data.get_value_u16(Fields::IpLocalPort as usize),
            )) {
                let process_id = data.get_process_id().unwrap_or(0);
                info!(
                    device.logger,
                    "Port {}/{} released pid={}",
                    data.get_value_u16(Fields::IpLocalPort as usize),
                    get_protocol(&data, Fields::IpProtocol as usize),
                    process_id,
                );
                for conn in conns {
                    let info = Box::new(ConnectionEndEventV6Info::new(
                        process_id,
                        conn.extra.direction as u8,
                        data.get_value_u8(Fields::IpProtocol as usize),
                        conn.local_address.0,
                        conn.remote_address.0,
                        conn.local_port,
                        conn.remote_port,
                    ));
                    let _ = device.event_queue.push(info);
                }
            }
        }
        _ => {}
    }
}
