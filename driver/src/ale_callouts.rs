use alloc::boxed::Box;
use protocol::info::{ConnectionEndEventV4Info, ConnectionInfoV4};
use smoltcp::wire::{IpProtocol, Ipv4Address, IPV4_HEADER_LEN};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{self, FieldsAleAuthConnectV4, FieldsAleAuthRecvAcceptV4};
use wdk::filter_engine::net_buffer::NetBufferList;
use wdk::filter_engine::packet::Injector;
use wdk::interface;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::connection_cache::{Connection, ConnectionExtra, Key};
use crate::connection_members::{Direction, Verdict};
use crate::info;
use crate::{connection_cache::ConnectionAction, dbg, device::Device, err};

// ALE Layers

struct AleLayerData {
    reauthorize: bool,
    process_id: u64,
    protocol: IpProtocol,
    direction: Direction,
    local_ip: Ipv4Address,
    local_port: u16,
    remote_ip: Ipv4Address,
    remote_port: u16,
    interface_index: u32,
    sub_interface_index: u32,
}
impl AleLayerData {
    fn as_connection_info_v4(&self, id: u64) -> ConnectionInfoV4 {
        let mut local_port = 0;
        let mut remote_port = 0;
        match IpProtocol::from(self.protocol) {
            IpProtocol::Tcp | IpProtocol::Udp => {
                local_port = self.local_port;
                remote_port = self.remote_port;
            }
            _ => {}
        }
        ConnectionInfoV4::new(
            id,
            self.process_id,
            self.direction as u8,
            u8::from(self.protocol),
            self.local_ip.0,
            self.remote_ip.0,
            local_port,
            remote_port,
        )
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

fn get_ipv4_address(data: &CalloutData, index: usize) -> Ipv4Address {
    Ipv4Address::from_bytes(&data.get_value_u32(index).to_be_bytes())
}

pub fn ale_layer_connect(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = FieldsAleAuthConnectV4;
    let ale_data = AleLayerData {
        reauthorize: data.is_reauthorize(Fields::Flags as usize),
        process_id: data.get_process_id().unwrap_or(0),
        protocol: get_protocol(&data, Fields::IpProtocol as usize),
        direction: Direction::Outbound,
        local_ip: get_ipv4_address(&data, Fields::IpLocalAddress as usize),
        local_port: data.get_value_u16(Fields::IpLocalPort as usize),
        remote_ip: get_ipv4_address(&data, Fields::IpRemoteAddress as usize),
        remote_port: data.get_value_u16(Fields::IpRemotePort as usize),
        interface_index: data.get_value_u32(Fields::InterfaceIndex as usize),
        sub_interface_index: data.get_value_u32(Fields::SubInterfaceIndex as usize),
    };

    ale_layer_auth(data, device_object, ale_data);
}

pub fn ale_layer_accept(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = FieldsAleAuthRecvAcceptV4;
    let ale_data = AleLayerData {
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
        .was_network_packet_injected_by_self(data.get_layer_data() as _)
    {
        data.action_permit();
        return;
    }

    // Check if protocol is supported
    match IpProtocol::from(ale_data.protocol) {
        IpProtocol::Tcp | IpProtocol::Udp => {}
        _ => {
            // Not supported. Send event and permit.
            let conn_info = ale_data.as_connection_info_v4(0);
            let _ = device.primary_queue.push(Box::new(conn_info));
            data.action_permit();
            return;
        }
    }
    if let Some(action) = device.connection_cache.get_connection_action(
        &ale_data.as_key(),
        |conn| -> Option<ConnectionAction> {
            // Is behind spin lock, just copy and return.
            Some(conn.action.clone())
        },
    ) {
        // We already have a verdict for it.
        dbg!(device.logger, "Verdict: {}", action);
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
                        nbl.retreat(IPV4_HEADER_LEN as u32, true);
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
            nbl.retreat(IPV4_HEADER_LEN as u32, true);
            if let Ok(clone) = nbl.clone(&device.network_allocator) {
                packet_list = Some(Injector::from_ale_callout(
                    &data,
                    clone,
                    ale_data.remote_ip.0,
                    true,
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
        let conn_info = ale_data.as_connection_info_v4(id);
        let _ = device.primary_queue.push(Box::new(conn_info));
        let conn = Connection {
            protocol: ale_data.protocol,
            local_address: ale_data.local_ip,
            local_port: ale_data.local_port,
            remote_address: ale_data.remote_ip,
            remote_port: ale_data.remote_port,
            action: ConnectionAction::Verdict(Verdict::Undecided),
            extra: Box::new(ConnectionExtra {
                direction: ale_data.direction,
                endpoint_handle: data.get_transport_endpoint_handle().unwrap_or(0),
                packet_queue: Some(promise),
                callout_id: data.get_callout_id(),
            }),
        };

        device.connection_cache.add_connection(conn);

        data.block_and_absorb();
    }
}

pub fn endpoint_closure(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FieldsAleEndpointClosureV4;
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    let conn = device.connection_cache.remove_connection(
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
        let _ = device.primary_queue.push(info);
    } else {
        err!(
            device.logger,
            "connection not found in cache: pid={}, local={}:{}, remote={}:{}",
            data.get_process_id().unwrap_or(0),
            get_ipv4_address(&data, Fields::IpLocalAddress as usize),
            data.get_value_u16(Fields::IpLocalPort as usize),
            get_ipv4_address(&data, Fields::IpRemoteAddress as usize),
            data.get_value_u16(Fields::IpRemotePort as usize)
        );
    }
}

pub fn ale_resource_monitor_ipv4(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };
    match data.layer {
        layer::Layer::AleResourceAssignmentV4 => {
            type Fields = layer::FieldsAleResourceAssignmentV4;
            info!(
                device.logger,
                "Port {}/{} assigned pid={}",
                data.get_value_u16(Fields::IpLocalPort as usize),
                get_protocol(&data, Fields::IpProtocol as usize),
                data.get_process_id().unwrap_or(0),
            );
        }
        layer::Layer::AleResourceReleaseV4 => {
            type Fields = layer::FieldsAleResourceReleaseV4;
            if let Some(conns) = device.connection_cache.unregister_port((
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
                    let _ = device.primary_queue.push(info);
                }
            }
        }
        _ => {}
    }
}
