use alloc::boxed::Box;
use protocol::info::ConnectionEndEventV4Info;
use smoltcp::wire::{IpProtocol, Ipv4Address, IPV4_HEADER_LEN};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{self, FwpsFieldsAleAuthConnectV4, FwpsFieldsAleAuthRecvAcceptV4};
use wdk::filter_engine::net_buffer::{NetBufferList, NetBufferListIter};
use wdk::filter_engine::packet::{InjectInfo, Injector};
use wdk::interface;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::connection_cache::Connection;
use crate::packet_util::{get_key_from_nbl, redirect_inbound_packet, redirect_outbound_packet};
use crate::types::Direction;
use crate::{
    connection_cache::ConnectionAction,
    dbg,
    device::Device,
    err,
    types::{PacketInfo, Verdict},
};

// ALE Layers

pub fn ale_layer_connect(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = FwpsFieldsAleAuthConnectV4;
    let reauthorize = data.is_reauthorize(Fields::Flags as usize);
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);
    ale_layer_auth(
        data,
        device_object,
        reauthorize,
        interface_index,
        sub_interface_index,
    );
}

pub fn ale_layer_accept(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = FwpsFieldsAleAuthRecvAcceptV4;
    let reauthorize = data.is_reauthorize(Fields::Flags as usize);
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);
    ale_layer_auth(
        data,
        device_object,
        reauthorize,
        interface_index,
        sub_interface_index,
    );
}

pub fn ale_layer_auth(
    mut data: CalloutData,
    device_object: &mut DEVICE_OBJECT,
    reauthorize: bool,
    interface_index: u32,
    sub_interface_index: u32,
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

    let packet = PacketInfo::from_callout_data(&data);

    // Check if protocol is supported
    match IpProtocol::from(packet.protocol) {
        IpProtocol::Tcp | IpProtocol::Udp => {}
        _ => {
            // Not supported. Send event and permit.
            let conn_info = packet.as_connection_info(0);
            let _ = device.primary_queue.push(Box::new(conn_info));
            data.action_permit();
            return;
        }
    }
    if let Some(action) = device.connection_cache.get_connection_action(
        &packet.get_key(),
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
                    if packet.protocol == u8::from(IpProtocol::Udp) || reauthorize {
                        let mut nbl = NetBufferList::new(data.get_layer_data() as _);
                        nbl.retreat(IPV4_HEADER_LEN as u32, true);
                        if let Ok(clone) = nbl.clone(&device.network_allocator) {
                            device
                                .connection_cache
                                .push_packet_to_connection(packet.get_key(), clone);
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
        if packet.protocol == u8::from(IpProtocol::Udp) || reauthorize {
            let mut nbl = NetBufferList::new(data.get_layer_data() as _);
            nbl.retreat(IPV4_HEADER_LEN as u32, true);
            if let Ok(clone) = nbl.clone(&device.network_allocator) {
                packet_list = Some(Injector::from_ale_callout(
                    &data,
                    clone,
                    packet.remote_ip,
                    true,
                    interface_index,
                    sub_interface_index,
                ));
            }
        }
        let promise = if reauthorize {
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
        let id = device.packet_cache.push(packet.clone());
        let conn_info = packet.as_connection_info(id);
        let _ = device.primary_queue.push(Box::new(conn_info));

        // Save the connection.
        let mut conn = packet.as_connection(
            ConnectionAction::Verdict(Verdict::Undecided),
            data.get_callout_id(),
            data.get_transport_endpoint_handle().unwrap_or(0),
        );
        conn.packet_queue = Some(promise);
        device.connection_cache.add_connection(conn);

        data.block_and_absorb();
    }
}

pub fn endpoint_closure(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    let packet = PacketInfo::from_callout_data(&data);
    let conn = device.connection_cache.remove_connection(
        (IpProtocol::from(packet.protocol), packet.local_port),
        data.get_transport_endpoint_handle().unwrap_or(0),
    );
    if let Some(conn) = conn {
        let mut local_ip: [u8; 4] = [0; 4];
        local_ip.copy_from_slice(conn.local_address.as_bytes());
        let mut remote_ip: [u8; 4] = [0; 4];
        remote_ip.copy_from_slice(conn.remote_address.as_bytes());
        let info = Box::new(ConnectionEndEventV4Info::new(
            packet.process_id.unwrap_or(0),
            conn.direction as u8,
            packet.protocol,
            local_ip,
            remote_ip,
            conn.local_port,
            conn.remote_port,
        ));
        let _ = device.primary_queue.push(info);
    }
}

// IP packet layer

pub fn ip_packet_layer_outbound(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FwpsFieldsOutboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    ip_packet_layer(
        data,
        device_object,
        Direction::Outbound,
        interface_index,
        sub_interface_index,
    );
}

pub fn ip_packet_layer_inbound(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FwpsFieldsInboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    ip_packet_layer(
        data,
        device_object,
        Direction::Inbound,
        interface_index,
        sub_interface_index,
    );
}

fn ip_packet_layer(
    mut data: CalloutData,
    device_object: &mut DEVICE_OBJECT,
    direction: Direction,
    interface_index: u32,
    sub_interface_index: u32,
) {
    // Set default action to permit. If redirect happens it will override the flag.
    data.action_permit();
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };
    if device
        .injector
        .was_network_packet_injected_by_self(data.get_layer_data() as _)
    {
        return;
    }

    for mut nbl in NetBufferListIter::new(data.get_layer_data() as _) {
        if let Direction::Inbound = direction {
            // The header is not part of the NBL for incoming packets. Move the beginning of the buffer back so we get access to it.
            // The net buffer list will auto advance after it loses scope.
            nbl.retreat(IPV4_HEADER_LEN as u32, true);
        }

        // Get key from packet.
        let key = match get_key_from_nbl(&nbl, direction) {
            Ok(key) => key,
            Err(_) => {
                // Protocol not supported.
                continue;
            }
        };
        struct ConnectionInfo {
            local_address: Ipv4Address,
            remote_address: Ipv4Address,
            remote_port: u16,
            redirect_address: Ipv4Address,
            redirect_port: u16,
        }
        // Check if packet should be redirected.
        let conn_info = device.connection_cache.get_connection_action(
            &key,
            |conn: &Connection| -> Option<ConnectionInfo> {
                // Function is is behind spin lock. Just copy and return.
                if let ConnectionAction::RedirectIP {
                    redirect_address,
                    redirect_port,
                } = conn.action
                {
                    return Some(ConnectionInfo {
                        local_address: conn.local_address,
                        remote_address: conn.remote_address,
                        remote_port: conn.remote_port,
                        redirect_address,
                        redirect_port,
                    });
                }
                None
            },
        );

        // Check if there is action for this connection.
        if let Some(conn) = conn_info {
            // Only redirects have custom behavior.
            // Clone net buffer so it can be modified.
            let mut clone = match nbl.clone(&device.network_allocator) {
                Ok(clone) => clone,
                Err(err) => {
                    err!(device.logger, "failed to clone net buffer: {}", err);
                    // TODO: should the error action be permit?
                    continue;
                }
            };

            // print_packet(&mut device.logger, &connection.in_packet_buffer);
            let mut inbound = false;
            match direction {
                Direction::Outbound => {
                    redirect_outbound_packet(
                        clone.get_data_mut().unwrap(),
                        conn.redirect_address,
                        conn.redirect_port,
                    );
                }
                Direction::Inbound => {
                    redirect_inbound_packet(
                        clone.get_data_mut().unwrap(),
                        conn.local_address,
                        conn.remote_address,
                        conn.remote_port,
                    );
                    inbound = true;
                }
                Direction::NotApplicable => {}
            }

            let result = device.injector.inject_net_buffer_list(
                clone,
                InjectInfo {
                    inbound,
                    loopback: conn.redirect_address.is_loopback(),
                    interface_index,
                    sub_interface_index,
                },
            );

            if let Err(err) = result {
                err!(device.logger, "failed to inject net buffer: {}", err);
            }

            // TODO: should it block on failed inject?
            data.block_and_absorb();
        }
    }
}
