use smoltcp::wire::{Ipv4Address, IPV4_HEADER_LEN};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer;
use wdk::filter_engine::net_buffer::NetBufferListIter;
use wdk::filter_engine::packet::InjectInfo;
use wdk::interface;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::connection_cache::Connection;
use crate::connection_members::Direction;
use crate::packet_util::{get_key_from_nbl, redirect_inbound_packet, redirect_outbound_packet};
use crate::{connection_cache::ConnectionAction, device::Device, err};

// IP packet layers
pub fn ip_packet_layer_outbound(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FieldsOutboundIppacketV4;
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
    type Fields = layer::FieldsInboundIppacketV4;
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
