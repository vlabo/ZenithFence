use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address, IPV4_HEADER_LEN, IPV6_HEADER_LEN};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer;
use wdk::filter_engine::net_buffer::NetBufferListIter;
use wdk::filter_engine::packet::InjectInfo;
use wdk::interface;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::connection::{ConnectionV4, ConnectionV6, Direction, PM_DNS_PORT, PM_SPN_PORT};
use crate::packet_util::{
    get_key_from_nbl_v4, get_key_from_nbl_v6, redirect_inbound_packet, redirect_outbound_packet,
};
use crate::{device::Device, err};

// IP packet layers
pub fn ip_packet_layer_outbound_v4(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FieldsOutboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    ip_packet_layer(
        data,
        device_object,
        false,
        Direction::Outbound,
        interface_index,
        sub_interface_index,
    );
}

pub fn ip_packet_layer_inbound_v4(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FieldsInboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    ip_packet_layer(
        data,
        device_object,
        false,
        Direction::Inbound,
        interface_index,
        sub_interface_index,
    );
}

pub fn ip_packet_layer_outbound_v6(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FieldsOutboundIppacketV6;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    ip_packet_layer(
        data,
        device_object,
        true,
        Direction::Outbound,
        interface_index,
        sub_interface_index,
    );
}

pub fn ip_packet_layer_inbound_v6(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FieldsInboundIppacketV6;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    ip_packet_layer(
        data,
        device_object,
        true,
        Direction::Inbound,
        interface_index,
        sub_interface_index,
    );
}

fn ip_packet_layer(
    mut data: CalloutData,
    device_object: &mut DEVICE_OBJECT,
    ipv6: bool,
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
        .was_network_packet_injected_by_self(data.get_layer_data() as _, ipv6)
    {
        return;
    }

    for mut nbl in NetBufferListIter::new(data.get_layer_data() as _) {
        if let Direction::Inbound = direction {
            // The header is not part of the NBL for incoming packets. Move the beginning of the buffer back so we get access to it.
            // The NBL will auto advance after it loses scope.
            if ipv6 {
                nbl.retreat(IPV6_HEADER_LEN as u32, true);
            } else {
                nbl.retreat(IPV4_HEADER_LEN as u32, true);
            }
        }

        // Get key from packet.
        let key = match if ipv6 {
            get_key_from_nbl_v6(&nbl, direction)
        } else {
            get_key_from_nbl_v4(&nbl, direction)
        } {
            Ok(key) => key,
            Err(_) => {
                // Protocol not supported.
                continue;
            }
        };
        // crit!(device.logger, "Packet: {}", key);
        struct ConnectionInfo {
            local_address: IpAddress,
            remote_address: IpAddress,
            remote_port: u16,
            redirect_port: u16,
            unify: bool,
        }
        let redirect_address;
        // Check if packet should be redirected.
        let conn_info = if ipv6 {
            redirect_address = IpAddress::Ipv6(Ipv6Address::LOOPBACK);
            device.connection_cache.get_connection_redirect_v6(
                &key,
                |conn: &ConnectionV6| -> Option<ConnectionInfo> {
                    // Function is is behind spin lock. Just copy and return.
                    match conn.verdict {
                        crate::connection::Verdict::RedirectNameServer => Some(ConnectionInfo {
                            local_address: IpAddress::Ipv6(conn.local_address),
                            remote_address: IpAddress::Ipv6(conn.remote_address),
                            remote_port: conn.remote_port,
                            redirect_port: PM_DNS_PORT,
                            unify: false,
                        }),
                        crate::connection::Verdict::RedirectTunnel => Some(ConnectionInfo {
                            local_address: IpAddress::Ipv6(conn.local_address),
                            remote_address: IpAddress::Ipv6(conn.remote_address),
                            remote_port: conn.remote_port,
                            redirect_port: PM_SPN_PORT,
                            unify: true,
                        }),
                        _ => None,
                    }
                },
            )
        } else {
            redirect_address = IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1));
            device.connection_cache.get_connection_redirect_v4(
                &key,
                |conn: &ConnectionV4| -> Option<ConnectionInfo> {
                    // Function is is behind spin lock. Just copy and return.
                    match conn.verdict {
                        crate::connection::Verdict::RedirectNameServer => Some(ConnectionInfo {
                            local_address: IpAddress::Ipv4(conn.local_address),
                            remote_address: IpAddress::Ipv4(conn.remote_address),
                            remote_port: conn.remote_port,
                            redirect_port: PM_DNS_PORT,
                            unify: false,
                        }),
                        crate::connection::Verdict::RedirectTunnel => Some(ConnectionInfo {
                            local_address: IpAddress::Ipv4(conn.local_address),
                            remote_address: IpAddress::Ipv4(conn.remote_address),
                            remote_port: conn.remote_port,
                            redirect_port: PM_SPN_PORT,
                            unify: true,
                        }),
                        _ => None,
                    }
                },
            )
        };

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
                        redirect_address,
                        conn.redirect_port,
                        conn.unify,
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
            let loopback = !conn.unify;

            let result = device.injector.inject_net_buffer_list(
                clone,
                InjectInfo {
                    ipv6,
                    inbound,
                    loopback,
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
