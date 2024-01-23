use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket, IPV4_HEADER_LEN,
};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{self, FwpsFieldsAleAuthConnectV4, FwpsFieldsAleAuthRecvAcceptV4};
use wdk::filter_engine::net_buffer::{NetBufferList, NetBufferListIter};
use wdk::filter_engine::packet::{InjectInfo, Injector};
use wdk::interface;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::connection_cache::{Connection, Key};
use crate::logger::Logger;
use crate::types::Direction;
use crate::{
    connection_cache::ConnectionAction,
    dbg,
    device::Device,
    err,
    types::{PacketInfo, Verdict},
};
use crate::{info, warn};

pub fn ale_layer_connect(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = FwpsFieldsAleAuthConnectV4;

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

    let is_reauthorize = data.is_reauthorize(Fields::Flags as usize);

    let packet = PacketInfo::from_callout_data(&data);
    info!(device.logger, "Connect callout: {:?}", packet);
    if let Some(action) = device.connection_cache.get_connection_action(
        &packet.get_key(),
        |conn| -> Option<ConnectionAction> {
            // Function is is behind spin lock. Just copy and return.
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
                    if packet.protocol == u8::from(IpProtocol::Udp) || is_reauthorize {
                        if let Ok(clone) = NetBufferList::new(data.get_layer_data() as _)
                            .clone(&device.network_allocator)
                        {
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
        if packet.protocol == u8::from(IpProtocol::Udp) || is_reauthorize {
            if let Ok(clone) =
                NetBufferList::new(data.get_layer_data() as _).clone(&device.network_allocator)
            {
                packet_list = Some(Injector::from_ale_callout(
                    &data,
                    clone,
                    packet.remote_ip,
                    false,
                    0, // TODO: remove argument for outbound
                    0, // TODO: remove argument for outbound
                ));
            }
        }
        let promise = if is_reauthorize {
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
        let _ = device.io_queue.push(Box::new(conn_info));

        // Save the connection.
        let mut conn = packet.as_connection(
            ConnectionAction::Verdict(Verdict::Undecided),
            data.get_callout_id(),
        );
        conn.packet_queue = Some(promise);
        device.connection_cache.add_connection(conn);

        data.block_and_absorb();
    }
}

pub fn ale_layer_accept(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = FwpsFieldsAleAuthRecvAcceptV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

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

    let is_reauthorize = data.is_reauthorize(Fields::Flags as usize);

    let packet = PacketInfo::from_callout_data(&data);
    info!(device.logger, "Accept callout: {:?}", packet);
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
                    if packet.protocol == u8::from(IpProtocol::Udp) || is_reauthorize {
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
        if packet.protocol == u8::from(IpProtocol::Udp) || is_reauthorize {
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
        let promise = if is_reauthorize {
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
        let _ = device.io_queue.push(Box::new(conn_info));

        // Save the connection.
        let mut conn = packet.as_connection(
            ConnectionAction::Verdict(Verdict::Undecided),
            data.get_callout_id(),
        );
        conn.packet_queue = Some(promise);
        device.connection_cache.add_connection(conn);

        data.block_and_absorb();
    }
}

// TODO: move this to util file.
fn redirect_outbound_packet(packet: &mut [u8], remote_address: Ipv4Address, remote_port: u16) {
    if let Ok(mut ip_packet) = Ipv4Packet::new_checked(packet) {
        ip_packet.set_dst_addr(remote_address);
        if remote_address.is_loopback() {
            ip_packet.set_src_addr(Ipv4Address::new(127, 0, 0, 1));
        }
        ip_packet.fill_checksum();
        let src_addr = ip_packet.src_addr();
        let dst_addr = ip_packet.dst_addr();
        if ip_packet.next_header() == IpProtocol::Udp {
            if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                udp_packet.set_dst_port(remote_port);
                udp_packet.fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
            }
        }
        if ip_packet.next_header() == IpProtocol::Tcp {
            if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                tcp_packet.set_dst_port(remote_port);
                tcp_packet.fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
            }
        }
    }
}

// TODO: move this to util file.
fn redirect_inbound_packet(
    packet: &mut [u8],
    local_address: Ipv4Address,
    original_remote_address: Ipv4Address,
    original_remote_port: u16,
) {
    if let Ok(mut ip_packet) = Ipv4Packet::new_checked(packet) {
        ip_packet.set_dst_addr(local_address);
        ip_packet.set_src_addr(original_remote_address);
        ip_packet.fill_checksum();
        let src_addr = ip_packet.src_addr();
        let dst_addr = ip_packet.dst_addr();
        if ip_packet.next_header() == IpProtocol::Udp {
            if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                udp_packet.set_src_port(original_remote_port);
                udp_packet.fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
            }
        }
        if ip_packet.next_header() == IpProtocol::Tcp {
            if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                tcp_packet.set_src_port(original_remote_port);
                tcp_packet.fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
            }
        }
    }
}

// TODO: move this to util file.
#[allow(dead_code)]
fn print_packet(logger: &mut Logger, packet: &[u8]) {
    if let Ok(ip_packet) = Ipv4Packet::new_checked(packet) {
        if ip_packet.next_header() == IpProtocol::Udp {
            if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
                dbg!(logger, "packet {} {}", ip_packet, udp_packet);
            }
        }
        if ip_packet.next_header() == IpProtocol::Tcp {
            if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                dbg!(logger, "packet {} {}", ip_packet, tcp_packet);
            }
        }
    } else {
        err!(
            logger,
            "failed to print packet: invalid ip header: {:?}",
            packet
        );
    }
}

// TODO: Move this to util file?
fn get_key_from_nbl(nbl: &NetBufferList, direction: Direction) -> Result<Key, String> {
    // Get bytes
    let mut headers = [0; smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::TCP_HEADER_LEN];
    let Ok(()) = nbl.read_bytes(&mut headers) else {
        return Err("failed to get net_buffer data".to_string());
    };

    // Parse packet
    let ip_packet = Ipv4Packet::new_unchecked(&headers);
    let protocol;
    let src_port;
    let dst_port;
    match ip_packet.next_header() {
        smoltcp::wire::IpProtocol::Tcp => {
            let tcp_packet = TcpPacket::new_unchecked(&headers[smoltcp::wire::IPV4_HEADER_LEN..]);
            protocol = smoltcp::wire::IpProtocol::Tcp;
            src_port = tcp_packet.src_port();
            dst_port = tcp_packet.dst_port();
        }
        smoltcp::wire::IpProtocol::Udp => {
            let udp_packet = UdpPacket::new_unchecked(&headers[smoltcp::wire::IPV4_HEADER_LEN..]);
            protocol = smoltcp::wire::IpProtocol::Udp;
            src_port = udp_packet.src_port();
            dst_port = udp_packet.dst_port();
        }
        protocol => {
            return Err(format!(
                "unsupported protocol: {} {} {}",
                ip_packet.src_addr(),
                ip_packet.dst_addr(),
                protocol
            ));
        }
    };

    // Build key
    match direction {
        Direction::Outbound => Ok(Key {
            protocol,
            local_address: ip_packet.src_addr(),
            local_port: src_port,
            remote_address: ip_packet.dst_addr(),
            remote_port: dst_port,
        }),
        Direction::Inbound => Ok(Key {
            protocol,
            local_address: ip_packet.dst_addr(),
            local_port: dst_port,
            remote_address: ip_packet.src_addr(),
            remote_port: src_port,
        }),
        Direction::NotApplicable => Err("invalid direction".to_string()),
    }
}

pub fn network_layer_outbound(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FwpsFieldsOutboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    network_layer(
        data,
        device_object,
        Direction::Outbound,
        interface_index,
        sub_interface_index,
    );
}

pub fn network_layer_inbound(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FwpsFieldsInboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);

    network_layer(
        data,
        device_object,
        Direction::Inbound,
        interface_index,
        sub_interface_index,
    );
}

fn network_layer(
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
            Err(err) => {
                let packet = PacketInfo::from_callout_data(&data);
                warn!(device.logger, "error reading key: {}", err);
                warn!(device.logger, "             data: {:?}", packet);
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

pub fn ale_resource_monitor_ipv4(data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    let packet = PacketInfo::from_callout_data(&data);
    match data.layer {
        layer::Layer::FwpmLayerAleResourceAssignmentV4 => {
            info!(
                device.logger,
                "Port {}/{} assigned pid={}",
                packet.local_port,
                packet.protocol,
                packet.process_id.unwrap_or(0)
            );
        }
        layer::Layer::FwpmLayerAleResourceReleaseV4 => {
            if device
                .connection_cache
                .unregister_port((IpProtocol::from(packet.protocol), packet.local_port))
                .is_some()
            {
                info!(
                    device.logger,
                    "Port {}/{} released pid={}",
                    packet.local_port,
                    packet.protocol,
                    packet.process_id.unwrap_or(0)
                );
            } else {
                info!(
                    device.logger,
                    "Port {}/{} released pid={} (was not in the cache)",
                    packet.local_port,
                    packet.protocol,
                    packet.process_id.unwrap_or(0)
                );
            }
        }
        _ => {}
    }
}
