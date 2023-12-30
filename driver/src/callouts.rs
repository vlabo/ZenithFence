use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket, IPV4_HEADER_LEN,
};
use wdk::ffi::NET_BUFFER_LIST;
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{self, FwpsFieldsAleAuthConnectV4, FwpsFieldsAleAuthRecvAcceptV4};
use wdk::filter_engine::net_buffer::{
    read_packet, read_packet_partial, NBLIterator, NetworkAllocator,
};
use wdk::filter_engine::packet::Injector;
use wdk::interface;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::connection_cache::Key;
use crate::info;
use crate::logger::Logger;
use crate::types::Direction;
use crate::{
    connection_cache::ConnectionAction,
    dbg,
    device::Device,
    err,
    types::{PacketInfo, Verdict},
};

pub fn ale_layer_connect(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    if device
        .injector
        .was_network_packet_injected_by_self(data.get_layer_data() as _)
    {
        data.action_permit();
        return;
    }

    let mut packet = PacketInfo::from_callout_data(&data);
    info!(device.logger, "Connect callout: {:?}", packet);
    if let Some(connection) = device
        .connection_cache
        .get_connection_action(packet.get_key())
    {
        // We already have a verdict for it.
        match connection.action {
            ConnectionAction::Verdict(verdict) => match verdict {
                Verdict::Accept | Verdict::Redirect => data.action_permit(),
                Verdict::Block => data.action_block(),
                Verdict::Drop | Verdict::Undecided | Verdict::Undeterminable | Verdict::Failed => {
                    data.block_and_absorb()
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
        dbg!(device.logger, "Pend decision");
        let mut packet_list = None;
        if packet.protocol == u8::from(IpProtocol::Udp) {
            packet_list = Some(Injector::from_ale_callout(&data, packet.remote_ip));
        }
        let promise = if data.is_reauthorize(FwpsFieldsAleAuthConnectV4::Flags as usize) {
            data.pend_filter_rest(packet_list)
        } else {
            match data.pend_operation(packet_list) {
                Ok(cc) => cc,
                Err(error) => {
                    err!(device.logger, "failed to postpone decision: {}", error);
                    data.action_permit(); // TODO: Do we need to permit on fail?
                    return;
                }
            }
        };

        // Send request to user-space.
        packet.classify_promise = Some(promise);
        let serialized = device.packet_cache.push_and_serialize(packet);
        if let Ok(bytes) = serialized {
            let _ = device.io_queue.push(bytes);
        }

        data.block_and_absorb();
    }
}

pub fn ale_layer_accept(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    if device
        .injector
        .was_network_packet_injected_by_self(data.get_layer_data() as _)
    {
        data.action_permit();
        return;
    }

    let mut packet = PacketInfo::from_callout_data(&data);
    info!(device.logger, "Accept callout: {:?}", packet);
    if let Some(connection) = device
        .connection_cache
        .get_connection_action(packet.get_key())
    {
        // We already have a verdict for it.
        match connection.action {
            ConnectionAction::Verdict(verdict) => match verdict {
                Verdict::Accept | Verdict::Redirect => data.action_permit(),
                Verdict::Block => data.action_block(),
                Verdict::Drop | Verdict::Undecided | Verdict::Undeterminable | Verdict::Failed => {
                    data.block_and_absorb()
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
        // TODO: check if connection is already pended. As more packets are coming the callout will be called again.
        // Pend decision of connection.
        dbg!(device.logger, "Pend decision");
        let mut packet_list = None;
        if packet.protocol == u8::from(IpProtocol::Udp) {
            packet_list = Some(Injector::from_ale_callout(&data, packet.remote_ip));
        }
        let promise = if data.is_reauthorize(FwpsFieldsAleAuthRecvAcceptV4::Flags as usize) {
            data.pend_filter_rest(packet_list)
        } else {
            match data.pend_operation(packet_list) {
                Ok(cc) => cc,
                Err(error) => {
                    err!(device.logger, "failed to postpone decision: {}", error);
                    data.action_permit(); // TODO: Do we need to permit on fail?
                    return;
                }
            }
        };

        // Send request to user-space.
        packet.classify_promise = Some(promise);
        let serialized = device.packet_cache.push_and_serialize(packet);
        if let Ok(bytes) = serialized {
            let _ = device.io_queue.push(bytes);
        }

        data.block_and_absorb();
    }
}

// TODO: Can redirect_outbound_packet and redirect_inbound_packet be combined?
// TODO: Should this be inside the NBL injector?
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

// TODO: Should this be inside the NBL injector?
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
                dbg!(logger, "injecting packet {} {}", ip_packet, udp_packet);
            }
        }
        if ip_packet.next_header() == IpProtocol::Tcp {
            if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                dbg!(logger, "injecting packet {} {}", ip_packet, tcp_packet);
            }
        }
    }
}

// TODO: Move this to util file?
fn get_key_from_nbl(
    nbl: *mut NET_BUFFER_LIST,
    logger: &mut Logger,
    direction: Direction,
) -> Option<Key> {
    // Get bytes
    let mut headers = [0; smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::TCP_HEADER_LEN];
    let Ok(()) = read_packet_partial(nbl, &mut headers) else {
        err!(logger, "failed to get net_buffer data");
        return None;
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
        _ => {
            return None;
        }
    };

    // Build key
    match direction {
        Direction::Outbound => Some(Key {
            protocol,
            local_address: ip_packet.src_addr(),
            local_port: src_port,
            remote_address: ip_packet.dst_addr(),
            remote_port: dst_port,
        }),
        Direction::Inbound => Some(Key {
            protocol,
            local_address: ip_packet.dst_addr(),
            local_port: dst_port,
            remote_address: ip_packet.src_addr(),
            remote_port: src_port,
        }),
        Direction::NotApplicable => None,
    }
}

pub fn network_layer_outbound(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FwpsFieldsOutboundIppacketV4;

    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    if device
        .injector
        .was_network_packet_injected_by_self(data.get_layer_data() as _)
    {
        data.action_permit();
        return;
    }

    for (_, nbl) in NBLIterator::new(data.get_layer_data() as _).enumerate() {
        // Get key from packet.
        let Some(key) = get_key_from_nbl(nbl, &mut device.logger, Direction::Outbound) else {
            data.action_permit();
            return;
        };

        // Check if there is action for this connection.
        if let Some(connection) = device.connection_cache.get_connection_action(key) {
            // Only redirects have custom behavior.
            if let ConnectionAction::RedirectIP {
                redirect_address,
                redirect_port,
            } = connection.action
            {
                // FIXME: make sure buffer is alive until packet is injected. Move this allocation to the NBL Injector.
                let mut buffer = alloc::vec::Vec::new();
                let Ok(()) = read_packet(nbl, &mut buffer) else {
                    err!(device.logger, "failed to get net_buffer data");
                    data.action_permit();
                    return;
                };
                redirect_outbound_packet(&mut buffer, redirect_address, redirect_port);
                // print_packet(&mut device.logger, &connection.in_packet_buffer);
                if let Ok(nbl) = device.network_allocator.wrap_packet_in_nbl(&buffer) {
                    let packet = Injector::from_ip_callout(
                        nbl,
                        false,
                        redirect_address.is_loopback(),
                        data.get_value_u32(Fields::InterfaceIndex as usize),
                        data.get_value_u32(Fields::SubInterfaceIndex as usize),
                    );
                    _ = device.injector.inject_packet_list_network(packet);
                    data.block_and_absorb();
                    return;
                }
            }
        } else {
            err!(device.logger, "failed to get connection");
        }
    }

    data.action_permit();
}

pub fn network_layer_inbound(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FwpsFieldsInboundIppacketV4;

    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };
    if device
        .injector
        .was_network_packet_injected_by_self(data.get_layer_data() as _)
    {
        data.action_permit();
        return;
    }

    for (_, nbl) in NBLIterator::new(data.get_layer_data() as _).enumerate() {
        // The header is not part of the NBL for incoming packets. Move the beginning of the buffer back so we get access to it.
        // The guard will ensure that it will be advance after we exit the function.
        let _advance_guard =
            NetworkAllocator::retreat_net_buffer(nbl, IPV4_HEADER_LEN as u32, true);

        // Get key from packet.
        let Some(key) = get_key_from_nbl(nbl, &mut device.logger, Direction::Inbound) else {
            data.action_permit();
            return;
        };

        // Check if there is action for this connection.
        if let Some(connection) = device.connection_cache.get_connection_action(key) {
            // Only redirects have custom behavior.
            if let ConnectionAction::RedirectIP {
                redirect_address,
                redirect_port: _,
            } = connection.action
            {
                // FIXME: make sure buffer is alive until packet is injected. Move this allocation to the NBL Injector.
                let mut buffer = alloc::vec::Vec::new(); // TODO: remove allocation for each redirect.
                let Ok(()) = read_packet(nbl, &mut buffer) else {
                    err!(device.logger, "failed to get net_buffer data");
                    data.action_permit();
                    return;
                };

                // print_packet(&mut device.logger, &connection.in_packet_buffer);
                redirect_inbound_packet(
                    &mut buffer,
                    connection.local_address,
                    connection.remote_address,
                    connection.remote_port,
                );
                if let Ok(nbl) = device.network_allocator.wrap_packet_in_nbl(&buffer) {
                    let packet = Injector::from_ip_callout(
                        nbl,
                        false,
                        redirect_address.is_loopback(),
                        data.get_value_u32(Fields::InterfaceIndex as usize),
                        data.get_value_u32(Fields::SubInterfaceIndex as usize),
                    );
                    _ = device.injector.inject_packet_list_network(packet);
                    data.block_and_absorb();
                    return;
                }
            }
        } else {
            err!(device.logger, "failed to get connection");
        }
    }

    data.action_permit();
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
