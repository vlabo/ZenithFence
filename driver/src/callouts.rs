use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket, IPV4_HEADER_LEN,
};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{self, FwpsFieldsAleAuthConnectV4};
use wdk::filter_engine::net_buffer::{
    read_packet, read_packet_partial, NBLIterator, NetworkAllocator,
};
use wdk::filter_engine::packet::Injector;
use wdk::interface;
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::info;
use crate::logger::Logger;
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
        .get_connection_action(packet.local_port, IpProtocol::from(packet.protocol))
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
        if packet.protocol == 17 {
            packet_list = Some(Injector::from_ale_callout(&data, packet.remote_ip));
        }
        let promise = if data.is_reauthorize(FwpsFieldsAleAuthConnectV4::Flags as usize) {
            data.pend_filter_rest(packet_list)
        } else {
            match data.pend_operation(packet_list) {
                Ok(cc) => cc,
                Err(error) => {
                    err!(device.logger, "failed to postpone decision: {}", error);
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
        // Read the headers of the packet. IP and TCP/UDP. Stack allocation should be faster.
        let mut headers = [0; smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::TCP_HEADER_LEN];
        let Ok(()) = read_packet_partial(nbl, &mut headers) else {
            err!(device.logger, "failed to get net_buffer data");
            data.action_permit();
            return;
        };

        // Parse packet.
        let mut key: Option<(u16, IpProtocol)> = None;
        let ip_packet = Ipv4Packet::new_unchecked(&headers);
        match ip_packet.next_header() {
            smoltcp::wire::IpProtocol::Tcp => {
                let tcp_packet =
                    TcpPacket::new_unchecked(&headers[smoltcp::wire::IPV4_HEADER_LEN..]);
                key = Some((tcp_packet.src_port(), IpProtocol::Tcp));
            }
            smoltcp::wire::IpProtocol::Udp => {
                let udp_packet =
                    UdpPacket::new_unchecked(&headers[smoltcp::wire::IPV4_HEADER_LEN..]);
                key = Some((udp_packet.src_port(), IpProtocol::Udp));
            }
            _ => {}
        }

        let Some((port, protocol)) = key else {
            data.action_permit();
            return;
        };

        // Get action.
        if let Some(connection) = device
            .connection_cache
            .get_connection_action(port, protocol)
        {
            if let ConnectionAction::RedirectIP {
                redirect_address,
                redirect_port,
            } = connection.action
            {
                // let mut buffer = Vec::new();
                let Ok(()) = read_packet(nbl, &mut connection.packet_buffer) else {
                    err!(device.logger, "failed to get net_buffer data");
                    data.action_permit();
                    return;
                };
                redirect_outbound_packet(
                    &mut connection.packet_buffer,
                    redirect_address,
                    redirect_port,
                );
                print_packet(&mut device.logger, &connection.in_packet_buffer);
                if let Ok(nbl) = device
                    .network_allocator
                    .wrap_packet_in_nbl(&connection.packet_buffer)
                {
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
        let mut key: Option<(u16, IpProtocol)> = None;
        let _advance_guard =
            NetworkAllocator::retreat_net_buffer(nbl, IPV4_HEADER_LEN as u32, true); // No idea why this works. Only the header is retreated but we get access to the whole packet.

        // Read the headers of the packet. IP and TCP/UDP. Stack allocation should be faster.
        let mut headers = [0; smoltcp::wire::IPV4_HEADER_LEN + smoltcp::wire::TCP_HEADER_LEN];
        let Ok(()) = read_packet_partial(nbl, &mut headers) else {
            err!(device.logger, "failed to get net_buffer data");
            data.action_permit();
            return;
        };

        // Parse headers and get the protocol and destination (local port).
        let ip_packet = Ipv4Packet::new_unchecked(&headers);
        match ip_packet.next_header() {
            smoltcp::wire::IpProtocol::Tcp => {
                let tcp_packet =
                    TcpPacket::new_unchecked(&headers[smoltcp::wire::IPV4_HEADER_LEN..]);
                key = Some((tcp_packet.dst_port(), IpProtocol::Tcp))
            }
            smoltcp::wire::IpProtocol::Udp => {
                let udp_packet =
                    UdpPacket::new_unchecked(&headers[smoltcp::wire::IPV4_HEADER_LEN..]);
                key = Some((udp_packet.dst_port(), IpProtocol::Udp))
            }
            _ => {}
        }

        // Check if we have the needed information to continue.
        let Some((port, protocol)) = key else {
            data.action_permit();
            return;
        };

        // Get action.
        if let Some(connection) = device
            .connection_cache
            .get_connection_action(port, protocol)
        {
            if let ConnectionAction::RedirectIP {
                redirect_address,
                redirect_port: _,
            } = connection.action
            {
                let Ok(()) = read_packet(nbl, &mut connection.in_packet_buffer) else {
                    err!(device.logger, "failed to get net_buffer data");
                    data.action_permit();
                    return;
                };

                print_packet(&mut device.logger, &connection.in_packet_buffer);
                redirect_inbound_packet(
                    &mut connection.in_packet_buffer,
                    connection.local_address,
                    connection.remote_address,
                    connection.remote_port,
                );
                if let Ok(nbl) = device
                    .network_allocator
                    .wrap_packet_in_nbl(&connection.in_packet_buffer)
                {
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
        }
    }

    data.action_permit();
}
