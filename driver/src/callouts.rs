use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket, IPV4_HEADER_LEN,
};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{self, FwpsFieldsAleAuthConnectV4};
use wdk::filter_engine::net_buffer::{read_first_packet, NBLIterator, NetworkAllocator};
use wdk::filter_engine::packet::Injector;
use wdk::{dbg, err, interface};
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::{
    connection_cache::ConnectionAction,
    device::Device,
    types::{PacketInfo, Verdict},
};

pub fn ale_layer_connect(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    if device
        .injector
        .was_netwrok_packet_injected_by_self(data.get_layer_data() as _)
    {
        dbg!("injected packet");
        data.action_permit();
        return;
    }

    let mut packet = PacketInfo::from_callout_data(&data);
    dbg!("Connect callout: {:?}", packet);
    if let Some(action) = device
        .connection_cache
        .get_connection_action(packet.local_port, IpProtocol::from(packet.protocol))
    {
        // We already have a verdict for it.
        match action {
            ConnectionAction::Verdict(verdict) => match verdict {
                Verdict::Accept => data.action_permit(),
                Verdict::Block => data.action_block(),
                Verdict::Drop | Verdict::Undecided | Verdict::Undeterminable | Verdict::Failed => {
                    data.block_and_absorb()
                }
            },
            ConnectionAction::RedirectIP {
                local_address,
                original_remote_address,
                original_remote_port,
                remote_address,
                remote_port,
            } => {
                data.action_permit();
            }
        }
    } else {
        // Pend decision of connection.
        let mut packet_list = None;
        if packet.protocol == 17 {
            packet_list = Some(Injector::from_ale_callout(
                &data,
                false,
                packet.remote_ip,
                packet.interface_index,
                packet.sub_interface_index,
            ));
        }
        let promise = if data.is_reauthorize(FwpsFieldsAleAuthConnectV4::Flags as usize) {
            data.pend_filter_rest(packet_list)
        } else {
            match data.pend_operation(packet_list) {
                Ok(cc) => cc,
                Err(error) => {
                    err!("failed to postpone decision: {}", error);
                    return;
                }
            }
        };

        // Send request to userspace.
        packet.classify_promise = Some(promise);
        let serialized = device.packet_cache.push_and_serialize(packet);
        if let Ok(bytes) = serialized {
            let _ = device.io_queue.push(bytes);
        }

        data.block_and_absorb();
    }
}

fn inject_packet(
    device: &mut Device,
    packet: &[u8],
    inbound: bool,
    loopback: bool,
    if_index: u32,
    sub_inf_index: u32,
) -> Result<(), ()> {
    if let Ok(nbl) = device.network_allocator.wrap_packet_in_nbl(&packet) {
        let packet = Injector::from_ip_callout(nbl, inbound, loopback, if_index, sub_inf_index);
        _ = device.injector.inject_packet_list_network(packet);
        return Ok(());
    }
    return Err(());
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

pub fn network_layer_outbound(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FwpsFieldsOutboundIppacketV4;

    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    if device
        .injector
        .was_netwrok_packet_injected_by_self(data.get_layer_data() as _)
    {
        dbg!("injected packet");
        data.action_permit();
        return;
    }

    for (i, nbl) in NBLIterator::new(data.get_layer_data() as _).enumerate() {
        // Get packet data.
        let Ok((full_packet, buffer)) = read_first_packet(nbl) else {
            err!("failed to get net_buffer data");
            data.action_permit();
            return;
        };

        // Parse packet.
        let mut key: Option<(u16, IpProtocol)> = None;
        if let Ok(ip_packet) = Ipv4Packet::new_checked(full_packet) {
            match ip_packet.next_header() {
                smoltcp::wire::IpProtocol::Tcp => {
                    if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                        wdk::info!("packet out {}: {} {}", i, ip_packet, tcp_packet);
                        key = Some((tcp_packet.src_port(), IpProtocol::Tcp))
                    }
                }
                smoltcp::wire::IpProtocol::Udp => {
                    if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
                        wdk::info!("packet out {}: {} {}", i, ip_packet, udp_packet);
                        key = Some((udp_packet.src_port(), IpProtocol::Udp))
                    }
                }
                _ => {
                    err!("unsupported protocol {}: {}", i, ip_packet.next_header());
                }
            }
        } else {
            err!("failed to parse packet");
        };

        let Some((port, protocol)) = key else {
            data.action_permit();
            return;
        };

        // Get action.
        match device
            .connection_cache
            .get_connection_action(port, protocol)
        {
            Some(ConnectionAction::RedirectIP {
                local_address: _,
                original_remote_address: _,
                original_remote_port: _,
                remote_address,
                remote_port,
            }) => {
                let mut buffer = buffer.unwrap_or(full_packet.to_vec());
                redirect_outbound_packet(&mut buffer, remote_address, remote_port);
                if inject_packet(
                    device,
                    &buffer,
                    false,
                    remote_address.is_loopback(),
                    data.get_value_u32(Fields::InterfaceIndex as usize),
                    data.get_value_u32(Fields::SubInterfaceIndex as usize),
                )
                .is_ok()
                {
                    data.block_and_absorb();
                    return;
                }
            }
            _ => {}
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
        .was_netwrok_packet_injected_by_self(data.get_layer_data() as _)
    {
        dbg!("injected packet");
        data.action_permit();
        return;
    }

    for (i, nbl) in NBLIterator::new(data.get_layer_data() as _).enumerate() {
        let mut key: Option<(u16, IpProtocol)> = None;
        NetworkAllocator::retreat_net_buffer(nbl, IPV4_HEADER_LEN as u32); // No idea why this works.
        let Ok((full_packet, buffer)) = read_first_packet(nbl) else {
            err!("failed to get net_buffer data");
            data.action_permit();
            return;
        };
        if let Ok(ip_packet) = Ipv4Packet::new_checked(full_packet) {
            match ip_packet.next_header() {
                smoltcp::wire::IpProtocol::Tcp => {
                    if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                        wdk::info!("packet in {}: {} {}", i, ip_packet, tcp_packet);
                        key = Some((tcp_packet.dst_port(), IpProtocol::Tcp))
                    }
                }
                smoltcp::wire::IpProtocol::Udp => {
                    if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
                        wdk::info!("packet in {}: {} {}", i, ip_packet, udp_packet);
                        key = Some((udp_packet.dst_port(), IpProtocol::Udp))
                    }
                }
                _ => {
                    err!("unsupported protocol {}: {}", i, ip_packet.next_header());
                }
            }
        } else {
            err!("failed to parse packet");
        }
        NetworkAllocator::advance_net_buffer(nbl, IPV4_HEADER_LEN as u32);
        let Some((port, protocol)) = key else {
            data.action_permit();
            return;
        };

        // Get action.
        match device
            .connection_cache
            .get_connection_action(port, protocol)
        {
            Some(ConnectionAction::RedirectIP {
                local_address,
                original_remote_address,
                original_remote_port,
                remote_address,
                remote_port: _,
            }) => {
                let mut buffer = buffer.unwrap_or(full_packet.to_vec());
                redirect_inbound_packet(
                    &mut buffer,
                    local_address,
                    original_remote_address,
                    original_remote_port,
                );
                if inject_packet(
                    device,
                    &buffer,
                    false,
                    remote_address.is_loopback(),
                    data.get_value_u32(Fields::InterfaceIndex as usize),
                    data.get_value_u32(Fields::SubInterfaceIndex as usize),
                )
                .is_ok()
                {
                    data.block_and_absorb();
                    return;
                }
            }
            _ => {}
        }
    }

    data.action_permit();
}
