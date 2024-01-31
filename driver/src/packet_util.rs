use alloc::{
    format,
    string::{String, ToString},
};
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
};
use wdk::filter_engine::net_buffer::NetBufferList;

use crate::{connection::Direction, connection_cache::Key, dbg, err, logger::Logger};

pub fn redirect_outbound_packet(
    packet: &mut [u8],
    remote_address: IpAddress,
    remote_port: u16,
    unify: bool,
) {
    match remote_address {
        IpAddress::Ipv4(remote_address) => {
            if let Ok(mut ip_packet) = Ipv4Packet::new_checked(packet) {
                if unify {
                    ip_packet.set_dst_addr(ip_packet.src_addr());
                } else {
                    ip_packet.set_dst_addr(remote_address);
                    if remote_address.is_loopback() {
                        ip_packet.set_src_addr(Ipv4Address::new(127, 0, 0, 1));
                    }
                }
                ip_packet.fill_checksum();
                let src_addr = ip_packet.src_addr();
                let dst_addr = ip_packet.dst_addr();
                if ip_packet.next_header() == IpProtocol::Udp {
                    if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                        udp_packet.set_dst_port(remote_port);
                        udp_packet
                            .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                    }
                }
                if ip_packet.next_header() == IpProtocol::Tcp {
                    if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                        tcp_packet.set_dst_port(remote_port);
                        tcp_packet
                            .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                    }
                }
            }
        }
        IpAddress::Ipv6(remote_address) => {
            if let Ok(mut ip_packet) = Ipv6Packet::new_checked(packet) {
                ip_packet.set_dst_addr(remote_address);
                if unify {
                    ip_packet.set_dst_addr(ip_packet.src_addr());
                } else {
                    ip_packet.set_dst_addr(remote_address);
                    if remote_address.is_loopback() {
                        ip_packet.set_src_addr(Ipv6Address::LOOPBACK);
                    }
                }
                let src_addr = ip_packet.src_addr();
                let dst_addr = ip_packet.dst_addr();
                if ip_packet.next_header() == IpProtocol::Udp {
                    if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                        udp_packet.set_dst_port(remote_port);
                        udp_packet
                            .fill_checksum(&IpAddress::Ipv6(src_addr), &IpAddress::Ipv6(dst_addr));
                    }
                }
                if ip_packet.next_header() == IpProtocol::Tcp {
                    if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                        tcp_packet.set_dst_port(remote_port);
                        tcp_packet
                            .fill_checksum(&IpAddress::Ipv6(src_addr), &IpAddress::Ipv6(dst_addr));
                    }
                }
            }
        }
    }
}

pub fn redirect_inbound_packet(
    packet: &mut [u8],
    local_address: IpAddress,
    original_remote_address: IpAddress,
    original_remote_port: u16,
) {
    match local_address {
        IpAddress::Ipv4(local_address) => {
            let IpAddress::Ipv4(original_remote_address) = original_remote_address else {
                return;
            };

            if let Ok(mut ip_packet) = Ipv4Packet::new_checked(packet) {
                ip_packet.set_dst_addr(local_address);
                ip_packet.set_src_addr(original_remote_address);
                ip_packet.fill_checksum();
                let src_addr = ip_packet.src_addr();
                let dst_addr = ip_packet.dst_addr();
                if ip_packet.next_header() == IpProtocol::Udp {
                    if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                        udp_packet.set_src_port(original_remote_port);
                        udp_packet
                            .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                    }
                }
                if ip_packet.next_header() == IpProtocol::Tcp {
                    if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                        tcp_packet.set_src_port(original_remote_port);
                        tcp_packet
                            .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                    }
                }
            }
        }
        IpAddress::Ipv6(local_address) => {
            if let Ok(mut ip_packet) = Ipv6Packet::new_checked(packet) {
                let IpAddress::Ipv6(original_remote_address) = original_remote_address else {
                    return;
                };
                ip_packet.set_dst_addr(local_address);
                ip_packet.set_src_addr(original_remote_address);
                let src_addr = ip_packet.src_addr();
                let dst_addr = ip_packet.dst_addr();
                if ip_packet.next_header() == IpProtocol::Udp {
                    if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                        udp_packet.set_src_port(original_remote_port);
                        udp_packet
                            .fill_checksum(&IpAddress::Ipv6(src_addr), &IpAddress::Ipv6(dst_addr));
                    }
                }
                if ip_packet.next_header() == IpProtocol::Tcp {
                    if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                        tcp_packet.set_src_port(original_remote_port);
                        tcp_packet
                            .fill_checksum(&IpAddress::Ipv6(src_addr), &IpAddress::Ipv6(dst_addr));
                    }
                }
            }
        }
    }
}

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

pub fn get_key_from_nbl_v4(nbl: &NetBufferList, direction: Direction) -> Result<Key, String> {
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
            local_address: IpAddress::Ipv4(ip_packet.src_addr()),
            local_port: src_port,
            remote_address: IpAddress::Ipv4(ip_packet.dst_addr()),
            remote_port: dst_port,
        }),
        Direction::Inbound => Ok(Key {
            protocol,
            local_address: IpAddress::Ipv4(ip_packet.dst_addr()),
            local_port: dst_port,
            remote_address: IpAddress::Ipv4(ip_packet.src_addr()),
            remote_port: src_port,
        }),
    }
}

pub fn get_key_from_nbl_v6(nbl: &NetBufferList, direction: Direction) -> Result<Key, String> {
    // Get bytes
    let mut headers = [0; smoltcp::wire::IPV6_HEADER_LEN + smoltcp::wire::TCP_HEADER_LEN];
    let Ok(()) = nbl.read_bytes(&mut headers) else {
        return Err("failed to get net_buffer data".to_string());
    };

    // Parse packet
    let ip_packet = Ipv6Packet::new_unchecked(&headers);
    let protocol;
    let src_port;
    let dst_port;
    match ip_packet.next_header() {
        smoltcp::wire::IpProtocol::Tcp => {
            let tcp_packet = TcpPacket::new_unchecked(&headers[smoltcp::wire::IPV6_HEADER_LEN..]);
            protocol = smoltcp::wire::IpProtocol::Tcp;
            src_port = tcp_packet.src_port();
            dst_port = tcp_packet.dst_port();
        }
        smoltcp::wire::IpProtocol::Udp => {
            let udp_packet = UdpPacket::new_unchecked(&headers[smoltcp::wire::IPV6_HEADER_LEN..]);
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
            local_address: IpAddress::Ipv6(ip_packet.src_addr()),
            local_port: src_port,
            remote_address: IpAddress::Ipv6(ip_packet.dst_addr()),
            remote_port: dst_port,
        }),
        Direction::Inbound => Ok(Key {
            protocol,
            local_address: IpAddress::Ipv6(ip_packet.dst_addr()),
            local_port: dst_port,
            remote_address: IpAddress::Ipv6(ip_packet.src_addr()),
            remote_port: src_port,
        }),
    }
}
