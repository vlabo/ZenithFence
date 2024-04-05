use alloc::boxed::Box;
use alloc::string::{String, ToString};
use protocol::info::{ConnectionInfoV4, ConnectionInfoV6, Info};
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
};
use wdk::filter_engine::net_buffer::NetBufferList;

use crate::connection_map::Key;
use crate::device::Packet;
use crate::{
    connection::{Direction, RedirectInfo},
    dbg, err,
    logger::Logger,
};

pub trait Redirect {
    fn redirect(&mut self, redirect_info: RedirectInfo) -> Result<(), String>;
}

impl Redirect for Packet {
    fn redirect(&mut self, redirect_info: RedirectInfo) -> Result<(), String> {
        if let Packet::PacketLayer(nbl, inject_info) = self {
            let Some(data) = nbl.get_data_mut() else {
                return Err("trying to redirect immutable NBL".to_string());
            };

            if inject_info.inbound {
                redirect_inbound_packet(
                    data,
                    redirect_info.local_address,
                    redirect_info.remote_address,
                    redirect_info.remote_port,
                )
            } else {
                redirect_outbound_packet(
                    data,
                    redirect_info.redirect_address,
                    redirect_info.redirect_port,
                    redirect_info.unify,
                )
            }
            return Ok(());
        }
        // return Err("can't redirect from ale layer".to_string());
        return Ok(());
    }
}

fn redirect_outbound_packet(
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

fn redirect_inbound_packet(
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
    let mut src_port = 0;
    let mut dst_port = 0;
    match ip_packet.next_header() {
        smoltcp::wire::IpProtocol::Tcp => {
            let tcp_packet = TcpPacket::new_unchecked(&headers[smoltcp::wire::IPV4_HEADER_LEN..]);
            src_port = tcp_packet.src_port();
            dst_port = tcp_packet.dst_port();
        }
        smoltcp::wire::IpProtocol::Udp => {
            let udp_packet = UdpPacket::new_unchecked(&headers[smoltcp::wire::IPV4_HEADER_LEN..]);
            src_port = udp_packet.src_port();
            dst_port = udp_packet.dst_port();
        }
        _ => {
            // No ports for other protocols
        }
    };

    // Build key
    match direction {
        Direction::Outbound => Ok(Key {
            protocol: ip_packet.next_header(),
            local_address: IpAddress::Ipv4(ip_packet.src_addr()),
            local_port: src_port,
            remote_address: IpAddress::Ipv4(ip_packet.dst_addr()),
            remote_port: dst_port,
        }),
        Direction::Inbound => Ok(Key {
            protocol: ip_packet.next_header(),
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
    let mut src_port = 0;
    let mut dst_port = 0;
    match ip_packet.next_header() {
        smoltcp::wire::IpProtocol::Tcp => {
            let tcp_packet = TcpPacket::new_unchecked(&headers[smoltcp::wire::IPV6_HEADER_LEN..]);
            src_port = tcp_packet.src_port();
            dst_port = tcp_packet.dst_port();
        }
        smoltcp::wire::IpProtocol::Udp => {
            let udp_packet = UdpPacket::new_unchecked(&headers[smoltcp::wire::IPV6_HEADER_LEN..]);
            src_port = udp_packet.src_port();
            dst_port = udp_packet.dst_port();
        }
        _ => {
            // No ports for other protocols
        }
    };

    // Build key
    match direction {
        Direction::Outbound => Ok(Key {
            protocol: ip_packet.next_header(),
            local_address: IpAddress::Ipv6(ip_packet.src_addr()),
            local_port: src_port,
            remote_address: IpAddress::Ipv6(ip_packet.dst_addr()),
            remote_port: dst_port,
        }),
        Direction::Inbound => Ok(Key {
            protocol: ip_packet.next_header(),
            local_address: IpAddress::Ipv6(ip_packet.dst_addr()),
            local_port: dst_port,
            remote_address: IpAddress::Ipv6(ip_packet.src_addr()),
            remote_port: src_port,
        }),
    }
}

pub fn key_to_connection_info(
    key: &Key,
    packet_id: u64,
    process_id: u64,
    direction: Direction,
) -> Option<Box<dyn Info>> {
    let mut local_port = 0;
    let mut remote_port = 0;
    match key.protocol {
        IpProtocol::Tcp | IpProtocol::Udp => {
            local_port = key.local_port;
            remote_port = key.remote_port;
        }
        _ => {}
    }
    if key.is_ipv6() {
        let IpAddress::Ipv6(local_ip) = key.local_address else {
            return None;
        };
        let IpAddress::Ipv6(remote_ip) = key.remote_address else {
            return None;
        };

        Some(Box::new(ConnectionInfoV6::new(
            packet_id,
            process_id,
            direction as u8,
            u8::from(key.protocol),
            local_ip.0,
            remote_ip.0,
            local_port,
            remote_port,
        )))
    } else {
        let IpAddress::Ipv4(local_ip) = key.local_address else {
            return None;
        };
        let IpAddress::Ipv4(remote_ip) = key.remote_address else {
            return None;
        };

        Some(Box::new(ConnectionInfoV4::new(
            packet_id,
            process_id,
            direction as u8,
            u8::from(key.protocol),
            local_ip.0,
            remote_ip.0,
            local_port,
            remote_port,
        )))
    }
}
