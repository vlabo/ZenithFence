use alloc::string::{String, ToString};
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
    IPV4_HEADER_LEN, IPV6_HEADER_LEN,
};
use wdk::filter_engine::net_buffer::NetBufferList;

use crate::device::Packet;
use crate::{
    connection::{Direction, Key, RedirectInfo},
    dbg, err,
};

/// `Redirect` is a trait that defines a method for redirecting network packets.
///
/// This trait is used to implement different strategies for redirecting packets,
/// depending on the specific requirements of the application.
pub trait Redirect {
    /// Redirects a network packet based on the provided `RedirectInfo`.
    ///
    /// # Arguments
    ///
    /// * `redirect_info` - A struct containing information about how to redirect the packet.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the packet was successfully redirected.
    /// * `Err(String)` if there was an error redirecting the packet.
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
        // return Err("can't redirect from non packet layer".to_string());
        return Ok(());
    }
}

/// Redirects an outbound packet to a specified remote address and port.
///
/// # Arguments
///
/// * `packet` - A mutable reference to the packet data.
/// * `remote_address` - The IP address to redirect the packet to.
/// * `remote_port` - The port to redirect the packet to.
/// * `unify` - If true, the source and destination addresses of the packet will be set to the same value.
///
/// This function modifies the packet in-place to change its destination address and port.
/// It also updates the checksums for the IP and transport layer headers.
/// If the `unify` parameter is true, it sets the source and destination addresses to be the same.
/// If the remote address is a loopback address, it sets the source address to the loopback address.
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
                        ip_packet.set_src_addr(Ipv6Address::LOCALHOST);
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

/// Redirects an inbound packet to a local address.
///
/// This function takes a mutable reference to a packet and modifies it in place.
/// It changes the destination address to the provided local address and the source address
/// to the original remote address. It also sets the source port to the original remote port.
/// The function handles both IPv4 and IPv6 addresses.
///
/// # Arguments
///
/// * `packet` - A mutable reference to the packet data.
/// * `local_address` - The local IP address to redirect the packet to.
/// * `original_remote_address` - The original remote IP address of the packet.
/// * `original_remote_port` - The original remote port of the packet.
///
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

pub fn recalc_header_checksums(packet: &mut [u8], ipv6: bool) {
    if ipv6 {
        if let Ok(mut ip_packet) = Ipv6Packet::new_checked(packet) {
            let src_addr = ip_packet.src_addr();
            let dst_addr = ip_packet.dst_addr();
            if ip_packet.next_header() == IpProtocol::Udp {
                if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                    udp_packet
                        .fill_checksum(&IpAddress::Ipv6(src_addr), &IpAddress::Ipv6(dst_addr));
                }
            }
            if ip_packet.next_header() == IpProtocol::Tcp {
                if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                    tcp_packet
                        .fill_checksum(&IpAddress::Ipv6(src_addr), &IpAddress::Ipv6(dst_addr));
                }
            }
        }
    } else {
        if let Ok(mut ip_packet) = Ipv4Packet::new_checked(packet) {
            ip_packet.fill_checksum();
            let src_addr = ip_packet.src_addr();
            let dst_addr = ip_packet.dst_addr();
            if ip_packet.next_header() == IpProtocol::Udp {
                if let Ok(mut udp_packet) = UdpPacket::new_checked(ip_packet.payload_mut()) {
                    udp_packet
                        .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                }
            }
            if ip_packet.next_header() == IpProtocol::Tcp {
                if let Ok(mut tcp_packet) = TcpPacket::new_checked(ip_packet.payload_mut()) {
                    tcp_packet
                        .fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
                }
            }
        }
    }
}

#[allow(dead_code)]
fn print_packet(packet: &[u8]) {
    if let Ok(ip_packet) = Ipv4Packet::new_checked(packet) {
        if ip_packet.next_header() == IpProtocol::Udp {
            if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
                dbg!("packet {} {}", ip_packet, udp_packet);
            }
        }
        if ip_packet.next_header() == IpProtocol::Tcp {
            if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                dbg!("packet {} {}", ip_packet, tcp_packet);
            }
        }
    } else {
        err!("failed to print packet: invalid ip header: {:?}", packet);
    }
}

/// This function extracts a key from a given IPv4 network buffer list (NBL).
/// The key contains the protocol, local and remote addresses and ports.
///
/// # Arguments
///
/// * `nbl` - A reference to the network buffer list from which the key will be extracted.
/// * `direction` - The direction of the packet (Inbound or Outbound).
///
/// # Returns
///
/// * `Ok(Key)` - A key containing the protocol, local and remote addresses and ports.
/// * `Err(String)` - An error message if the function fails to get net_buffer data.
fn get_ports(packet: &[u8], protocol: smoltcp::wire::IpProtocol) -> (u16, u16) {
    match protocol {
        smoltcp::wire::IpProtocol::Tcp => {
            let tcp_packet = TcpPacket::new_unchecked(packet);
            (tcp_packet.src_port(), tcp_packet.dst_port())
        }
        smoltcp::wire::IpProtocol::Udp => {
            let udp_packet = UdpPacket::new_unchecked(packet);
            (udp_packet.src_port(), udp_packet.dst_port())
        }
        _ => (0, 0), // No ports for other protocols
    }
}

/// Upper bound on an IPv4 header: the fixed 20 bytes plus the 40 bytes of
/// options that the 4-bit IHL field can express.
const MAX_IPV4_HEADER_LEN: usize = 60;

/// Reads the first `len` bytes of the net buffer into `buffer[..len]`.
///
/// `NetBufferList::read_bytes` always reads from the start of the buffer and
/// fails if the requested length exceeds the packet, so anything past the fixed
/// header (IPv4 options, IPv6 extension headers, the transport header) is
/// reached by reading successively larger prefixes and indexing into them.
fn read_prefix(nbl: &NetBufferList, buffer: &mut [u8], len: usize) -> Result<(), ()> {
    if len > buffer.len() {
        return Err(());
    }
    nbl.read_bytes(&mut buffer[..len])
}

pub fn get_key_from_nbl_v4(nbl: &NetBufferList, direction: Direction) -> Result<Key, String> {
    // Buffer large enough for the largest possible IPv4 header, options included, and the
    // first 4 transport bytes (source + destination ports).
    let mut headers = [0u8; MAX_IPV4_HEADER_LEN + 4];

    // Read the fixed part of the header; it carries the IHL that locates the transport header.
    if read_prefix(nbl, &mut headers, IPV4_HEADER_LEN).is_err() {
        return Err("failed to get net_buffer data".to_string());
    }
    let (src_addr, dst_addr, protocol, header_len) = {
        let ip_packet = Ipv4Packet::new_unchecked(&headers[..IPV4_HEADER_LEN]);
        (
            ip_packet.src_addr(),
            ip_packet.dst_addr(),
            ip_packet.next_header(),
            ip_packet.header_len() as usize,
        )
    };

    // The header length comes from the packet itself, so validate it before using it as an
    // offset. IHL < 5 is malformed; IHL > 15 cannot be expressed in 4 bits.
    if header_len < IPV4_HEADER_LEN || header_len > MAX_IPV4_HEADER_LEN {
        return Err("invalid ipv4 header length".to_string());
    }

    // Parse the layer-4 ports for TCP and UDP. Options sit between the fixed header and the
    // transport header, so the ports are at header_len, which is only IPV4_HEADER_LEN when the
    // packet carries no options.
    let (src_port, dst_port) = if matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        let needed = header_len + 4;
        if read_prefix(nbl, &mut headers, needed).is_err() {
            return Err("failed to read ipv4 transport header".to_string());
        }
        get_ports(&headers[header_len..needed], protocol)
    } else {
        (0, 0)
    };

    // Build key
    match direction {
        Direction::Outbound => Ok(Key {
            protocol,
            local_address: IpAddress::Ipv4(src_addr),
            local_port: src_port,
            remote_address: IpAddress::Ipv4(dst_addr),
            remote_port: dst_port,
        }),
        Direction::Inbound => Ok(Key {
            protocol,
            local_address: IpAddress::Ipv4(dst_addr),
            local_port: dst_port,
            remote_address: IpAddress::Ipv4(src_addr),
            remote_port: src_port,
        }),
    }
}

// NOTE: The IPv6 extension-header parsing below is duplicated in the Linux eBPF
// parser (`get_key_skb` in cmds/ebpf-firewall/modules/headers/key.h). Keep the
// two implementations in sync.

// IPv6 extension-header protocol numbers.
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_DSTOPT: u8 = 60;

/// Bounds the extension-header walk. This is the chain depth (headers stacked in
/// one packet), not the number of header types; a real-world packet almost never
/// stacks more than 2-3.
const MAX_IPV6_EXT_HEADERS: usize = 4;

/// Upper bound on a single extension header's length; anything larger is treated
/// as malformed.
const MAX_IPV6_EXT_HEADER_LEN: usize = 256;

/// This function extracts a key from a given IPv6 network buffer list (NBL).
/// The key contains the protocol, local and remote addresses and ports.
///
/// IPv6 packets may carry a chain of extension headers (Hop-by-Hop, Routing,
/// Fragment, Destination Options) between the fixed header and the transport
/// header. The chain is walked so the key reflects the real transport protocol
/// and ports rather than the first extension header.
///
/// # Arguments
///
/// * `nbl` - A reference to the network buffer list from which the key will be extracted.
/// * `direction` - The direction of the packet (Inbound or Outbound).
///
/// # Returns
///
/// * `Ok(Key)` - A key containing the protocol, local and remote addresses and ports.
/// * `Err(String)` - An error message if the function fails to get net_buffer data
///   or the packet carries a malformed extension-header chain.
pub fn get_key_from_nbl_v6(nbl: &NetBufferList, direction: Direction) -> Result<Key, String> {
    // Buffer large enough for the fixed IPv6 header, the bounded extension-header
    // chain, and the first 4 transport bytes (source + destination ports).
    let mut headers = [0u8; IPV6_HEADER_LEN + MAX_IPV6_EXT_HEADERS * MAX_IPV6_EXT_HEADER_LEN + 4];

    // Read the fixed IPv6 header to get the addresses and the first Next Header.
    if read_prefix(nbl, &mut headers, IPV6_HEADER_LEN).is_err() {
        return Err("failed to get net_buffer data".to_string());
    }
    let (src_addr, dst_addr, mut nexthdr) = {
        let ip_packet = Ipv6Packet::new_unchecked(&headers[..IPV6_HEADER_LEN]);
        (
            ip_packet.src_addr(),
            ip_packet.dst_addr(),
            u8::from(ip_packet.next_header()),
        )
    };

    // l4_offset starts right after the fixed 40-byte IPv6 header.
    let mut l4_offset = IPV6_HEADER_LEN;

    // Walk the extension-header chain until the Next Header is an L4 protocol.
    for _ in 0..MAX_IPV6_EXT_HEADERS {
        // Stop once the current Next Header is not a known extension header; it
        // is then the L4 protocol.
        if nexthdr != IPPROTO_HOPOPTS
            && nexthdr != IPPROTO_ROUTING
            && nexthdr != IPPROTO_FRAGMENT
            && nexthdr != IPPROTO_DSTOPT
        {
            break;
        }

        // Each extension header starts with [next_header:u8][hdr_ext_len:u8].
        if read_prefix(nbl, &mut headers, l4_offset + 2).is_err() {
            return Err("failed to read ipv6 extension header".to_string());
        }
        let ext_next_header = headers[l4_offset];
        let ext_hdr_len_units = headers[l4_offset + 1];

        // Extension-header length is given in 8-octet units, not counting the
        // first 8 octets, so the total length is (hdrlen + 1) * 8.
        let ext_hdr_len = (ext_hdr_len_units as usize + 1) * 8;

        // Reject ridiculously large / malformed headers.
        if ext_hdr_len > MAX_IPV6_EXT_HEADER_LEN {
            return Err("ipv6 extension header too large".to_string());
        }

        // Move past this extension header; its Next Header drives the next step.
        l4_offset += ext_hdr_len;
        nexthdr = ext_next_header;
    }

    // nexthdr now holds the L4 protocol number and l4_offset points at the L4 header.
    let protocol = IpProtocol::from(nexthdr);

    // Parse the layer-4 ports for TCP and UDP.
    let (src_port, dst_port) = if matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        let needed = l4_offset + 4;
        if read_prefix(nbl, &mut headers, needed).is_err() {
            return Err("failed to read ipv6 transport header".to_string());
        }
        get_ports(&headers[l4_offset..needed], protocol)
    } else {
        (0, 0)
    };

    // Build key
    match direction {
        Direction::Outbound => Ok(Key {
            protocol,
            local_address: IpAddress::Ipv6(src_addr),
            local_port: src_port,
            remote_address: IpAddress::Ipv6(dst_addr),
            remote_port: dst_port,
        }),
        Direction::Inbound => Ok(Key {
            protocol,
            local_address: IpAddress::Ipv6(dst_addr),
            local_port: dst_port,
            remote_address: IpAddress::Ipv6(src_addr),
            remote_port: src_port,
        }),
    }
}

// Converts a given key into connection information.
//
// This function takes a key, packet id, process id, and direction as input.
// It then uses these to create a new `ConnectionInfoV6` or `ConnectionInfoV4` object,
// depending on whether the IP addresses in the key are IPv6 or IPv4 respectively.
//
// # Arguments
//
// * `key` - A reference to the key object containing the connection details.
// * `packet_id` - The id of the packet.
// * `process_id` - The id of the process.
// * `direction` - The direction of the connection.
//
// # Returns
//
// * `Some(Box<dyn Info>)` - A boxed `Info` trait object if the key contains valid IPv4 or IPv6 addresses.
// * `None` - If the key does not contain valid IPv4 or IPv6 addresses.
// pub fn key_to_connection_info(
//     key: &Key,
//     packet_id: u64,
//     process_id: u64,
//     direction: Direction,
//     payload: &[u8],
// ) -> Option<Info> {
//     let (local_port, remote_port) = match key.protocol {
//         IpProtocol::Tcp | IpProtocol::Udp => (key.local_port, key.remote_port),
//         _ => (0, 0),
//     };

//     match (key.local_address, key.remote_address) {
//         (IpAddress::Ipv6(local_ip), IpAddress::Ipv6(remote_ip)) if key.is_ipv6() => {
//             Some(protocol::info::connection_info_v6(
//                 packet_id,
//                 process_id,
//                 direction as u8,
//                 u8::from(key.protocol),
//                 local_ip.0,
//                 remote_ip.0,
//                 local_port,
//                 remote_port,
//                 payload,
//             ))
//         }
//         (IpAddress::Ipv4(local_ip), IpAddress::Ipv4(remote_ip)) => {
//             Some(protocol::info::connection_info_v4(
//                 packet_id,
//                 process_id,
//                 direction as u8,
//                 u8::from(key.protocol),
//                 local_ip.0,
//                 remote_ip.0,
//                 local_port,
//                 remote_port,
//                 payload,
//             ))
//         }
//         _ => None,
//     }
// }
