//! Packet parsing / rewriting helpers never panic and keep their invariants.
//!
//! Runs the real driver code (mock/driver) over the mock WDK.

use driver::packet_util::*;
use driver::connection::Direction;
use proptest::prelude::*;
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use wdk::filter_engine::net_buffer::NetBuffer;

fn v6(last: u8) -> Ipv6Address {
    let mut o = [0u8; 16];
    o[15] = last;
    Ipv6Address::from_octets(o)
}

proptest! {
    // The IPv4 key extractor must never panic / read out of bounds on any
    // input, regardless of length (the fixed-size header read guards it).
    #[test]
    fn get_key_v4_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
        inbound in any::<bool>(),
    ) {
        let dir = if inbound { Direction::Inbound } else { Direction::Outbound };
        let nb = NetBuffer::owned_from_bytes(bytes);
        let _ = get_key_from_nb_v4(&nb, dir);
    }

    #[test]
    fn get_key_v6_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
        inbound in any::<bool>(),
    ) {
        let dir = if inbound { Direction::Inbound } else { Direction::Outbound };
        let nb = NetBuffer::owned_from_bytes(bytes);
        let _ = get_key_from_nb_v6(&nb, dir);
    }

    // Inbound/outbound extract a 5-tuple that is the reverse of each other.
    #[test]
    fn get_key_v4_direction_symmetry(
        bytes in proptest::collection::vec(any::<u8>(), 24..64),
    ) {
        let nb_in = NetBuffer::owned_from_bytes(bytes.clone());
        let nb_out = NetBuffer::owned_from_bytes(bytes);
        if let (Ok(k_in), Ok(k_out)) = (
            get_key_from_nb_v4(&nb_in, Direction::Inbound),
            get_key_from_nb_v4(&nb_out, Direction::Outbound),
        ) {
            prop_assert!(k_in == k_out.reverse());
        }
    }

    // recalc_header_checksums must never panic and must be idempotent.
    #[test]
    fn recalc_never_panics_and_idempotent(
        mut bytes in proptest::collection::vec(any::<u8>(), 0..256),
        ipv6 in any::<bool>(),
    ) {
        recalc_header_checksums(&mut bytes, ipv6);
        let after_once = bytes.clone();
        recalc_header_checksums(&mut bytes, ipv6);
        prop_assert_eq!(after_once, bytes);
    }

    // Redirect mutates in place: the packet length must be invariant and it
    // must never panic for any input.
    #[test]
    fn redirect_outbound_len_invariant(
        mut bytes in proptest::collection::vec(any::<u8>(), 0..256),
        port in any::<u16>(),
        unify in any::<bool>(),
        v6_addr in any::<bool>(),
    ) {
        let len_before = bytes.len();
        let addr = if v6_addr {
            IpAddress::Ipv6(Ipv6Address::LOCALHOST)
        } else {
            IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1))
        };
        redirect_outbound_packet(&mut bytes, addr, port, unify);
        prop_assert_eq!(len_before, bytes.len());
    }

    #[test]
    fn redirect_inbound_len_invariant(
        mut bytes in proptest::collection::vec(any::<u8>(), 0..256),
        port in any::<u16>(),
        v6_addr in any::<bool>(),
    ) {
        let len_before = bytes.len();
        let (local, remote) = if v6_addr {
            (IpAddress::Ipv6(Ipv6Address::LOCALHOST), IpAddress::Ipv6(v6(2)))
        } else {
            (
                IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)),
                IpAddress::Ipv4(Ipv4Address::new(8, 8, 8, 8)),
            )
        };
        redirect_inbound_packet(&mut bytes, local, remote, port);
        prop_assert_eq!(len_before, bytes.len());
    }
}
