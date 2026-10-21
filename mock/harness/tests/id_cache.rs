//! Packet id cache ordering and pop semantics.
//!
//! Runs the real driver code (mock/driver) over the mock WDK.

use driver::connection::{Direction, Key};
use driver::device::Packet;
use driver::id_cache::*;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address};
use wdk::filter_engine::net_buffer::NetBufferList;
use wdk::filter_engine::packet::InjectInfo;

fn test_key() -> Key {
    Key {
        protocol: IpProtocol::Tcp,
        local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
        local_port: 1234,
        remote_address: IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)),
        remote_port: 80,
    }
}

fn mk_packet() -> Packet {
    Packet::PacketLayer(
        NetBufferList::owned_from_bytes(vec![0u8; 40]),
        InjectInfo {
            ipv6: false,
            inbound: false,
            loopback: false,
            interface_index: 0,
            sub_interface_index: 0,
            compartment_id: 0,
        },
    )
}

#[test]
fn push_assigns_sequential_ids_and_pops_once() {
    let cache = IdCache::new();
    let k = test_key();
    // ids are assigned sequentially starting at 1.
    for _ in 0..5 {
        cache.push((k, mk_packet()), 1, Direction::Outbound, false);
    }
    assert_eq!(cache.get_entries_count(), 5);

    // The missing-id sentinel is always None.
    assert!(cache.pop_id(PACKET_MISSING_ID).is_none());

    // Pop out of order; each id pops exactly once. This validates that the
    // deque stays sorted by id so `binary_search_by_key` is correct.
    assert!(cache.pop_id(3).is_some());
    assert!(cache.pop_id(3).is_none());
    assert!(cache.pop_id(1).is_some());
    assert!(cache.pop_id(5).is_some());
    assert!(cache.pop_id(99).is_none());

    assert_eq!(cache.get_entries_count(), 2); // ids 2 and 4 remain
    let rest = cache.pop_all();
    assert_eq!(rest.len(), 2);
    assert_eq!(cache.get_entries_count(), 0);
}
