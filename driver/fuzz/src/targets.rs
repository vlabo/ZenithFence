//! Fuzz-target bodies. Each takes a raw `&[u8]` (what libFuzzer / the replay
//! runner provide) and runs the code under test plus its oracles. A violated
//! oracle panics, which libFuzzer reports as a crash and the replay runner
//! surfaces as a process abort.

use arbitrary::{Arbitrary, Unstructured};
use driver::fuzz_api::{
    fuzz_device_write, fuzz_key_from_bytes_v4, fuzz_key_from_bytes_v6, fuzz_redirect_inbound,
    fuzz_redirect_outbound, new_mock_device, recalc_header_checksums, Device, Direction,
};
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use std::cell::RefCell;

/// The set of valid target names (kept in sync with the functions below).
pub const NAMES: &[&str] = &[
    "packet_key_v4",
    "packet_key_v6",
    "packet_redirect",
    "device_write",
    "protocol_command",
];

/// Dispatch by name. Returns `false` for an unknown target.
pub fn run(name: &str, data: &[u8]) -> bool {
    match name {
        "packet_key_v4" => packet_key_v4(data),
        "packet_key_v6" => packet_key_v6(data),
        "packet_redirect" => packet_redirect(data),
        "device_write" => device_write(data),
        "protocol_command" => protocol_command(data),
        _ => return false,
    }
    true
}

/// IPv4 5-tuple extraction. Oracle: never panic / never read out of bounds.
pub fn packet_key_v4(data: &[u8]) {
    let _ = fuzz_key_from_bytes_v4(data, Direction::Outbound);
    let _ = fuzz_key_from_bytes_v4(data, Direction::Inbound);
}

/// IPv6 5-tuple extraction. Oracle: never panic / never read out of bounds.
pub fn packet_key_v6(data: &[u8]) {
    let _ = fuzz_key_from_bytes_v6(data, Direction::Outbound);
    let _ = fuzz_key_from_bytes_v6(data, Direction::Inbound);
}

#[derive(Arbitrary, Debug)]
struct RedirectInput {
    packet: Vec<u8>,
    v6: bool,
    port: u16,
    unify: bool,
}

fn v6_other() -> Ipv6Address {
    let mut o = [0u8; 16];
    o[15] = 2;
    Ipv6Address::from_octets(o)
}

/// Redirect + checksum mutators. Oracles: no panic / no OOB, length invariant,
/// idempotent checksum recompute.
pub fn packet_redirect(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let Ok(input) = RedirectInput::arbitrary(&mut u) else {
        return;
    };
    let RedirectInput {
        packet,
        v6,
        port,
        unify,
    } = input;

    let (local, remote) = if v6 {
        (
            IpAddress::Ipv6(Ipv6Address::LOCALHOST),
            IpAddress::Ipv6(v6_other()),
        )
    } else {
        (
            IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)),
            IpAddress::Ipv4(Ipv4Address::new(8, 8, 8, 8)),
        )
    };

    let mut outbound = packet.clone();
    let len = outbound.len();
    fuzz_redirect_outbound(&mut outbound, remote, port, unify);
    assert_eq!(len, outbound.len(), "redirect_outbound changed packet length");

    let mut inbound = packet.clone();
    let len = inbound.len();
    fuzz_redirect_inbound(&mut inbound, local, remote, port);
    assert_eq!(len, inbound.len(), "redirect_inbound changed packet length");

    let mut recalc = packet;
    recalc_header_checksums(&mut recalc, v6);
    let once = recalc.clone();
    recalc_header_checksums(&mut recalc, v6);
    assert_eq!(once, recalc, "recalc_header_checksums is not idempotent");
}

thread_local! {
    // Built once and reused across iterations (a few MB to allocate). This also
    // makes it stateful fuzzing of the command handlers and caches.
    static DEVICE: RefCell<Option<Device>> = const { RefCell::new(None) };
}

/// User-space command channel (`Device::write`). Oracle: never panic / no OOB.
pub fn device_write(data: &[u8]) {
    DEVICE.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = new_mock_device().ok();
        }
        if let Some(device) = slot.as_mut() {
            fuzz_device_write(device, data);
        }
    });
}

/// Command wire-format parsers. Oracle: never panic / no OOB for any length.
pub fn protocol_command(data: &[u8]) {
    use protocol::command::{
        parse_type, parse_update_info, parse_update_v4, parse_update_v6, parse_verdict,
    };
    let _ = parse_type(data);
    let _ = parse_verdict(data);
    let _ = parse_update_v4(data);
    let _ = parse_update_v6(data);
    let _ = parse_update_info(data);

    // Also exercise the "skip command byte, parse tail" shape Device::write uses.
    if let Some((_, tail)) = data.split_first() {
        let _ = parse_verdict(tail);
        let _ = parse_update_v4(tail);
        let _ = parse_update_v6(tail);
        let _ = parse_update_info(tail);
    }
}
