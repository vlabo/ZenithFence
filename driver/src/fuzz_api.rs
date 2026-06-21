//! Public test/fuzz surface for the `driver` crate.
//!
//! Compiled only under the `mock` feature, so it is never part of the
//! production driver's public API. It re-exports the packet-handling functions
//! (some of which are `pub(crate)`) and provides small constructors that build
//! mock inputs, so external fuzz targets (in the `fuzz/` crate) can drive the
//! driver without knowing the internal module layout.
#![allow(missing_docs)]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};

use protocol::command::CommandType;
use wdk::filter_engine::callout_data::{CalloutData, Value};
use wdk::filter_engine::classify::ClassifyOut;
use wdk::filter_engine::layer::{self, Layer};
use wdk::irp_helpers::{ReadRequest, WriteRequest};

pub use crate::connection::{Direction, Key, Verdict};
pub use crate::device::{Device, Packet};
pub use crate::entry::{clear_device, get_device, set_device};
pub use crate::packet_util::{get_key_from_nbl_v4, get_key_from_nbl_v6, recalc_header_checksums};

// Re-export the mock NBL type so fuzz targets can construct packet buffers.
pub use wdk::driver::Driver;
pub use wdk::filter_engine::net_buffer::{NetBufferList, NET_BUFFER_LIST};
// Re-export the classify action constants so the callout fuzz target can assert
// the verdict an action produced without depending on `wdk`/`mock_wdk` directly.
pub use wdk::filter_engine::classify::{FWP_ACTION_BLOCK, FWP_ACTION_PERMIT};

/// Fuzz `get_ports` directly on an arbitrary transport-header slice.
pub fn fuzz_get_ports(packet: &[u8], protocol: IpProtocol) -> (u16, u16) {
    crate::packet_util::get_ports(packet, protocol)
}

/// Fuzz the outbound redirect path on an arbitrary packet buffer (in place).
pub fn fuzz_redirect_outbound(
    packet: &mut [u8],
    remote_address: IpAddress,
    remote_port: u16,
    unify: bool,
) {
    crate::packet_util::redirect_outbound_packet(packet, remote_address, remote_port, unify);
}

/// Fuzz the inbound redirect path on an arbitrary packet buffer (in place).
pub fn fuzz_redirect_inbound(
    packet: &mut [u8],
    local_address: IpAddress,
    original_remote_address: IpAddress,
    original_remote_port: u16,
) {
    crate::packet_util::redirect_inbound_packet(
        packet,
        local_address,
        original_remote_address,
        original_remote_port,
    );
}

/// Build an owned mock `NetBufferList` from raw bytes and extract the IPv4 key.
pub fn fuzz_key_from_bytes_v4(bytes: &[u8], direction: Direction) -> Result<Key, String> {
    let nbl = NetBufferList::owned_from_bytes(bytes.to_vec());
    get_key_from_nbl_v4(&nbl, direction)
}

/// Build an owned mock `NetBufferList` from raw bytes and extract the IPv6 key.
pub fn fuzz_key_from_bytes_v6(bytes: &[u8], direction: Direction) -> Result<Key, String> {
    let nbl = NetBufferList::owned_from_bytes(bytes.to_vec());
    get_key_from_nbl_v6(&nbl, direction)
}

/// Construct a mock `Device` for end-to-end harnesses (command channel / callouts).
pub fn new_mock_device() -> Result<Device, String> {
    let driver = Driver::mock();
    Device::new(&driver)
}

/// Feed an arbitrary byte buffer into the user-space command channel
/// (`Device::write`). Mirrors what a `handle.Write` from user space does.
pub fn fuzz_device_write(device: &mut Device, command_bytes: &[u8]) {
    let mut write_request = wdk::irp_helpers::WriteRequest::from_bytes(command_bytes);
    device.write(&mut write_request);
}

/// Convenience: collect a `Vec<u8>` packet into an owned NBL (for redirect tests
/// that go through the `Redirect for Packet` trait).
pub fn owned_nbl(bytes: Vec<u8>) -> NetBufferList {
    NetBufferList::owned_from_bytes(bytes)
}

// ============================================================================
// Callout fuzzing surface
//
// Drives the real ALE and packet-layer callout entry points (`ale_layer_*`,
// `ip_packet_layer_*`, `endpoint_closure_*`, `ale_resource_monitor`) against a
// live `Device` installed in the global slot, exactly like the kernel does.
//
// All the mock-fidelity rules live here in ONE place: the classify `values`
// vector must be sized to the layer's `Fields::Max` (the mock indexes it and
// panics otherwise), each field must use the matching `Value` variant (else the
// mock silently reads 0 and keys don't match), and inbound NBLs need a
// `data_offset` that covers the headers the callout retreats past. The fuzz
// crate only decodes an op stream and asserts oracles -- it never touches these
// invariants.
// ============================================================================

/// Outcome of one callout invocation, as observed on the `ClassifyOut`.
#[derive(Clone, Copy)]
pub struct CalloutResult {
    /// The action the callout set (`0` if it left none, e.g. on a parse error).
    pub action: u32,
    /// Whether the callout set the ABSORB flag.
    pub absorb: bool,
}

/// Number of distinct connection slots the fuzzer can address. The slot index
/// (op byte `conn` mod `POOL_SIZE`) selects a *stable* 5-tuple so the
/// ALE-pend -> verdict -> packet-layer pipeline links up across ops (fully
/// random tuples would never collide). The pool is deliberately diverse and
/// spans the whole address space (see `pool_v4`/`pool_v6`) so coverage is wide
/// while collisions stay common. The last slot is always a loopback connection
/// (special-cased by ALE). Fully fuzzer-controlled, arbitrary-range packets are
/// exercised separately via the `raw` packet path (the bytes become the packet
/// verbatim, so `get_key_from_nbl` parses arbitrary addresses/ports/protocols).
pub const POOL_SIZE: u8 = 64;

const IP4_HDR: u32 = 20;
const IP6_HDR: u32 = 40;
const TP_HDR: u32 = 20;

#[derive(Clone, Copy)]
struct TupleV4 {
    proto: IpProtocol,
    local: Ipv4Address,
    lport: u16,
    remote: Ipv4Address,
    rport: u16,
}

#[derive(Clone, Copy)]
struct TupleV6 {
    proto: IpProtocol,
    local: Ipv6Address,
    lport: u16,
    remote: Ipv6Address,
    rport: u16,
}

/// Deterministic 32-bit mix (splitmix-style), used to spread slot indices over
/// the entire address/port space.
fn mix32(x: u32) -> u32 {
    let mut z = x.wrapping_mul(0x9E37_79B1).wrapping_add(0x7F4A_7C15);
    z = (z ^ (z >> 16)).wrapping_mul(0x85EB_CA6B);
    z = (z ^ (z >> 13)).wrapping_mul(0xC2B2_AE35);
    z ^ (z >> 16)
}

fn proto_from_sel(sel: u8) -> IpProtocol {
    // Keep TCP/UDP frequent so the connection-tracked pipeline links; still
    // cover ICMP and arbitrary "other" protocol numbers (not connection-tracked).
    match sel % 8 {
        0 | 1 | 2 => IpProtocol::Tcp,
        3 | 4 | 5 => IpProtocol::Udp,
        6 => IpProtocol::Icmp,
        _ => IpProtocol::from(sel),
    }
}

fn ports_for(proto: IpProtocol, lport: u16, rport: u16) -> (u16, u16) {
    match proto {
        IpProtocol::Tcp | IpProtocol::Udp => (lport, rport),
        _ => (0, 0),
    }
}

/// Whether a `proto_sel` op byte maps to a connection-tracked protocol
/// (TCP/UDP). Kept here so the callout fuzz oracle doesn't hard-code the private
/// `proto_from_sel` mapping: a *structured* TCP/UDP packet always parses, so the
/// packet callout must set an action.
pub fn proto_is_connectable(proto_sel: u8) -> bool {
    matches!(proto_from_sel(proto_sel), IpProtocol::Tcp | IpProtocol::Udp)
}

// IPv6 address with a 2-byte prefix and a one-byte tail (rest zero).
fn v6_prefix(p0: u8, p1: u8, last: u8) -> Ipv6Address {
    Ipv6Address::from_octets([p0, p1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last])
}

// Full-spread IPv6 address derived from a seed (covers the whole v6 space).
fn v6_from_seed(seed: u32) -> Ipv6Address {
    let mut o = [0u8; 16];
    let mut s = seed;
    for chunk in o.chunks_mut(4) {
        s = mix32(s);
        chunk.copy_from_slice(&s.to_be_bytes());
    }
    Ipv6Address::from_octets(o)
}

fn pool_v4(conn: u8, proto_sel: u8) -> TupleV4 {
    let c = conn % POOL_SIZE;
    // Curated low slots (clean flows + edge cases), computed full-range middle
    // slots, loopback always last. Slots 0/1 stay clean+distinct (the native
    // pipeline test relies on them). Ports apply only to TCP/UDP (see ports_for).
    let (local, remote, lport, rport) = match c {
        0 => (Ipv4Address::new(10, 0, 0, 1), Ipv4Address::new(93, 184, 216, 34), 1000, 8000),
        1 => (Ipv4Address::new(10, 0, 0, 2), Ipv4Address::new(8, 8, 8, 8), 1001, 8001),
        2 => (Ipv4Address::new(192, 168, 1, 5), Ipv4Address::new(1, 1, 1, 1), 53, 53),
        3 => (Ipv4Address::new(172, 16, 0, 9), Ipv4Address::new(140, 82, 121, 4), 443, 50000),
        4 => (Ipv4Address::new(169, 254, 0, 7), Ipv4Address::new(169, 254, 0, 8), 5353, 5353),
        5 => (Ipv4Address::new(100, 64, 0, 1), Ipv4Address::new(203, 0, 113, 9), 717, 1),
        6 => (Ipv4Address::new(0, 0, 0, 0), Ipv4Address::new(255, 255, 255, 255), 0, 65535),
        7 => (Ipv4Address::new(10, 0, 0, 3), Ipv4Address::new(224, 0, 0, 251), 5353, 5353),
        _ if c == POOL_SIZE - 1 => {
            (Ipv4Address::new(127, 0, 0, 1), Ipv4Address::new(127, 0, 0, 2), 1000, 8000)
        }
        _ => {
            let a = mix32(c as u32 * 2);
            let b = mix32(c as u32 * 2 + 1);
            (
                Ipv4Address::from_octets(a.to_be_bytes()),
                Ipv4Address::from_octets(b.to_be_bytes()),
                (a >> 16) as u16,
                (b & 0xffff) as u16,
            )
        }
    };
    TupleV4 {
        proto: proto_from_sel(proto_sel),
        local,
        lport,
        remote,
        rport,
    }
}

fn pool_v6(conn: u8, proto_sel: u8) -> TupleV6 {
    let c = conn % POOL_SIZE;
    let (local, remote, lport, rport) = match c {
        0 => (v6_prefix(0x20, 0x01, 1), v6_prefix(0x20, 0x01, 0x80), 1000, 8000),
        1 => (v6_prefix(0x20, 0x01, 2), v6_prefix(0x20, 0x01, 0x88), 1001, 8001),
        2 => (v6_prefix(0xfe, 0x80, 1), v6_prefix(0xfe, 0x80, 2), 53, 53), // link-local
        3 => (v6_prefix(0xfc, 0x00, 1), v6_prefix(0x20, 0x01, 0x90), 443, 50000), // ULA
        4 => (v6_prefix(0xff, 0x02, 1), v6_prefix(0x20, 0x01, 0x91), 5353, 5353), // multicast
        5 => (Ipv6Address::from_octets([0u8; 16]), v6_prefix(0x20, 0x01, 0x92), 0, 65535),
        _ if c == POOL_SIZE - 1 => {
            (Ipv6Address::LOCALHOST, v6_prefix(0x20, 0x01, 0x88), 1000, 8000)
        }
        _ => {
            let a = mix32(c as u32 * 2 + 0x6000);
            let b = mix32(c as u32 * 2 + 0x6001);
            (
                v6_from_seed(a),
                v6_from_seed(b),
                (a >> 16) as u16,
                (b & 0xffff) as u16,
            )
        }
    };
    TupleV6 {
        proto: proto_from_sel(proto_sel),
        local,
        lport,
        remote,
        rport,
    }
}

fn key_v4(t: &TupleV4) -> Key {
    let (local_port, remote_port) = ports_for(t.proto, t.lport, t.rport);
    Key {
        protocol: t.proto,
        local_address: IpAddress::Ipv4(t.local),
        local_port,
        remote_address: IpAddress::Ipv4(t.remote),
        remote_port,
    }
}

fn key_v6(t: &TupleV6) -> Key {
    let (local_port, remote_port) = ports_for(t.proto, t.lport, t.rport);
    Key {
        protocol: t.proto,
        local_address: IpAddress::Ipv6(t.local),
        local_port,
        remote_address: IpAddress::Ipv6(t.remote),
        remote_port,
    }
}

fn reauth_flag(reauthorize: bool) -> u32 {
    if reauthorize {
        wdk::consts::FWP_CONDITION_FLAG_IS_REAUTHORIZE
    } else {
        0
    }
}

// Build an IPv4 packet whose extracted 5-tuple is `t` for the given direction.
// `raw` returns the fuzzer bytes verbatim instead, to exercise the in-callout
// parser on garbage. `get_key_from_nbl_v4` uses `next_header`, addresses and the
// first 4 transport bytes (ports); the rest is padding/payload.
fn build_packet_v4(t: &TupleV4, direction: Direction, payload: &[u8], raw: bool) -> Vec<u8> {
    if raw {
        return payload.to_vec();
    }
    let (src, dst, sport, dport) = match direction {
        Direction::Outbound => (t.local, t.remote, t.lport, t.rport),
        Direction::Inbound => (t.remote, t.local, t.rport, t.lport),
    };
    let mut p = alloc::vec![0u8; 40]; // IPv4 header (20) + room for a TCP/UDP header
    p[0] = 0x45; // version 4, IHL 5
    p[9] = u8::from(t.proto);
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(payload);
    let total = (p.len() as u16).to_be_bytes();
    p[2..4].copy_from_slice(&total);
    p
}

fn build_packet_v6(t: &TupleV6, direction: Direction, payload: &[u8], raw: bool) -> Vec<u8> {
    if raw {
        return payload.to_vec();
    }
    let (src, dst, sport, dport) = match direction {
        Direction::Outbound => (t.local, t.remote, t.lport, t.rport),
        Direction::Inbound => (t.remote, t.local, t.rport, t.lport),
    };
    let mut p = alloc::vec![0u8; 44]; // IPv6 header (40) + 4 bytes of ports
    p[0] = 0x60; // version 6
    p[6] = u8::from(t.proto); // next header
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40..42].copy_from_slice(&sport.to_be_bytes());
    p[42..44].copy_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(payload);
    let payload_len = ((p.len() - 40) as u16).to_be_bytes();
    p[4..6].copy_from_slice(&payload_len);
    p
}

// Build the mock CalloutData around `values` + `packet`, run `callout`, and
// report what it wrote to the ClassifyOut. The NBL box and ClassifyOut outlive
// the borrow taken by `CalloutData` (raw pointers), so they are read afterwards.
fn drive<F>(
    layer: Layer,
    values: Vec<Value>,
    process_id: Option<u64>,
    packet: Vec<u8>,
    data_offset: usize,
    ip_header_size: u32,
    transport_header_size: u32,
    callout: F,
) -> CalloutResult
where
    F: FnOnce(CalloutData),
{
    let mut nbl = NET_BUFFER_LIST::new_box(packet, data_offset);
    let mut classify_out = ClassifyOut::new();
    {
        let data = CalloutData::mock(
            layer,
            values,
            process_id,
            &mut classify_out as *mut _,
            nbl.as_mut() as *mut _,
            ip_header_size,
            transport_header_size,
        );
        callout(data);
    }
    // `nbl` is owned here and only dropped at end of scope; the callout has
    // returned, so reading `classify_out` is sound.
    drop(nbl);
    CalloutResult {
        action: classify_out.action(),
        absorb: classify_out.is_absorb(),
    }
}

// ---- Device lifecycle / observers ----------------------------------------

/// Install a fresh mock `Device` in the global slot if none is present. The
/// callout fuzz target keeps one device for the whole process (persistent
/// stateful fuzzing), so this is a no-op after the first call.
pub fn ensure_device() {
    if crate::entry::get_device().is_none() {
        if let Ok(device) = new_mock_device() {
            crate::entry::set_device(Box::into_raw(Box::new(device)));
        }
    }
}

/// Number of packets currently pending in the id/packet cache.
pub fn packet_cache_len() -> usize {
    crate::entry::get_device()
        .map(|device| device.packet_cache.get_entries_count())
        .unwrap_or(0)
}

/// Number of active (not-yet-ended) connections in the connection cache.
pub fn active_conn_count() -> usize {
    crate::entry::get_device()
        .map(|device| device.connection_cache.get_entries_count().0)
        .unwrap_or(0)
}

/// Snapshot of packet ids currently pending, for issuing matching verdicts.
pub fn live_ids() -> Vec<u64> {
    crate::entry::get_device()
        .map(|device| device.packet_cache.fuzz_live_ids())
        .unwrap_or_default()
}

/// The verdict the connection cache currently holds for pool connection
/// `(conn, proto_sel)`, if any. Used as the cross-layer (Tier-3) oracle: the
/// packet layer's action for this flow must agree with this verdict.
pub fn verdict_for_v4(conn: u8, proto_sel: u8) -> Option<u8> {
    let key = key_v4(&pool_v4(conn, proto_sel));
    crate::entry::get_device()?
        .connection_cache
        .get_verdict(&key)
        .map(|verdict| verdict as u8)
}

pub fn verdict_for_v6(conn: u8, proto_sel: u8) -> Option<u8> {
    let key = key_v6(&pool_v6(conn, proto_sel));
    crate::entry::get_device()?
        .connection_cache
        .get_verdict(&key)
        .map(|verdict| verdict as u8)
}

// ---- ALE callouts ---------------------------------------------------------

pub fn run_ale_connect_v4(
    conn: u8,
    proto_sel: u8,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
    raw: bool,
) -> CalloutResult {
    use layer::FieldsAleAuthConnectV4 as F;
    let t = pool_v4(conn, proto_sel);
    let mut v = alloc::vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    v[F::IpLocalAddress as usize] = Value::U32(u32::from_be_bytes(t.local.octets()));
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::U32(u32::from_be_bytes(t.remote.octets()));
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    v[F::Flags as usize] = Value::U32(reauth_flag(reauthorize));
    let packet = build_packet_v4(&t, Direction::Outbound, payload, raw);
    drive(
        Layer::AleAuthConnectV4,
        v,
        Some(process_id),
        packet,
        0,
        IP4_HDR,
        TP_HDR,
        |d| crate::ale_callouts::ale_layer_connect_v4(d),
    )
}

pub fn run_ale_accept_v4(
    conn: u8,
    proto_sel: u8,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
    raw: bool,
) -> CalloutResult {
    use layer::FieldsAleAuthRecvAcceptV4 as F;
    let t = pool_v4(conn, proto_sel);
    let mut v = alloc::vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    v[F::IpLocalAddress as usize] = Value::U32(u32::from_be_bytes(t.local.octets()));
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::U32(u32::from_be_bytes(t.remote.octets()));
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    v[F::Flags as usize] = Value::U32(reauth_flag(reauthorize));
    // Inbound ALE: the data pointer starts past IP+transport; the callout
    // retreats `ip_header_size + transport_header_size` (= 40) before cloning.
    let packet = build_packet_v4(&t, Direction::Inbound, payload, raw);
    drive(
        Layer::AleAuthRecvAcceptV4,
        v,
        Some(process_id),
        packet,
        (IP4_HDR + TP_HDR) as usize,
        IP4_HDR,
        TP_HDR,
        |d| crate::ale_callouts::ale_layer_accept_v4(d),
    )
}

pub fn run_ale_connect_v6(
    conn: u8,
    proto_sel: u8,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
    raw: bool,
) -> CalloutResult {
    use layer::FieldsAleAuthConnectV6 as F;
    let t = pool_v6(conn, proto_sel);
    let mut v = alloc::vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    v[F::IpLocalAddress as usize] = Value::Bytes16(t.local.octets());
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::Bytes16(t.remote.octets());
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    v[F::Flags as usize] = Value::U32(reauth_flag(reauthorize));
    let packet = build_packet_v6(&t, Direction::Outbound, payload, raw);
    drive(
        Layer::AleAuthConnectV6,
        v,
        Some(process_id),
        packet,
        0,
        IP6_HDR,
        TP_HDR,
        |d| crate::ale_callouts::ale_layer_connect_v6(d),
    )
}

pub fn run_ale_accept_v6(
    conn: u8,
    proto_sel: u8,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
    raw: bool,
) -> CalloutResult {
    use layer::FieldsAleAuthRecvAcceptV6 as F;
    let t = pool_v6(conn, proto_sel);
    let mut v = alloc::vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    v[F::IpLocalAddress as usize] = Value::Bytes16(t.local.octets());
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::Bytes16(t.remote.octets());
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    v[F::Flags as usize] = Value::U32(reauth_flag(reauthorize));
    let packet = build_packet_v6(&t, Direction::Inbound, payload, raw);
    drive(
        Layer::AleAuthRecvAcceptV6,
        v,
        Some(process_id),
        packet,
        (IP6_HDR + TP_HDR) as usize,
        IP6_HDR,
        TP_HDR,
        |d| crate::ale_callouts::ale_layer_accept_v6(d),
    )
}

// ---- Packet-layer callouts ------------------------------------------------

pub fn run_packet_in_v4(conn: u8, proto_sel: u8, payload: &[u8], raw: bool) -> CalloutResult {
    use layer::FieldsInboundIppacketV4 as F;
    let t = pool_v4(conn, proto_sel);
    let v = alloc::vec![Value::U32(0); F::Max as usize];
    let packet = build_packet_v4(&t, Direction::Inbound, payload, raw);
    drive(
        Layer::InboundIppacketV4,
        v,
        None,
        packet,
        IP4_HDR as usize,
        0,
        0,
        |d| crate::packet_callouts::ip_packet_layer_inbound_v4(d),
    )
}

pub fn run_packet_out_v4(conn: u8, proto_sel: u8, payload: &[u8], raw: bool) -> CalloutResult {
    use layer::FieldsOutboundIppacketV4 as F;
    let t = pool_v4(conn, proto_sel);
    let v = alloc::vec![Value::U32(0); F::Max as usize];
    let packet = build_packet_v4(&t, Direction::Outbound, payload, raw);
    drive(
        Layer::OutboundIppacketV4,
        v,
        None,
        packet,
        0,
        0,
        0,
        |d| crate::packet_callouts::ip_packet_layer_outbound_v4(d),
    )
}

pub fn run_packet_in_v6(conn: u8, proto_sel: u8, payload: &[u8], raw: bool) -> CalloutResult {
    use layer::FieldsInboundIppacketV6 as F;
    let t = pool_v6(conn, proto_sel);
    let v = alloc::vec![Value::U32(0); F::Max as usize];
    let packet = build_packet_v6(&t, Direction::Inbound, payload, raw);
    drive(
        Layer::InboundIppacketV6,
        v,
        None,
        packet,
        IP6_HDR as usize,
        0,
        0,
        |d| crate::packet_callouts::ip_packet_layer_inbound_v6(d),
    )
}

pub fn run_packet_out_v6(conn: u8, proto_sel: u8, payload: &[u8], raw: bool) -> CalloutResult {
    use layer::FieldsOutboundIppacketV6 as F;
    let t = pool_v6(conn, proto_sel);
    let v = alloc::vec![Value::U32(0); F::Max as usize];
    let packet = build_packet_v6(&t, Direction::Outbound, payload, raw);
    drive(
        Layer::OutboundIppacketV6,
        v,
        None,
        packet,
        0,
        0,
        0,
        |d| crate::packet_callouts::ip_packet_layer_outbound_v6(d),
    )
}

// ---- Teardown callouts (no classify action expected) ----------------------

pub fn run_endpoint_close_v4(conn: u8, proto_sel: u8, process_id: u64) {
    use layer::FieldsAleEndpointClosureV4 as F;
    let t = pool_v4(conn, proto_sel);
    let mut v = alloc::vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    // Must be FwpUint32-typed or the callout treats it as an invalid address.
    v[F::IpLocalAddress as usize] = Value::U32(u32::from_be_bytes(t.local.octets()));
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::U32(u32::from_be_bytes(t.remote.octets()));
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    let _ = drive(
        Layer::AleEndpointClosureV4,
        v,
        Some(process_id),
        Vec::new(),
        0,
        0,
        0,
        |d| crate::ale_callouts::endpoint_closure_v4(d),
    );
}

pub fn run_endpoint_close_v6(conn: u8, proto_sel: u8, process_id: u64) {
    use layer::FieldsAleEndpointClosureV6 as F;
    let t = pool_v6(conn, proto_sel);
    let mut v = alloc::vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    // Both local and remote must be FwpByteArray16-typed for the v6 callout.
    v[F::IpLocalAddress as usize] = Value::Bytes16(t.local.octets());
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::Bytes16(t.remote.octets());
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    let _ = drive(
        Layer::AleEndpointClosureV6,
        v,
        Some(process_id),
        Vec::new(),
        0,
        0,
        0,
        |d| crate::ale_callouts::endpoint_closure_v6(d),
    );
}

/// Resource assignment-discard (`kind` even) or resource release (`kind` odd).
pub fn run_resource_v4(kind: u8, proto_sel: u8, port: u16) {
    let proto = proto_from_sel(proto_sel);
    if kind % 2 == 0 {
        use layer::FieldsAleResourceAssignmentV4 as F;
        let mut v = alloc::vec![Value::U32(0); F::Max as usize];
        v[F::IpProtocol as usize] = Value::U8(u8::from(proto));
        v[F::IpLocalPort as usize] = Value::U16(port);
        let _ = drive(
            Layer::AleResourceAssignmentV4Discard,
            v,
            Some(0),
            Vec::new(),
            0,
            0,
            0,
            |d| crate::ale_callouts::ale_resource_monitor(d),
        );
    } else {
        use layer::FieldsAleResourceReleaseV4 as F;
        let mut v = alloc::vec![Value::U32(0); F::Max as usize];
        v[F::IpProtocol as usize] = Value::U8(u8::from(proto));
        v[F::IpLocalPort as usize] = Value::U16(port);
        let _ = drive(
            Layer::AleResourceReleaseV4,
            v,
            Some(0),
            Vec::new(),
            0,
            0,
            0,
            |d| crate::ale_callouts::ale_resource_monitor(d),
        );
    }
}

pub fn run_resource_v6(kind: u8, proto_sel: u8, port: u16) {
    let proto = proto_from_sel(proto_sel);
    if kind % 2 == 0 {
        use layer::FieldsAleResourceAssignmentV6 as F;
        let mut v = alloc::vec![Value::U32(0); F::Max as usize];
        v[F::IpProtocol as usize] = Value::U8(u8::from(proto));
        v[F::IpLocalPort as usize] = Value::U16(port);
        let _ = drive(
            Layer::AleResourceAssignmentV6Discard,
            v,
            Some(0),
            Vec::new(),
            0,
            0,
            0,
            |d| crate::ale_callouts::ale_resource_monitor(d),
        );
    } else {
        use layer::FieldsAleResourceReleaseV6 as F;
        let mut v = alloc::vec![Value::U32(0); F::Max as usize];
        v[F::IpProtocol as usize] = Value::U8(u8::from(proto));
        v[F::IpLocalPort as usize] = Value::U16(port);
        let _ = drive(
            Layer::AleResourceReleaseV6,
            v,
            Some(0),
            Vec::new(),
            0,
            0,
            0,
            |d| crate::ale_callouts::ale_resource_monitor(d),
        );
    }
}

// ---- User-space command channel (the verdict side of the pipeline) --------

fn write_global(bytes: &[u8]) {
    if let Some(device) = crate::entry::get_device() {
        let mut request = WriteRequest::from_bytes(bytes);
        device.write(&mut request);
    }
}

/// Deliver a verdict for a pended packet id (mirrors a user-space `Verdict`
/// command). `id` should usually come from [`live_ids`].
pub fn device_write_verdict(id: u64, verdict: u8) {
    let mut command = Vec::with_capacity(10);
    command.push(CommandType::Verdict as u8);
    command.extend_from_slice(&id.to_le_bytes());
    command.push(verdict);
    write_global(&command);
}

pub fn device_write_update_v4(conn: u8, proto_sel: u8, verdict: u8) {
    let t = pool_v4(conn, proto_sel);
    let mut command = Vec::new();
    command.push(CommandType::UpdateV4 as u8);
    command.push(u8::from(t.proto));
    command.extend_from_slice(&t.local.octets());
    command.extend_from_slice(&t.lport.to_le_bytes());
    command.extend_from_slice(&t.remote.octets());
    command.extend_from_slice(&t.rport.to_le_bytes());
    command.push(verdict);
    write_global(&command);
}

pub fn device_write_update_v6(conn: u8, proto_sel: u8, verdict: u8) {
    let t = pool_v6(conn, proto_sel);
    let mut command = Vec::new();
    command.push(CommandType::UpdateV6 as u8);
    command.push(u8::from(t.proto));
    command.extend_from_slice(&t.local.octets());
    command.extend_from_slice(&t.lport.to_le_bytes());
    command.extend_from_slice(&t.remote.octets());
    command.extend_from_slice(&t.rport.to_le_bytes());
    command.push(verdict);
    write_global(&command);
}

pub fn device_clear_cache() {
    write_global(&[CommandType::ClearCache as u8]);
}

pub fn device_shutdown() {
    write_global(&[CommandType::Shutdown as u8]);
}

/// Drain up to `max` events from the device (mirrors user-space `Read` calls).
/// `wait_and_pop` is non-blocking in the mock, so an empty queue just ends.
pub fn drain_events(max: u8) {
    let Some(device) = crate::entry::get_device() else {
        return;
    };
    let mut buffer = [0u8; 256];
    for _ in 0..max {
        let mut request = ReadRequest::from_buffer(&mut buffer);
        device.read(&mut request);
    }
}
