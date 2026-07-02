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
pub use wdk::filter_engine::layer::{self, Layer};
pub use wdk::filter_engine::packet::InjectedPacket;
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

/// An explicit IPv4 5-tuple for the `*_tuple` entry points, so harnesses (the
/// sim traffic producer) are not limited to the fixed fuzz pool. `protocol` is
/// the raw IP protocol number (6 TCP, 17 UDP, 1 ICMP, ...).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TupleSpecV4 {
    pub protocol: u8,
    pub local: [u8; 4],
    pub local_port: u16,
    pub remote: [u8; 4],
    pub remote_port: u16,
}

/// An explicit IPv6 5-tuple, see [`TupleSpecV4`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TupleSpecV6 {
    pub protocol: u8,
    pub local: [u8; 16],
    pub local_port: u16,
    pub remote: [u8; 16],
    pub remote_port: u16,
}

impl TupleV4 {
    fn from_spec(spec: &TupleSpecV4) -> Self {
        TupleV4 {
            proto: IpProtocol::from(spec.protocol),
            local: Ipv4Address::from_octets(spec.local),
            lport: spec.local_port,
            remote: Ipv4Address::from_octets(spec.remote),
            rport: spec.remote_port,
        }
    }
}

impl TupleV6 {
    fn from_spec(spec: &TupleSpecV6) -> Self {
        TupleV6 {
            proto: IpProtocol::from(spec.protocol),
            local: Ipv6Address::from_octets(spec.local),
            lport: spec.local_port,
            remote: Ipv6Address::from_octets(spec.remote),
            rport: spec.remote_port,
        }
    }
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
    let nbl = NET_BUFFER_LIST::new_box(packet, data_offset);
    drive_nbl(
        layer,
        values,
        process_id,
        nbl,
        ip_header_size,
        transport_header_size,
        callout,
    )
}

// Like `drive`, but over a caller-built NBL (used to replay injected packets
// carrying the injected-by-self mark).
fn drive_nbl<F>(
    layer: Layer,
    values: Vec<Value>,
    process_id: Option<u64>,
    mut nbl: Box<NET_BUFFER_LIST>,
    ip_header_size: u32,
    transport_header_size: u32,
    callout: F,
) -> CalloutResult
where
    F: FnOnce(CalloutData),
{
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

/// The connection cache's verdict for an explicit tuple, if any. This is how a
/// harness observes the agent's (asynchronous) verdict landing, like the OS
/// observes the ALE re-authorization outcome.
pub fn verdict_for_key_v4(spec: TupleSpecV4) -> Option<u8> {
    let key = key_v4(&TupleV4::from_spec(&spec));
    crate::entry::get_device()?
        .connection_cache
        .get_verdict(&key)
        .map(|verdict| verdict as u8)
}

/// See [`verdict_for_key_v4`]; v6 flavor.
pub fn verdict_for_key_v6(spec: TupleSpecV6) -> Option<u8> {
    let key = key_v6(&TupleV6::from_spec(&spec));
    crate::entry::get_device()?
        .connection_cache
        .get_verdict(&key)
        .map(|verdict| verdict as u8)
}

/// Take every packet the driver injected since the last drain (the mock
/// injector records instead of injecting). A harness feeds these back through
/// the packet-layer callouts to model the OS re-presenting injected packets.
pub fn drain_injected() -> Vec<InjectedPacket> {
    crate::entry::get_device()
        .map(|device| device.injector.drain_injected())
        .unwrap_or_default()
}

/// Number of injected packets not yet drained.
pub fn injected_len() -> usize {
    crate::entry::get_device()
        .map(|device| device.injector.injected_len())
        .unwrap_or(0)
}

/// Snapshot of the filter engine's registration state, for asserting the
/// driver loaded like the kernel would see it (sublayer committed, expected
/// callouts on expected layers, live filter ids).
pub struct FilterEngineSnapshot {
    pub committed: bool,
    /// `(name, layer, filter_id)` per registered callout, in registration order.
    pub callouts: Vec<(String, Layer, u64)>,
}

pub fn filter_engine_snapshot() -> Option<FilterEngineSnapshot> {
    let device = crate::entry::get_device()?;
    let filter_engine = device.filter_engine.read_lock();
    Some(FilterEngineSnapshot {
        committed: filter_engine.is_committed(),
        callouts: filter_engine
            .registrations()
            .iter()
            .map(|reg| (reg.name.clone(), reg.layer, reg.filter_id))
            .collect(),
    })
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
    ale_connect_v4_with(pool_v4(conn, proto_sel), reauthorize, process_id, payload, raw)
}

/// ALE outbound-connect against an explicit tuple (see [`TupleSpecV4`]).
pub fn run_ale_connect_v4_tuple(
    spec: TupleSpecV4,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
) -> CalloutResult {
    ale_connect_v4_with(TupleV4::from_spec(&spec), reauthorize, process_id, payload, false)
}

fn ale_connect_v4_with(
    t: TupleV4,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
    raw: bool,
) -> CalloutResult {
    use layer::FieldsAleAuthConnectV4 as F;
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
    ale_accept_v4_with(pool_v4(conn, proto_sel), reauthorize, process_id, payload, raw)
}

/// ALE inbound-accept against an explicit tuple (see [`TupleSpecV4`]).
pub fn run_ale_accept_v4_tuple(
    spec: TupleSpecV4,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
) -> CalloutResult {
    ale_accept_v4_with(TupleV4::from_spec(&spec), reauthorize, process_id, payload, false)
}

fn ale_accept_v4_with(
    t: TupleV4,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
    raw: bool,
) -> CalloutResult {
    use layer::FieldsAleAuthRecvAcceptV4 as F;
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
    ale_connect_v6_with(pool_v6(conn, proto_sel), reauthorize, process_id, payload, raw)
}

/// ALE outbound-connect against an explicit tuple (see [`TupleSpecV6`]).
pub fn run_ale_connect_v6_tuple(
    spec: TupleSpecV6,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
) -> CalloutResult {
    ale_connect_v6_with(TupleV6::from_spec(&spec), reauthorize, process_id, payload, false)
}

fn ale_connect_v6_with(
    t: TupleV6,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
    raw: bool,
) -> CalloutResult {
    use layer::FieldsAleAuthConnectV6 as F;
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
    ale_accept_v6_with(pool_v6(conn, proto_sel), reauthorize, process_id, payload, raw)
}

/// ALE inbound-accept against an explicit tuple (see [`TupleSpecV6`]).
pub fn run_ale_accept_v6_tuple(
    spec: TupleSpecV6,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
) -> CalloutResult {
    ale_accept_v6_with(TupleV6::from_spec(&spec), reauthorize, process_id, payload, false)
}

fn ale_accept_v6_with(
    t: TupleV6,
    reauthorize: bool,
    process_id: u64,
    payload: &[u8],
    raw: bool,
) -> CalloutResult {
    use layer::FieldsAleAuthRecvAcceptV6 as F;
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
    packet_in_v4_with(pool_v4(conn, proto_sel), payload, raw)
}

fn packet_in_v4_with(t: TupleV4, payload: &[u8], raw: bool) -> CalloutResult {
    use layer::FieldsInboundIppacketV4 as F;
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
    packet_out_v4_with(pool_v4(conn, proto_sel), payload, raw)
}

/// Packet-layer classify for an explicit tuple, in either direction, with a
/// structured packet built around `payload`.
pub fn run_packet_v4_tuple(spec: TupleSpecV4, direction: Direction, payload: &[u8]) -> CalloutResult {
    let t = TupleV4::from_spec(&spec);
    match direction {
        Direction::Inbound => packet_in_v4_with(t, payload, false),
        Direction::Outbound => packet_out_v4_with(t, payload, false),
    }
}

fn packet_out_v4_with(t: TupleV4, payload: &[u8], raw: bool) -> CalloutResult {
    use layer::FieldsOutboundIppacketV4 as F;
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
    packet_in_v6_with(pool_v6(conn, proto_sel), payload, raw)
}

fn packet_in_v6_with(t: TupleV6, payload: &[u8], raw: bool) -> CalloutResult {
    use layer::FieldsInboundIppacketV6 as F;
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
    packet_out_v6_with(pool_v6(conn, proto_sel), payload, raw)
}

/// Packet-layer classify for an explicit tuple, see [`run_packet_v4_tuple`].
pub fn run_packet_v6_tuple(spec: TupleSpecV6, direction: Direction, payload: &[u8]) -> CalloutResult {
    let t = TupleV6::from_spec(&spec);
    match direction {
        Direction::Inbound => packet_in_v6_with(t, payload, false),
        Direction::Outbound => packet_out_v6_with(t, payload, false),
    }
}

/// Run the v4 packet-layer callout on an already-built packet buffer, as the
/// OS re-presents a packet: `injected_by_self` marks it as network-injected by
/// the driver (the FWPS injection state), so the callout's self-inject permit
/// branch runs. `bytes` must start at the IP header.
pub fn run_packet_bytes_v4(bytes: &[u8], direction: Direction, injected_by_self: bool) -> CalloutResult {
    let (data_offset, ipv6) = match direction {
        // Inbound packet-layer NBLs start past the IP header; the callout retreats.
        Direction::Inbound => (IP4_HDR as usize, false),
        Direction::Outbound => (0, false),
    };
    let nbl = if injected_by_self {
        NET_BUFFER_LIST::new_box_injected(bytes.to_vec(), data_offset, ipv6)
    } else {
        NET_BUFFER_LIST::new_box(bytes.to_vec(), data_offset)
    };
    match direction {
        Direction::Inbound => {
            use layer::FieldsInboundIppacketV4 as F;
            drive_nbl(
                Layer::InboundIppacketV4,
                alloc::vec![Value::U32(0); F::Max as usize],
                None,
                nbl,
                0,
                0,
                |d| crate::packet_callouts::ip_packet_layer_inbound_v4(d),
            )
        }
        Direction::Outbound => {
            use layer::FieldsOutboundIppacketV4 as F;
            drive_nbl(
                Layer::OutboundIppacketV4,
                alloc::vec![Value::U32(0); F::Max as usize],
                None,
                nbl,
                0,
                0,
                |d| crate::packet_callouts::ip_packet_layer_outbound_v4(d),
            )
        }
    }
}

/// See [`run_packet_bytes_v4`]; v6 flavor.
pub fn run_packet_bytes_v6(bytes: &[u8], direction: Direction, injected_by_self: bool) -> CalloutResult {
    let data_offset = match direction {
        Direction::Inbound => IP6_HDR as usize,
        Direction::Outbound => 0,
    };
    let nbl = if injected_by_self {
        NET_BUFFER_LIST::new_box_injected(bytes.to_vec(), data_offset, true)
    } else {
        NET_BUFFER_LIST::new_box(bytes.to_vec(), data_offset)
    };
    match direction {
        Direction::Inbound => {
            use layer::FieldsInboundIppacketV6 as F;
            drive_nbl(
                Layer::InboundIppacketV6,
                alloc::vec![Value::U32(0); F::Max as usize],
                None,
                nbl,
                0,
                0,
                |d| crate::packet_callouts::ip_packet_layer_inbound_v6(d),
            )
        }
        Direction::Outbound => {
            use layer::FieldsOutboundIppacketV6 as F;
            drive_nbl(
                Layer::OutboundIppacketV6,
                alloc::vec![Value::U32(0); F::Max as usize],
                None,
                nbl,
                0,
                0,
                |d| crate::packet_callouts::ip_packet_layer_outbound_v6(d),
            )
        }
    }
}

fn packet_out_v6_with(t: TupleV6, payload: &[u8], raw: bool) -> CalloutResult {
    use layer::FieldsOutboundIppacketV6 as F;
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
    endpoint_close_v4_with(pool_v4(conn, proto_sel), process_id)
}

/// Endpoint closure for an explicit tuple (see [`TupleSpecV4`]).
pub fn run_endpoint_close_v4_tuple(spec: TupleSpecV4, process_id: u64) {
    endpoint_close_v4_with(TupleV4::from_spec(&spec), process_id)
}

fn endpoint_close_v4_with(t: TupleV4, process_id: u64) {
    use layer::FieldsAleEndpointClosureV4 as F;
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
    endpoint_close_v6_with(pool_v6(conn, proto_sel), process_id)
}

/// Endpoint closure for an explicit tuple (see [`TupleSpecV6`]).
pub fn run_endpoint_close_v6_tuple(spec: TupleSpecV6, process_id: u64) {
    endpoint_close_v6_with(TupleV6::from_spec(&spec), process_id)
}

fn endpoint_close_v6_with(t: TupleV6, process_id: u64) {
    use layer::FieldsAleEndpointClosureV6 as F;
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

/// Resource release for a raw protocol number and port (unlike
/// [`run_resource_v4`], which maps through the fuzz `proto_sel` distribution).
pub fn run_resource_release_v4_port(protocol: u8, port: u16) {
    use layer::FieldsAleResourceReleaseV4 as F;
    let mut v = alloc::vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(protocol);
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

/// See [`run_resource_release_v4_port`]; v6 flavor.
pub fn run_resource_release_v6_port(protocol: u8, port: u16) {
    use layer::FieldsAleResourceReleaseV6 as F;
    let mut v = alloc::vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(protocol);
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

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use crate::entry::DEVICE_TEST_LOCK;

    // Install a fresh device in the global slot for the duration of `test`,
    // serialized against every other global-slot test.
    fn with_fresh_device(test: impl FnOnce()) {
        let _guard = DEVICE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let stale = crate::entry::clear_device();
        if !stale.is_null() {
            unsafe { drop(Box::from_raw(stale)) };
        }
        ensure_device();
        test();
        let device = crate::entry::clear_device();
        if !device.is_null() {
            unsafe { drop(Box::from_raw(device)) };
        }
    }

    // Loading fidelity: the real driver_entry, run over the mock, must commit
    // the filter engine with exactly the production callout set on the expected
    // layers -- a registration regression in callouts.rs fails here (and fails
    // the sim daemon at load, which does the same assertion).
    #[test]
    fn driver_entry_registers_expected_callouts() {
        let simulation = crate::sim::Simulation::start().expect("driver entry");
        let snapshot = filter_engine_snapshot().expect("device installed");
        assert!(snapshot.committed);

        let layers: Vec<Layer> = snapshot.callouts.iter().map(|(_, layer, _)| *layer).collect();
        assert_eq!(
            layers,
            alloc::vec![
                Layer::AleAuthConnectV4,
                Layer::AleAuthRecvAcceptV4,
                Layer::AleAuthConnectV6,
                Layer::AleAuthRecvAcceptV6,
                Layer::AleEndpointClosureV4,
                Layer::AleEndpointClosureV6,
                Layer::AleResourceReleaseV4,
                Layer::AleResourceReleaseV6,
                Layer::OutboundIppacketV4,
                Layer::InboundIppacketV4,
                Layer::OutboundIppacketV6,
                Layer::InboundIppacketV6,
            ]
        );

        let mut filter_ids: Vec<u64> = snapshot.callouts.iter().map(|(_, _, id)| *id).collect();
        filter_ids.sort_unstable();
        filter_ids.dedup();
        assert_eq!(filter_ids.len(), 12, "filter ids must be distinct");
        assert!(!filter_ids.contains(&0), "0 means unregistered");

        drop(simulation);
    }

    // Injection loopback: a pended packet released by a verdict is recorded by
    // the mock injector; replayed at the packet layer with the injected-by-self
    // mark it must hit the self-inject permit branch, and without the mark it
    // must pend again (the mark, not the bytes, drives the branch).
    #[test]
    fn injected_packet_loops_back_and_is_permitted() {
        with_fresh_device(|| {
            let _ = drain_injected();
            let spec = TupleSpecV4 {
                protocol: 1, // ICMP: not connection-tracked, pends per-packet
                local: [10, 0, 0, 9],
                local_port: 0,
                remote: [10, 0, 0, 10],
                remote_port: 0,
            };

            let result = run_packet_v4_tuple(spec, Direction::Outbound, &[8, 0, 0, 0]);
            assert!(result.absorb, "ICMP packet must pend for a per-packet verdict");
            let ids = live_ids();
            assert_eq!(ids.len(), 1);

            device_write_verdict(ids[0], Verdict::PermanentAccept as u8);
            assert_eq!(packet_cache_len(), 0);
            let injected = drain_injected();
            assert_eq!(injected.len(), 1, "accept verdict must inject the clone");
            let packet = &injected[0];
            assert!(!packet.transport);
            assert!(!packet.inbound);
            assert!(!packet.ipv6);

            let direction = if packet.inbound { Direction::Inbound } else { Direction::Outbound };
            let replay = run_packet_bytes_v4(&packet.data, direction, true);
            assert_eq!(replay.action, FWP_ACTION_PERMIT, "self-injected packet must be permitted");
            assert_eq!(packet_cache_len(), 0, "self-injected packet must not pend again");

            let replay = run_packet_bytes_v4(&packet.data, direction, false);
            assert!(replay.absorb, "unmarked packet must go through the normal path");
            assert_eq!(packet_cache_len(), 1, "and pend for a fresh verdict");
        });
    }

    // Tuple pipeline: an arbitrary (non-pool) tuple flows ALE pend -> verdict ->
    // packet-layer permit; an inbound accept carrying payload records a
    // transport inject when its verdict releases the defer.
    #[test]
    fn tuple_pipeline_links_ale_verdict_and_packet_layer() {
        with_fresh_device(|| {
            let _ = drain_injected();
            let spec = TupleSpecV4 {
                protocol: 6,
                local: [10, 1, 2, 3],
                local_port: 34567,
                remote: [52, 10, 20, 30],
                remote_port: 443,
            };

            let result = run_ale_connect_v4_tuple(spec, false, 4242, &[]);
            assert!(result.absorb, "new connection must pend");
            assert_eq!(verdict_for_key_v4(spec), Some(Verdict::Undecided as u8));

            let ids = live_ids();
            assert_eq!(ids.len(), 1);
            device_write_verdict(ids[0], Verdict::PermanentAccept as u8);
            assert_eq!(verdict_for_key_v4(spec), Some(Verdict::PermanentAccept as u8));
            // An outbound TCP connect defer carries no packet data, so nothing
            // is recorded by the injector.
            assert_eq!(injected_len(), 0);

            let result = run_packet_v4_tuple(spec, Direction::Outbound, b"data");
            assert_eq!(result.action, FWP_ACTION_PERMIT);

            // Inbound accept with payload: the verdict completes the ALE defer
            // and the pended first packet is transport-injected.
            let spec_in = TupleSpecV4 {
                protocol: 6,
                local: [10, 1, 2, 3],
                local_port: 8080,
                remote: [52, 10, 20, 31],
                remote_port: 51000,
            };
            let result = run_ale_accept_v4_tuple(spec_in, false, 4243, &[1, 2, 3, 4]);
            assert!(result.absorb);
            let ids = live_ids();
            assert_eq!(ids.len(), 1);
            device_write_verdict(ids[0], Verdict::PermanentAccept as u8);
            let injected = drain_injected();
            assert_eq!(injected.len(), 1);
            assert!(injected[0].transport);
            assert!(injected[0].inbound);
        });
    }
}
