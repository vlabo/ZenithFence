//! The real driver's callouts and state, driven like the kernel would.
//!
//! Builds mock classify inputs for an explicit 5-tuple and calls the driver's
//! real callout entry points, and reads back the state a script asserts on. The
//! driver is loaded through its real `driver_entry` (see [`crate::loader`]);
//! nothing here installs or replaces driver state.
//!
//! All the mock-fidelity rules live here in ONE place: the classify `values`
//! vector must be sized to the layer's `Fields::Max` (the mock indexes it and
//! panics otherwise), each field must use the matching `Value` variant (else the
//! mock silently reads 0 and keys don't match), and inbound NBLs need a
//! `data_offset` that covers the headers the callout retreats past.

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};

use wdk::filter_engine::callout_data::{CalloutData, Value};
use wdk::filter_engine::classify::ClassifyOut;
use wdk::filter_engine::layer;
pub use wdk::filter_engine::layer::Layer;
use wdk::filter_engine::net_buffer::NET_BUFFER_LIST;
pub use wdk::filter_engine::packet::InjectedPacket;

pub use driver::connection::Direction;
use driver::connection::Key;

pub use wdk::filter_engine::classify::{FWP_ACTION_BLOCK, FWP_ACTION_PERMIT};

/// Outcome of one callout invocation, as observed on the `ClassifyOut`.
#[derive(Clone, Copy)]
pub struct CalloutResult {
    /// The action the callout set (`0` if it left none, e.g. on a parse error).
    pub action: u32,
    /// Whether the callout set the ABSORB flag.
    pub absorb: bool,
}

const IP4_HDR: u32 = 20;
const IP6_HDR: u32 = 40;

/// Size of the transport header the packet builders put in front of the
/// payload: TCP 20, UDP 8. Other protocols (ICMP, ...) carry their own header
/// in the payload.
fn transport_header_len(proto: IpProtocol) -> u32 {
    match proto {
        IpProtocol::Tcp => 20,
        IpProtocol::Udp => 8,
        _ => 0,
    }
}

/// An IPv4 5-tuple. `protocol` is the raw IP protocol number (6 TCP, 17 UDP,
/// 1 ICMP, ...).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TupleSpecV4 {
    pub protocol: u8,
    pub local: [u8; 4],
    pub local_port: u16,
    pub remote: [u8; 4],
    pub remote_port: u16,
}

/// An IPv6 5-tuple, see [`TupleSpecV4`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TupleSpecV6 {
    pub protocol: u8,
    pub local: [u8; 16],
    pub local_port: u16,
    pub remote: [u8; 16],
    pub remote_port: u16,
}

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

fn ports_for(proto: IpProtocol, lport: u16, rport: u16) -> (u16, u16) {
    match proto {
        IpProtocol::Tcp | IpProtocol::Udp => (lport, rport),
        _ => (0, 0),
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

/// The Internet checksum (RFC 1071) over `chunks` taken as one buffer (every
/// chunk but the last must have an even length).
fn inet_checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in chunks {
        let mut words = chunk.chunks_exact(2);
        for w in &mut words {
            sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
        }
        if let [last] = words.remainder() {
            sum += u32::from(*last) << 8;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The transport header (see [`transport_header_len`]) followed by `payload`,
/// checksummed over `addresses` (source then destination, the start of the IP
/// pseudo-header). Protocols without a header here get `payload` unchanged.
fn transport_segment(proto: IpProtocol, sport: u16, dport: u16, payload: &[u8], addresses: &[u8]) -> Vec<u8> {
    let (mut seg, checksum_at) = match proto {
        IpProtocol::Tcp => {
            let mut h = vec![0u8; 20];
            h[4..8].copy_from_slice(&1u32.to_be_bytes()); // seq
            h[8..12].copy_from_slice(&1u32.to_be_bytes()); // ack
            h[12] = 5 << 4; // data offset: 5 words
            h[13] = 0x18; // PSH | ACK
            h[14..16].copy_from_slice(&0xffffu16.to_be_bytes()); // window
            (h, 16)
        }
        IpProtocol::Udp => {
            let mut h = vec![0u8; 8];
            h[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            (h, 6)
        }
        _ => return payload.to_vec(),
    };
    seg[0..2].copy_from_slice(&sport.to_be_bytes());
    seg[2..4].copy_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(payload);
    // Pseudo-header tail: segment length (u32, covers both the v4 u16 and the
    // v6 u32 form) and the protocol.
    let mut tail = [0u8; 8];
    tail[0..4].copy_from_slice(&(seg.len() as u32).to_be_bytes());
    tail[7] = u8::from(proto);
    let mut checksum = inet_checksum(&[addresses, &tail, &seg]);
    if checksum == 0 && proto == IpProtocol::Udp {
        checksum = 0xffff; // a zero UDP checksum means "none"
    }
    seg[checksum_at..checksum_at + 2].copy_from_slice(&checksum.to_be_bytes());
    seg
}

// Build a well-formed IPv4 packet whose 5-tuple is `t` for the given direction:
// IP header (with its checksum), a real TCP / UDP header for those protocols,
// then `payload` (which carries the header itself for ICMP and others), so a
// user-space parser reading the event payload sees a real packet.
fn build_packet_v4(t: &TupleV4, direction: Direction, payload: &[u8]) -> Vec<u8> {
    let (src, dst, sport, dport) = match direction {
        Direction::Outbound => (t.local, t.remote, t.lport, t.rport),
        Direction::Inbound => (t.remote, t.local, t.rport, t.lport),
    };
    let mut addresses = [0u8; 8];
    addresses[0..4].copy_from_slice(&src.octets());
    addresses[4..8].copy_from_slice(&dst.octets());
    let segment = transport_segment(t.proto, sport, dport, payload, &addresses);
    let mut p = vec![0u8; IP4_HDR as usize];
    p[0] = 0x45; // version 4, IHL 5
    p[2..4].copy_from_slice(&((IP4_HDR as usize + segment.len()) as u16).to_be_bytes());
    p[8] = 64; // TTL
    p[9] = u8::from(t.proto);
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let checksum = inet_checksum(&[&p]);
    p[10..12].copy_from_slice(&checksum.to_be_bytes());
    p.extend_from_slice(&segment);
    p
}

// IPv6 counterpart of `build_packet_v4`.
fn build_packet_v6(t: &TupleV6, direction: Direction, payload: &[u8]) -> Vec<u8> {
    let (src, dst, sport, dport) = match direction {
        Direction::Outbound => (t.local, t.remote, t.lport, t.rport),
        Direction::Inbound => (t.remote, t.local, t.rport, t.lport),
    };
    let mut addresses = [0u8; 32];
    addresses[0..16].copy_from_slice(&src.octets());
    addresses[16..32].copy_from_slice(&dst.octets());
    let segment = transport_segment(t.proto, sport, dport, payload, &addresses);
    let mut p = vec![0u8; IP6_HDR as usize];
    p[0] = 0x60; // version 6
    p[4..6].copy_from_slice(&(segment.len() as u16).to_be_bytes());
    p[6] = u8::from(t.proto); // next header
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p.extend_from_slice(&segment);
    p
}

// Build the mock CalloutData around `values` + `packet`, run `callout`, and
// report what it wrote to the ClassifyOut. The NBL box and ClassifyOut outlive
// the borrow taken by `CalloutData` (raw pointers), so they are read afterwards.
#[allow(clippy::too_many_arguments)]
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
    drive_nbl(layer, values, process_id, nbl, ip_header_size, transport_header_size, callout)
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

// Run a teardown callout, which sets no classify action.
fn notify(layer: Layer, values: Vec<Value>, process_id: u64, callout: impl FnOnce(CalloutData)) {
    let _ = drive(layer, values, Some(process_id), Vec::new(), 0, 0, 0, callout);
}

// ---- Driver state ---------------------------------------------------------

/// Number of packets currently pending in the id/packet cache.
pub fn packet_cache_len() -> usize {
    driver::entry::get_device()
        .map(|device| device.packet_cache.get_entries_count())
        .unwrap_or(0)
}

/// Number of active (not-yet-ended) connections in the connection cache.
pub fn active_conn_count() -> usize {
    driver::entry::get_device()
        .map(|device| device.connection_cache.get_entries_count().0)
        .unwrap_or(0)
}

/// Ids of the packets currently pending.
pub fn live_ids() -> Vec<u64> {
    driver::entry::get_device()
        .map(|device| device.packet_cache.pending_ids())
        .unwrap_or_default()
}

/// The connection cache's verdict for `spec`, if any. This is how a harness
/// observes the agent's (asynchronous) verdict landing, like the OS observes
/// the ALE re-authorization outcome.
pub fn verdict_for_v4(spec: TupleSpecV4) -> Option<u8> {
    let key = key_v4(&TupleV4::from_spec(&spec));
    driver::entry::get_device()?
        .connection_cache
        .get_verdict(&key)
        .map(|verdict| verdict as u8)
}

/// See [`verdict_for_v4`]; v6 flavor.
pub fn verdict_for_v6(spec: TupleSpecV6) -> Option<u8> {
    let key = key_v6(&TupleV6::from_spec(&spec));
    driver::entry::get_device()?
        .connection_cache
        .get_verdict(&key)
        .map(|verdict| verdict as u8)
}

/// Take every packet the driver injected since the last drain (the mock
/// injector records instead of injecting). A harness feeds these back through
/// the packet-layer callouts to model the OS re-presenting injected packets.
pub fn drain_injected() -> Vec<InjectedPacket> {
    driver::entry::get_device()
        .map(|device| device.injector.drain_injected())
        .unwrap_or_default()
}

/// Reset the device's transient per-flow state to a clean slate: drop every
/// tracked connection and any still-pended packet, and discard recorded injects.
/// Callout registration and the filter engine are left intact. No-op if no
/// device is installed.
pub fn reset_device_state() {
    if let Some(device) = driver::entry::get_device() {
        device.connection_cache.clear();
        device.packet_cache.pop_all();
        device.injector.drain_injected();
    }
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
    let device = driver::entry::get_device()?;
    Some(device.filter_engine.with(|filter_engine| FilterEngineSnapshot {
        committed: filter_engine.is_committed(),
        callouts: filter_engine
            .registrations()
            .iter()
            .map(|reg| (reg.name.clone(), reg.layer, reg.filter_id))
            .collect(),
    }))
}

// ---- ALE callouts ---------------------------------------------------------

/// ALE outbound-connect classify: the first packet of a new outbound flow.
pub fn ale_connect_v4(spec: TupleSpecV4, reauthorize: bool, process_id: u64, payload: &[u8]) -> CalloutResult {
    use layer::FieldsAleAuthConnectV4 as F;
    let t = TupleV4::from_spec(&spec);
    let mut v = vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    v[F::IpLocalAddress as usize] = Value::U32(u32::from_be_bytes(t.local.octets()));
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::U32(u32::from_be_bytes(t.remote.octets()));
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    v[F::Flags as usize] = Value::U32(reauth_flag(reauthorize));
    // Outbound ALE: WFP hands over the packet from its transport header on.
    drive(
        Layer::AleAuthConnectV4,
        v,
        Some(process_id),
        build_packet_v4(&t, Direction::Outbound, payload),
        IP4_HDR as usize,
        IP4_HDR,
        transport_header_len(t.proto),
        |d| driver::ale_callouts::ale_layer_connect_v4(d),
    )
}

/// ALE inbound-accept classify.
pub fn ale_accept_v4(spec: TupleSpecV4, reauthorize: bool, process_id: u64, payload: &[u8]) -> CalloutResult {
    use layer::FieldsAleAuthRecvAcceptV4 as F;
    let t = TupleV4::from_spec(&spec);
    let mut v = vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    v[F::IpLocalAddress as usize] = Value::U32(u32::from_be_bytes(t.local.octets()));
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::U32(u32::from_be_bytes(t.remote.octets()));
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    v[F::Flags as usize] = Value::U32(reauth_flag(reauthorize));
    // Inbound ALE: the data pointer starts past IP+transport; the callout
    // retreats `ip_header_size + transport_header_size` before cloning.
    let tp = transport_header_len(t.proto);
    drive(
        Layer::AleAuthRecvAcceptV4,
        v,
        Some(process_id),
        build_packet_v4(&t, Direction::Inbound, payload),
        (IP4_HDR + tp) as usize,
        IP4_HDR,
        tp,
        |d| driver::ale_callouts::ale_layer_accept_v4(d),
    )
}

/// See [`ale_connect_v4`]; v6 flavor.
pub fn ale_connect_v6(spec: TupleSpecV6, reauthorize: bool, process_id: u64, payload: &[u8]) -> CalloutResult {
    use layer::FieldsAleAuthConnectV6 as F;
    let t = TupleV6::from_spec(&spec);
    let mut v = vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    v[F::IpLocalAddress as usize] = Value::Bytes16(t.local.octets());
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::Bytes16(t.remote.octets());
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    v[F::Flags as usize] = Value::U32(reauth_flag(reauthorize));
    drive(
        Layer::AleAuthConnectV6,
        v,
        Some(process_id),
        build_packet_v6(&t, Direction::Outbound, payload),
        IP6_HDR as usize,
        IP6_HDR,
        transport_header_len(t.proto),
        |d| driver::ale_callouts::ale_layer_connect_v6(d),
    )
}

/// See [`ale_accept_v4`]; v6 flavor.
pub fn ale_accept_v6(spec: TupleSpecV6, reauthorize: bool, process_id: u64, payload: &[u8]) -> CalloutResult {
    use layer::FieldsAleAuthRecvAcceptV6 as F;
    let t = TupleV6::from_spec(&spec);
    let mut v = vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    v[F::IpLocalAddress as usize] = Value::Bytes16(t.local.octets());
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::Bytes16(t.remote.octets());
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    v[F::Flags as usize] = Value::U32(reauth_flag(reauthorize));
    let tp = transport_header_len(t.proto);
    drive(
        Layer::AleAuthRecvAcceptV6,
        v,
        Some(process_id),
        build_packet_v6(&t, Direction::Inbound, payload),
        (IP6_HDR + tp) as usize,
        IP6_HDR,
        tp,
        |d| driver::ale_callouts::ale_layer_accept_v6(d),
    )
}

// ---- Packet-layer callouts ------------------------------------------------

/// IP-packet-layer classify for a packet of `spec` built around `payload`.
pub fn packet_v4(spec: TupleSpecV4, direction: Direction, payload: &[u8]) -> CalloutResult {
    let t = TupleV4::from_spec(&spec);
    let packet = build_packet_v4(&t, direction, payload);
    match direction {
        Direction::Inbound => {
            use layer::FieldsInboundIppacketV4 as F;
            // Inbound packet-layer NBLs start past the IP header; the callout retreats.
            drive(
                Layer::InboundIppacketV4,
                vec![Value::U32(0); F::Max as usize],
                None,
                packet,
                IP4_HDR as usize,
                0,
                0,
                |d| driver::packet_callouts::ip_packet_layer_inbound_v4(d),
            )
        }
        Direction::Outbound => {
            use layer::FieldsOutboundIppacketV4 as F;
            drive(
                Layer::OutboundIppacketV4,
                vec![Value::U32(0); F::Max as usize],
                None,
                packet,
                0,
                0,
                0,
                |d| driver::packet_callouts::ip_packet_layer_outbound_v4(d),
            )
        }
    }
}

/// See [`packet_v4`]; v6 flavor.
pub fn packet_v6(spec: TupleSpecV6, direction: Direction, payload: &[u8]) -> CalloutResult {
    let t = TupleV6::from_spec(&spec);
    let packet = build_packet_v6(&t, direction, payload);
    match direction {
        Direction::Inbound => {
            use layer::FieldsInboundIppacketV6 as F;
            drive(
                Layer::InboundIppacketV6,
                vec![Value::U32(0); F::Max as usize],
                None,
                packet,
                IP6_HDR as usize,
                0,
                0,
                |d| driver::packet_callouts::ip_packet_layer_inbound_v6(d),
            )
        }
        Direction::Outbound => {
            use layer::FieldsOutboundIppacketV6 as F;
            drive(
                Layer::OutboundIppacketV6,
                vec![Value::U32(0); F::Max as usize],
                None,
                packet,
                0,
                0,
                0,
                |d| driver::packet_callouts::ip_packet_layer_outbound_v6(d),
            )
        }
    }
}

/// Run the v4 packet-layer callout on raw bytes starting at the IP header
/// (malformed ones included), as the OS re-presents a packet: `injected_by_self`
/// marks it as network-injected by the driver (the FWPS injection state), so
/// the callout's self-inject permit branch runs.
pub fn packet_bytes_v4(bytes: &[u8], direction: Direction, injected_by_self: bool) -> CalloutResult {
    let data_offset = match direction {
        // Inbound packet-layer NBLs start past the IP header; the callout retreats.
        Direction::Inbound => IP4_HDR as usize,
        Direction::Outbound => 0,
    };
    let nbl = if injected_by_self {
        NET_BUFFER_LIST::new_box_injected(bytes.to_vec(), data_offset, false)
    } else {
        NET_BUFFER_LIST::new_box(bytes.to_vec(), data_offset)
    };
    match direction {
        Direction::Inbound => {
            use layer::FieldsInboundIppacketV4 as F;
            drive_nbl(
                Layer::InboundIppacketV4,
                vec![Value::U32(0); F::Max as usize],
                None,
                nbl,
                0,
                0,
                |d| driver::packet_callouts::ip_packet_layer_inbound_v4(d),
            )
        }
        Direction::Outbound => {
            use layer::FieldsOutboundIppacketV4 as F;
            drive_nbl(
                Layer::OutboundIppacketV4,
                vec![Value::U32(0); F::Max as usize],
                None,
                nbl,
                0,
                0,
                |d| driver::packet_callouts::ip_packet_layer_outbound_v4(d),
            )
        }
    }
}

/// See [`packet_bytes_v4`]; v6 flavor.
pub fn packet_bytes_v6(bytes: &[u8], direction: Direction, injected_by_self: bool) -> CalloutResult {
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
                vec![Value::U32(0); F::Max as usize],
                None,
                nbl,
                0,
                0,
                |d| driver::packet_callouts::ip_packet_layer_inbound_v6(d),
            )
        }
        Direction::Outbound => {
            use layer::FieldsOutboundIppacketV6 as F;
            drive_nbl(
                Layer::OutboundIppacketV6,
                vec![Value::U32(0); F::Max as usize],
                None,
                nbl,
                0,
                0,
                |d| driver::packet_callouts::ip_packet_layer_outbound_v6(d),
            )
        }
    }
}

// ---- Teardown callouts (no classify action expected) ----------------------

/// ALE endpoint closure for `spec`: the connection ended.
pub fn endpoint_close_v4(spec: TupleSpecV4, process_id: u64) {
    use layer::FieldsAleEndpointClosureV4 as F;
    let t = TupleV4::from_spec(&spec);
    let mut v = vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    // Must be FwpUint32-typed or the callout treats it as an invalid address.
    v[F::IpLocalAddress as usize] = Value::U32(u32::from_be_bytes(t.local.octets()));
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::U32(u32::from_be_bytes(t.remote.octets()));
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    notify(Layer::AleEndpointClosureV4, v, process_id, |d| {
        driver::ale_callouts::endpoint_closure_v4(d)
    });
}

/// See [`endpoint_close_v4`]; v6 flavor.
pub fn endpoint_close_v6(spec: TupleSpecV6, process_id: u64) {
    use layer::FieldsAleEndpointClosureV6 as F;
    let t = TupleV6::from_spec(&spec);
    let mut v = vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(u8::from(t.proto));
    // Both local and remote must be FwpByteArray16-typed for the v6 callout.
    v[F::IpLocalAddress as usize] = Value::Bytes16(t.local.octets());
    v[F::IpLocalPort as usize] = Value::U16(t.lport);
    v[F::IpRemoteAddress as usize] = Value::Bytes16(t.remote.octets());
    v[F::IpRemotePort as usize] = Value::U16(t.rport);
    notify(Layer::AleEndpointClosureV6, v, process_id, |d| {
        driver::ale_callouts::endpoint_closure_v6(d)
    });
}

/// ALE resource release: local `port` of `protocol` was released.
pub fn resource_release_v4(protocol: u8, port: u16) {
    use layer::FieldsAleResourceReleaseV4 as F;
    let mut v = vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(protocol);
    v[F::IpLocalPort as usize] = Value::U16(port);
    notify(Layer::AleResourceReleaseV4, v, 0, |d| driver::ale_callouts::ale_resource_monitor(d));
}

/// See [`resource_release_v4`]; v6 flavor.
pub fn resource_release_v6(protocol: u8, port: u16) {
    use layer::FieldsAleResourceReleaseV6 as F;
    let mut v = vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(protocol);
    v[F::IpLocalPort as usize] = Value::U16(port);
    notify(Layer::AleResourceReleaseV6, v, 0, |d| driver::ale_callouts::ale_resource_monitor(d));
}
