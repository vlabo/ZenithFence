//! Outbound MAC layer callout.
//!
//! The ALE and IP packet callouts live inside `tcpip.sys`. Anything injected below it — a packet
//! capture driver sending through its own NDIS filter position, for example — reaches the wire
//! without ever being classified there. This callout sits at
//! `FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE`, which the inbox `ms_wfplwf_lower` lightweight filter
//! feeds from the bottom of the NDIS filter stack, below any such injector. It is the only place
//! WFP can still see those frames.
//!
//! The classification is a ladder, cheapest test first, so ordinary traffic pays as little as
//! possible. Nothing before step 5 parses the frame.
//!
//! 1. Teardown started -> permit.
//! 2. Injected by us here -> permit. Without this every reinjection is absorbed again, forever.
//! 3. Injected by us at the network layer -> permit. This is the whole "already went through user
//!    space" case: temporary verdicts, ICMP, IGMP and every reinjected TCP/UDP packet all get here
//!    with the injection mark still on them.
//! 4. Not an 802.3 medium -> permit. See `NDIS_MEDIUM_802_3` below.
//! 5. Parse the ethernet header and branch on the ether type.
//! 6. Parse the IP header and look the connection up in the cache. The outbound IP callout runs
//!    *before* this one, so anything that came through the stack already has an entry. **A missing
//!    entry is the bypass signal** — that is why no cross layer packet context is needed.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::FieldsOutboundMacFrameNative;
use wdk::filter_engine::net_buffer::{NetBuffer, NetBufferListIter};
use wdk::filter_engine::packet::MacInjectInfo;

use crate::connection::{Direction, Key, Verdict};
use crate::device::{Device, Packet};
use crate::packet_util::{get_key_from_nb_v4, get_key_from_nb_v6};
use crate::{err, info, trace, warn};

/// Master switch for enforcement.
///
/// With `false` the full ladder still runs and logs the decision it would have taken, but the
/// frame is always permitted and nothing is handed to user space. That was how this was brought
/// up: the dry run confirmed that frames injected below `tcpip.sys` really do reach this layer and
/// that the ethernet header is where the parse expects it.
///
/// Set back to `false` to diagnose without touching traffic — it is the difference between a
/// firewall and a monitor, so keep it `true` in anything shipped.
const MAC_ENFORCE: bool = true;

/// `NdisMedium802_3`. Anything else is a medium this callout cannot parse — native 802.11 above
/// all, because `ms_wfplwf_lower` binds below the medium converter, so on Wi-Fi the frame here is
/// an 802.11 frame and not an ethernet one.
///
/// Those frames are permitted and counted rather than blocked. Failing closed on them would drop
/// every Wi-Fi data frame including association and EAPOL, taking the network down. A medium we
/// recognise but cannot parse is a successful identification, not a failed assumption: no ethernet
/// assumption was ever made. Wireless stays covered by the IP layer callouts only.
const NDIS_MEDIUM_802_3: u32 = 0;

const ETHERNET_HEADER_LEN: u32 = 14;
const VLAN_TAGGED_HEADER_LEN: u32 = 18;

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_ARP: u16 = 0x0806;
const ETHER_TYPE_RARP: u16 = 0x8035;
const ETHER_TYPE_VLAN: u16 = 0x8100;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
const ETHER_TYPE_EAPOL: u16 = 0x888E;
const ETHER_TYPE_LLDP: u16 = 0x88CC;

/// How many classifies between counter summaries. Every frame on the adapter passes through here,
/// so per frame logging wraps the log ring buffer between two GetLogs commands. The counters are
/// the signal; the traces are for the dry run.
const COUNTER_LOG_INTERVAL: u64 = 4096;

static CLASSIFIES_SEEN: AtomicU64 = AtomicU64::new(0);
static PERMIT_INJECTED: AtomicU64 = AtomicU64::new(0);
static PERMIT_MEDIUM: AtomicU64 = AtomicU64::new(0);
static PERMIT_L2_CONTROL: AtomicU64 = AtomicU64::new(0);
static PERMIT_KNOWN: AtomicU64 = AtomicU64::new(0);
static BLOCKED_UNPARSEABLE: AtomicU64 = AtomicU64::new(0);
static BYPASS_DETECTED: AtomicU64 = AtomicU64::new(0);

/// What to do with one net buffer of the chain.
enum Decision {
    /// Known good: send it on untouched.
    Permit,
    /// No idea what this is. Fail closed.
    Block,
    /// Reached the wire without passing our IP layer callout. User space decides, then it is
    /// reinjected here. The `u32` is the link layer header length, needed to present the frame to
    /// user space as an IP packet.
    Bypass(Key, u32),
}

pub fn mac_frame_layer_outbound(mut data: CalloutData) {
    type Fields = FieldsOutboundMacFrameNative;
    let media_type = data.get_value_u32(Fields::NdisMediaType as usize);
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let ndis_port = data.get_value_u32(Fields::NdisPort as usize);
    let layer_id = data.get_layer_id();

    let Some(device) = crate::entry::get_device() else {
        // Should never happen.
        return;
    };

    // 1. Nothing may be held once the teardown starts: the event queue is being run down, so an
    //    absorbed frame would never get a verdict.
    if device.is_shutting_down() {
        data.action_permit();
        return;
    }

    // Logged before the ladder rather than after it, so the summary still appears on the paths
    // that return early. On a Wi-Fi only machine every frame leaves at step 4, and a summary
    // placed at the end would never be reached.
    log_counters(CLASSIFIES_SEEN.fetch_add(1, Ordering::Relaxed));
    let nbl_ptr = data.get_layer_data() as *const _;

    // 2. Our own reinjection coming back around.
    if device.injector.was_mac_packet_injected_by_self(nbl_ptr) {
        PERMIT_INJECTED.fetch_add(1, Ordering::Relaxed);
        data.action_permit();
        return;
    }

    // 3. Injected by us at the network layer, which means user space already saw it and allowed
    //    it. Covers every temporary verdict and everything that is not TCP or UDP. Free: no
    //    parsing, just an injection state query.
    if device
        .injector
        .was_network_packet_injected_by_self(nbl_ptr, false)
        || device
            .injector
            .was_network_packet_injected_by_self(nbl_ptr, true)
    {
        PERMIT_INJECTED.fetch_add(1, Ordering::Relaxed);
        data.action_permit();
        return;
    }

    // 4. A medium this callout does not parse.
    if media_type != NDIS_MEDIUM_802_3 {
        PERMIT_MEDIUM.fetch_add(1, Ordering::Relaxed);
        trace!("mac layer: media type {} not 802.3 -> permit", media_type);
        data.action_permit();
        return;
    }

    // 5 and 6, per net buffer. A list can carry a chain of them, each an independent frame with
    // its own offset and length, so every one is decided on its own.
    let mut decisions = Vec::new();
    for nbl in NetBufferListIter::new(data.get_layer_data() as _) {
        for mut nb in nbl.iter_net_buffers() {
            decisions.push(decide_frame(device, &mut nb));
        }
    }

    if decisions.is_empty() {
        // Nothing to look at. Let it go rather than black holing an empty list.
        data.action_permit();
        return;
    }

    let needs_arbitration = decisions.iter().any(|d| !matches!(d, Decision::Permit));

    if !needs_arbitration {
        PERMIT_KNOWN.fetch_add(decisions.len() as u64, Ordering::Relaxed);
        data.action_permit();
        return;
    }

    for decision in decisions.iter() {
        match decision {
            Decision::Permit => {}
            Decision::Block => {
                BLOCKED_UNPARSEABLE.fetch_add(1, Ordering::Relaxed);
            }
            Decision::Bypass(key, _) => {
                BYPASS_DETECTED.fetch_add(1, Ordering::Relaxed);
                if MAC_ENFORCE {
                    warn!("mac layer: bypass frame {} -> user space", key);
                } else {
                    warn!("mac layer: bypass frame {} -> permitted, dry run", key);
                }
            }
        }
    }

    if !MAC_ENFORCE {
        // Dry run: the decision is logged above, the frame still goes out.
        data.action_permit();
        return;
    }

    // The chain is absorbed as a whole, so anything in it that was fine has to be put back by
    // hand. Cloning happens after the absorb decision, never before, so a failed clone cannot
    // leak a frame past the filter.
    data.block_and_absorb();

    let inject_info = || MacInjectInfo {
        layer_id,
        interface_index,
        ndis_port,
    };

    let mut index = 0;
    for nbl in NetBufferListIter::new(data.get_layer_data() as _) {
        for nb in nbl.iter_net_buffers() {
            let Some(decision) = decisions.get(index) else {
                break;
            };
            index += 1;

            let (key, l2_len) = match decision {
                // Dropped outright, nothing to reinject.
                Decision::Block => continue,
                Decision::Permit => (None, 0),
                Decision::Bypass(key, l2_len) => (Some(key.clone()), *l2_len),
            };

            let clone = match nb.clone_as_nbl(&device.network_allocator) {
                Ok(clone) => clone,
                Err(err) => {
                    err!("mac layer: failed to clone frame: {}", err);
                    continue;
                }
            };
            let packet = Packet::MacLayer(clone, inject_info(), l2_len);

            match key {
                // Already decided, and only absorbed because something else in the same chain was
                // not. Put it straight back on the wire instead of paying a round trip.
                None => {
                    warn!("mac layer: mixed chain, reinjecting permitted frame");
                    if let Err(err) = device.inject_packet(packet, false) {
                        err!("mac layer: failed to reinject frame: {}", err);
                    }
                }
                Some(key) => {
                    let info =
                        device
                            .packet_cache
                            .push((key, packet), 0, Direction::Outbound, false);
                    if let Some(info) = info {
                        let _ = device.event_queue.push(info);
                    }
                }
            }
        }
    }
}

/// Steps 5 and 6 for a single frame.
fn decide_frame(device: &Device, nb: &mut NetBuffer) -> Decision {
    let mut header = [0u8; VLAN_TAGGED_HEADER_LEN as usize];

    // Too short to hold an ethernet header at all. We committed to 802.3 by the media type, so
    // this is a failed assumption and fails closed.
    if nb
        .read_bytes(&mut header[..ETHERNET_HEADER_LEN as usize])
        .is_err()
    {
        warn!("mac layer: frame shorter than an ethernet header -> block");
        return Decision::Block;
    }

    let mut ether_type = u16::from_be_bytes([header[12], header[13]]);
    let mut l2_len = ETHERNET_HEADER_LEN;

    // An inline VLAN tag pushes the real ether type out by four bytes. NDIS usually carries the
    // tag out of band instead, so this is the uncommon path, but reading the wrong offset would
    // misparse every field after it.
    if ether_type == ETHER_TYPE_VLAN {
        if nb.read_bytes(&mut header).is_err() {
            warn!("mac layer: truncated vlan tag -> block");
            return Decision::Block;
        }
        ether_type = u16::from_be_bytes([header[16], header[17]]);
        l2_len = VLAN_TAGGED_HEADER_LEN;
    }

    let ipv6 = match ether_type {
        // Identified well enough to be confident, and cheap: no further parsing. These carry no
        // IP tuple, so there is nothing user space could decide about them anyway.
        ETHER_TYPE_ARP | ETHER_TYPE_RARP | ETHER_TYPE_EAPOL | ETHER_TYPE_LLDP => {
            PERMIT_L2_CONTROL.fetch_add(1, Ordering::Relaxed);
            trace!("mac layer: ether type {:#06x} -> permit", ether_type);
            return Decision::Permit;
        }
        ETHER_TYPE_IPV4 => false,
        ETHER_TYPE_IPV6 => true,
        // Every assumption is used up.
        _ => {
            warn!("mac layer: unknown ether type {:#06x} -> block", ether_type);
            return Decision::Block;
        }
    };

    // Hand the existing IP parsers a net buffer that starts where they expect it to, then put the
    // offset back. The frame carries on down the stack after this, so leaving it moved would send
    // a headerless packet.
    nb.advance(l2_len);
    let key = if ipv6 {
        get_key_from_nb_v6(nb, Direction::Outbound)
    } else {
        get_key_from_nb_v4(nb, Direction::Outbound)
    };
    if let Err(err) = nb.retreat(l2_len, false) {
        // The offset is now wrong and the frame can no longer be sent as it is.
        err!("mac layer: failed to restore frame offset: {}", err);
        return Decision::Block;
    }

    let key = match key {
        Ok(key) => key,
        Err(err) => {
            warn!("mac layer: failed to parse ip header: {} -> block", err);
            return Decision::Block;
        }
    };

    match device.connection_cache.get_verdict(&key) {
        // Came through the stack and user space has ruled on it.
        Some(Verdict::PermanentAccept) => {
            trace!("mac layer: {} permanent accept", key);
            Decision::Permit
        }
        Some(Verdict::PermanentBlock)
        | Some(Verdict::PermanentDrop)
        | Some(Verdict::Undeterminable)
        | Some(Verdict::Failed) => {
            trace!("mac layer: {} blocked by cached verdict", key);
            Decision::Block
        }
        // A temporary or redirect verdict means the IP layer absorbed and reinjected this packet,
        // so step 3 should have caught it. Getting here means the injection mark did not survive
        // down to L2. Let it pass rather than send it round again, and say so.
        Some(verdict) => {
            warn!("mac layer: {} unexpected verdict {} at l2", key, verdict);
            Decision::Permit
        }
        // Never seen by the IP layer callout. This is the bypass.
        None => Decision::Bypass(key, l2_len),
    }
}

fn log_counters(count: u64) {
    if count % COUNTER_LOG_INTERVAL != 0 {
        return;
    }
    info!(
        "mac layer: classifies {} injected {} medium {} l2 {}",
        CLASSIFIES_SEEN.load(Ordering::Relaxed),
        PERMIT_INJECTED.load(Ordering::Relaxed),
        PERMIT_MEDIUM.load(Ordering::Relaxed),
        PERMIT_L2_CONTROL.load(Ordering::Relaxed),
    );
    info!(
        "mac layer: known {} blocked {} bypass {}",
        PERMIT_KNOWN.load(Ordering::Relaxed),
        BLOCKED_UNPARSEABLE.load(Ordering::Relaxed),
        BYPASS_DETECTED.load(Ordering::Relaxed),
    );
}
