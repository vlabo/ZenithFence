use alloc::string::String;
use alloc::sync::Arc;
use smoltcp::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer;
use wdk::filter_engine::net_buffer::{NetBufferList, NetBufferListIter};
use wdk::filter_engine::packet::InjectInfo;

use crate::connection::{Connection, ConnectionV4, ConnectionV6, Direction, Key, Verdict};
use crate::connection_cache::ConnectionCache;
use crate::device::{Device, Packet};
use crate::packet_util::{
    get_key_from_nbl_v4, get_key_from_nbl_v6, recalc_header_checksums, Redirect,
};
use crate::{err, warn};

trait IpVersion: Connection + Sized {
    const HEADER_LEN: u32;
    const IS_IPV6: bool;
    fn get_key_from_nbl(nbl: &NetBufferList, direction: Direction) -> Result<Key, String>;
    fn get_connection(cache: &ConnectionCache, key: &Key) -> Option<Arc<Self>>;
}

impl IpVersion for ConnectionV4 {
    const HEADER_LEN: u32 = IPV4_HEADER_LEN as u32;
    const IS_IPV6: bool = false;

    fn get_key_from_nbl(nbl: &NetBufferList, direction: Direction) -> Result<Key, String> {
        get_key_from_nbl_v4(nbl, direction)
    }

    fn get_connection(cache: &ConnectionCache, key: &Key) -> Option<Arc<Self>> {
        cache.get_connection_v4(key)
    }
}

impl IpVersion for ConnectionV6 {
    const HEADER_LEN: u32 = IPV6_HEADER_LEN as u32;
    const IS_IPV6: bool = true;

    fn get_key_from_nbl(nbl: &NetBufferList, direction: Direction) -> Result<Key, String> {
        get_key_from_nbl_v6(nbl, direction)
    }

    fn get_connection(cache: &ConnectionCache, key: &Key) -> Option<Arc<Self>> {
        cache.get_connection_v6(key)
    }
}

// -------- IP packet layers

// Out packet v4
pub fn ip_packet_layer_outbound_v4(data: CalloutData) {
    type Fields = layer::FieldsOutboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);
    let compartment_id = data.get_value_u32(Fields::CompartmentId as usize) as i32;

    ip_packet_layer::<ConnectionV4>(
        data,
        Direction::Outbound,
        interface_index,
        sub_interface_index,
        compartment_id,
    );
}

// In packet v4
pub fn ip_packet_layer_inbound_v4(data: CalloutData) {
    type Fields = layer::FieldsInboundIppacketV4;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);
    let compartment_id = data.get_value_u32(Fields::CompartmentId as usize) as i32;

    ip_packet_layer::<ConnectionV4>(
        data,
        Direction::Inbound,
        interface_index,
        sub_interface_index,
        compartment_id,
    );
}

// Out packet v6
pub fn ip_packet_layer_outbound_v6(data: CalloutData) {
    type Fields = layer::FieldsOutboundIppacketV6;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);
    let compartment_id = data.get_value_u32(Fields::CompartmentId as usize) as i32;

    ip_packet_layer::<ConnectionV6>(
        data,
        Direction::Outbound,
        interface_index,
        sub_interface_index,
        compartment_id,
    );
}

// In packet v6
pub fn ip_packet_layer_inbound_v6(data: CalloutData) {
    type Fields = layer::FieldsInboundIppacketV6;
    let interface_index = data.get_value_u32(Fields::InterfaceIndex as usize);
    let sub_interface_index = data.get_value_u32(Fields::SubInterfaceIndex as usize);
    let compartment_id = data.get_value_u32(Fields::CompartmentId as usize) as i32;

    ip_packet_layer::<ConnectionV6>(
        data,
        Direction::Inbound,
        interface_index,
        sub_interface_index,
        compartment_id,
    );
}

// ip_packet_layer generic function handling all packet callouts
fn ip_packet_layer<T: IpVersion>(
    mut data: CalloutData,
    direction: Direction,
    interface_index: u32,
    sub_interface_index: u32,
    compartment_id: i32,
) {
    // Get the current device object.
    let Some(device) = crate::entry::get_device() else {
        // Should never happen.
        return;
    };

    // Allow previously injected packets.
    if device
        .injector
        .was_network_packet_injected_by_self(data.get_layer_data() as _, T::IS_IPV6)
    {
        data.action_permit();
        return;
    }

    // Walk over all net buffers.
    for mut nbl in NetBufferListIter::new(data.get_layer_data() as _) {
        // Special condition for inbound packets.
        if let Direction::Inbound = direction {
            // The first index to the packet is set to the transport header. Retreat to the IP header.
            // The NBL will auto advance after it loses scope.
            nbl.retreat(T::HEADER_LEN, true);
        }

        // Get key from packet.
        let key = match T::get_key_from_nbl(&nbl, direction) {
            Ok(key) => key,
            Err(err) => {
                warn!("failed to get key from nbl: {}", err);
                return;
            }
        };

        let mut is_tmp_verdict = false;
        let mut process_id = 0;

        let packet_size = nbl.get_data_length();

        if matches!(
            key.protocol,
            smoltcp::wire::IpProtocol::Tcp | smoltcp::wire::IpProtocol::Udp
        ) {
            // TCP and UDP always need to go through ALE layer first.

            // Check if there is already connection object.
            if let Some(conn) = T::get_connection(&device.connection_cache, &key) {
                // Connection object found.

                conn.update_bandwidth_data(packet_size, direction);
                process_id = conn.get_process_id();

                // Check if there is action for this connection.
                match conn.get_verdict() {
                    Verdict::Undecided | Verdict::Accept | Verdict::Block | Verdict::Drop => {
                        // Temporary verdicts have special paths.
                        is_tmp_verdict = true
                    }
                    Verdict::PermanentAccept => data.action_permit(),
                    Verdict::PermanentBlock => data.action_block(),
                    Verdict::Undeterminable | Verdict::PermanentDrop | Verdict::Failed => {
                        data.block_and_absorb()
                    }
                    Verdict::RedirectNameServer | Verdict::RedirectTunnel => {
                        if let Some(redirect_info) = conn.redirect_info() {
                            match clone_packet(
                                device,
                                nbl,
                                direction,
                                T::IS_IPV6,
                                key.is_loopback(),
                                interface_index,
                                sub_interface_index,
                                compartment_id,
                            ) {
                                Ok(mut packet) => {
                                    let _ = packet.redirect(redirect_info);
                                    if let Err(err) = device.inject_packet(packet, false) {
                                        err!("failed to inject packet: {}", err);
                                    }
                                }
                                Err(err) => err!("failed to clone packet: {}", err),
                            }
                        }

                        // This will block the original packet. Even if injection failed.
                        data.block_and_absorb();
                        continue;
                    }
                }
            } else {
                // TCP and UDP always need to go through ALE layer first.
                if matches!(direction, Direction::Inbound) {
                    // If it's an inbound packet and the connection is not found, continue to ALE layer
                    warn!("connection not found for inbound packet: {}", key);
                    data.action_permit();
                    return;
                } else {
                    // This happens when connection is closed and there are leftover packets that cannot be associated to a connection.
                    data.block_and_absorb();
                    return;
                }
            }
        } else {
            // Every other protocol treat as a tmp verdict.
            is_tmp_verdict = true;
        }

        // Clone packet and send to user space if it's a temporary verdict.
        if is_tmp_verdict {
            // The decision for the packet is not jet made. If clone fails, it should not allow the packet.
            data.block_and_absorb();

            let packet = match clone_packet(
                device,
                nbl,
                direction,
                T::IS_IPV6,
                key.is_loopback(),
                interface_index,
                sub_interface_index,
                compartment_id,
            ) {
                Ok(p) => p,
                Err(err) => {
                    err!("failed to clone packet: {}", err);
                    return;
                }
            };

            let info = device
                .packet_cache
                .push((key, packet), process_id, direction, false);
            // Send to Userspace
            if let Some(info) = info {
                let _ = device.event_queue.push(info);
            }
        }
    }
}

fn clone_packet(
    device: &mut Device,
    nbl: NetBufferList,
    direction: Direction,
    ipv6: bool,
    loopback: bool,
    interface_index: u32,
    sub_interface_index: u32,
    compartment_id: i32,
) -> Result<Packet, String> {
    let mut clone = nbl.clone(&device.network_allocator)?;
    let inbound = match direction {
        Direction::Outbound => false,
        Direction::Inbound => true,
    };
    if let Some(data) = clone.get_data_mut() {
        recalc_header_checksums(data, ipv6);
    }
    Ok(Packet::PacketLayer(
        clone,
        InjectInfo {
            ipv6,
            inbound,
            loopback,
            interface_index,
            sub_interface_index,
            compartment_id,
        },
    ))
}
