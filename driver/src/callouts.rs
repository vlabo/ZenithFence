use alloc::vec::Vec;
use smoltcp::wire::{Ipv4Packet, TcpPacket, UdpPacket};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::{self, FwpsFieldsAleAuthConnectV4};
use wdk::filter_engine::net_buffer::{read_first_packet, NBLIterator};
use wdk::filter_engine::packet::Injector;
use wdk::{dbg, err, interface};
use windows_sys::Wdk::Foundation::DEVICE_OBJECT;

use crate::{
    connection_cache::ConnectionAction,
    device::Device,
    types::{PacketInfo, Verdict},
};

pub fn ale_layer_connect(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };

    let mut packet = PacketInfo::from_callout_data(&data);
    dbg!("Connect callout: {:?}", packet);
    if let Some(action) = device.connection_cache.get_connection_action(&packet) {
        // We already have a verdict for it.
        if let ConnectionAction::Verdict(verdict) = action {
            match verdict {
                Verdict::Accept => data.action_permit(),
                Verdict::Block => data.action_block(),
                Verdict::Drop | Verdict::Undecided | Verdict::Undeterminable | Verdict::Failed => {
                    data.block_and_absorb()
                }
                Verdict::Redirect => data.action_continue(),
            }
        }
    } else {
        // Pend decision of connection.
        let mut packet_list = None;
        if packet.protocol == 17 {
            packet_list = Some(Injector::from_ale_callout(
                &data,
                false,
                packet.remote_ip,
                packet.interface_index,
                packet.sub_interface_index,
            ));
        }
        let promise = if data.is_reauthorize(FwpsFieldsAleAuthConnectV4::Flags as usize) {
            data.pend_filter_rest(packet_list)
        } else {
            match data.pend_operation(packet_list) {
                Ok(cc) => cc,
                Err(error) => {
                    err!("failed to postpone decision: {}", error);
                    return;
                }
            }
        };

        // Send request to userspace.
        packet.classify_promise = Some(promise);
        let serialized = device.packet_cache.push_and_serialize(packet);
        if let Ok(bytes) = serialized {
            let _ = device.io_queue.push(bytes);
        }

        data.block_and_absorb();
    }
}

pub fn redirect_packet(
    device: &mut Device,
    packet: Vec<u8>,
    if_index: u32,
    sub_inf_index: u32,
) -> Result<(), ()> {
    if let Ok(nbl) = device.network_allocator.wrap_packet_in_nbl(&packet) {
        let packet = Injector::from_ip_callout(nbl, false, if_index, sub_inf_index);
        if let Err(err) = device.injector.inject_packet_list_network(packet) {
            err!("failed to inject packet: {}", err);
        } else {
            return Ok(());
        }
    }
    return Err(());
}

pub fn network_layer_outbound(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    type Fields = layer::FwpsFieldsOutboundIppacketV4;

    let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    else {
        return;
    };
    if device
        .injector
        .was_netwrok_packet_injected_by_self(data.get_layer_data() as _)
    {
        dbg!("injected packet");
        data.action_permit();
        return;
    }

    for (i, nbl) in NBLIterator::new(data.get_layer_data() as _)
        .into_iter()
        .enumerate()
    {
        let Ok((full_packet, buffer)) = read_first_packet(nbl) else {
            err!("failed to get net_buffer data");
            data.action_permit();
            return;
        };
        if let Ok(ip_packet) = Ipv4Packet::new_checked(full_packet) {
            match ip_packet.next_header() {
                smoltcp::wire::IpProtocol::Tcp => {
                    if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                        wdk::info!("packet {}: {} {}", i, ip_packet, tcp_packet);
                    }
                }
                smoltcp::wire::IpProtocol::Udp => {
                    if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
                        wdk::info!("packet {}: {} {}", i, ip_packet, udp_packet);
                    }
                    let buffer = buffer.unwrap_or(full_packet.to_vec());
                    if redirect_packet(
                        device,
                        buffer,
                        data.get_value_u32(Fields::InterfaceIndex as usize),
                        data.get_value_u32(Fields::SubInterfaceIndex as usize),
                    )
                    .is_ok()
                    {
                        data.block_and_absorb();
                        return;
                    }
                }
                _ => {
                    err!("unsupported protocol {}: {}", i, ip_packet.next_header());
                }
            }
        } else {
            err!("failed to parse packet");
        }
    }

    data.action_permit();
}
