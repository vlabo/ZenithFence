use smoltcp::wire::{Ipv4Packet, TcpPacket, UdpPacket};
use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::FwpsFieldsAleAuthConnectV4;
use wdk::filter_engine::net_buffer::read_first_packet;
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
            packet_list = Some(Injector::clone_layer_data(
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

pub fn network_layer_outbound(mut data: CalloutData, device_object: &mut DEVICE_OBJECT) {
    let _ = device_object;
    // let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
    // else {
    //     return;
    // };
    let Ok((full_packet, _buffer)) = read_first_packet(data.get_layer_data() as _) else {
        err!("faield to get net_buffer data");
        data.action_permit();
        return;
    };
    if let Ok(ip_packet) = Ipv4Packet::new_checked(full_packet) {
        match ip_packet.next_header() {
            smoltcp::wire::IpProtocol::Tcp => {
                if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                    wdk::info!("packet: {} {}", ip_packet, tcp_packet);
                }
            }
            smoltcp::wire::IpProtocol::Udp => {
                if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
                    wdk::info!("packet: {} {}", ip_packet, udp_packet);
                }
            }
            _ => {
                err!("unsupported protocol: {}", ip_packet.next_header());
            }
        }
    } else {
        err!("failed to parse packet");
    }

    data.action_permit();
}
