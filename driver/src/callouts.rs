use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::FwpsFieldsAleAuthConnectV4;
use wdk::filter_engine::packet::Injector;
use wdk::{dbg, err, info, interface};
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
                Verdict::Accept => {
                    data.permit();
                }
                Verdict::Block => {
                    data.block();
                }
                Verdict::Drop => {
                    data.block_and_absorb();
                }
                Verdict::Failed => {
                    data.block();
                }
                _ => {}
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

// pub fn network_layer_outbound(mut data: CalloutData, _device_object: &mut DEVICE_OBJECT) {
//     // let Ok(device) = interface::get_device_context_from_device_object::<Device>(device_object)
//     // else {
//     //     return;
//     // };

//     // let packet = PacketInfo::from_callout_data(&data);
//     // info!("network layer: {:?}", packet);
//     data.permit();
// }
