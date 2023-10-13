use wdk::filter_engine::callout_data::CalloutData;
use wdk::filter_engine::layer::FwpsFieldsAleAuthConnectV4;
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
    } else if data.is_reauthorize(FwpsFieldsAleAuthConnectV4::Flags as usize) {
        // Send request to userspace.
        let promise = data.pend_classification();

        let clone = packet.clone();
        packet.classify_promise = Some(promise);
        let id = device.packet_cache.push(packet);
        if let Ok(bytes) = clone.serialize(id) {
            let _ = device.io_queue.push(bytes);
        }

        data.block_and_absorb();
    } else {
        // Send request to userspace.
        let promise = match data.pend_operation() {
            Ok(cc) => cc,
            Err(error) => {
                err!("failed to postpone decision: {}", error);
                data.block();
                return;
            }
        };
        let clone = packet.clone();
        packet.classify_promise = Some(promise);
        let id = device.packet_cache.push(packet);
        if let Ok(bytes) = clone.serialize(id) {
            let _ = device.io_queue.push(bytes);
        }
    }
}
