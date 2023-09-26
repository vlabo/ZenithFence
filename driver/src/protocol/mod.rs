use flatbuffers::FlatBufferBuilder;

use crate::{
    protocol::protocol_generated::protocol::{Packet, PacketArgs},
    types::PacketInfo,
};

pub use self::protocol_generated::protocol::CommandUnion;
use self::protocol_generated::protocol::{Command, Shutdown, VerdictResponse};

#[allow(unused_imports)]
mod protocol_generated;

pub fn serialize_packet(packet: PacketInfo, mut writer: impl FnMut(&[u8])) {
    let mut buffer_builder = FlatBufferBuilder::new();

    let mut process_path = None;
    if let Some(path) = packet.process_path {
        process_path = Some(buffer_builder.create_string(&path));
    }

    let local_ip = if packet.ip_v6 {
        buffer_builder.create_vector(&packet.local_ip)
    } else {
        buffer_builder.create_vector(&packet.local_ip[0..1])
    };

    let remote_ip = if packet.ip_v6 {
        buffer_builder.create_vector(&packet.remote_ip)
    } else {
        buffer_builder.create_vector(&packet.remote_ip[0..1])
    };

    let packet = Packet::create(
        &mut buffer_builder,
        &PacketArgs {
            id: packet.id,
            process_id: packet.process_id,
            process_path,
            direction: packet.direction,
            ip_v6: packet.ip_v6,
            protocol: packet.protocol,
            local_ip: Some(local_ip),
            remote_ip: Some(remote_ip),
            local_port: packet.local_port,
            remote_port: packet.remote_port,
        },
    );

    buffer_builder.finish_minimal(packet);
    writer(buffer_builder.finished_data())
}

pub fn read_command(data: &[u8]) -> Option<CommandUnion> {
    if let Ok(command) = flatbuffers::root::<Command>(data) {
        return Some(command.command_type());
    }

    return None;
}
