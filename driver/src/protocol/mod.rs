use flatbuffers::FlatBufferBuilder;

use crate::types::{Info, PacketInfo};

pub use self::protocol_generated::protocol::CommandUnion;
use self::protocol_generated::protocol::{
    self, Command, InfoArgs, InfoUnion, LogLine, LogLineArgs, Packet, PacketArgs,
};
use alloc::string::String;

#[allow(unused_imports)]
#[allow(clippy::all)]
mod protocol_generated;

pub fn serialize_info(info: Info, mut writer: impl FnMut(&[u8])) {
    let mut buffer_builder = FlatBufferBuilder::new();
    match info {
        Info::PacketInfo(id, packet) => {
            serialize_packet(&mut buffer_builder, id, packet);
            writer(buffer_builder.finished_data());
        }
        Info::LogLine(line) => {
            serialize_log_lines(&mut buffer_builder, line);
            writer(buffer_builder.finished_data());
        }
    }
}

fn serialize_packet(buffer_builder: &mut FlatBufferBuilder, id: u64, packet: PacketInfo) {
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
        buffer_builder,
        &PacketArgs {
            id,
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

    let data = protocol::Info::create(
        buffer_builder,
        &InfoArgs {
            value_type: InfoUnion::Packet,
            value: Some(packet.as_union_value()),
        },
    );

    buffer_builder.finish_minimal(data);
}

fn serialize_log_lines(buffer_builder: &mut FlatBufferBuilder, line: String) {
    let buffer_line = buffer_builder.create_string(&line);
    let log_line = LogLine::create(
        buffer_builder,
        &LogLineArgs {
            line: Some(buffer_line),
        },
    );

    let data = protocol::Info::create(
        buffer_builder,
        &InfoArgs {
            value_type: InfoUnion::LogLine,
            value: Some(log_line.as_union_value()),
        },
    );

    buffer_builder.finish_minimal(data);
}

pub fn read_command(data: &[u8]) -> Option<Command> {
    if let Ok(command) = flatbuffers::root::<Command>(data) {
        return Some(command);
    }

    None
}
