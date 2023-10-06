use alloc::{format, string::String};
use core::fmt::Debug;
use wdk::{
    err,
    filter_engine::layer::{self, Layer},
    utils::CallData,
};

pub enum Info {
    PacketInfo(u64, PacketInfo),
    LogLine(String),
}

#[derive(Default, Clone)]
pub struct PacketInfo {
    pub process_id: Option<u64>,
    pub process_path: Option<String>,
    pub direction: u8,
    pub ip_v6: bool,
    pub protocol: u8,
    pub flags: u8,
    pub local_ip: [u32; 4],
    pub remote_ip: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub compartment_id: u64,
    pub interface_index: u32,
    pub sub_interface_index: u32,
    pub packet_size: u32,
}

impl PacketInfo {
    pub fn from_call_data(data: &CallData) -> Self {
        match data.layer {
            Layer::FwpmLayerInboundIppacketV4 => {
                type Field = layer::FwpsFieldsInboundIppacketV4;
                Self {
                    direction: 1,
                    ip_v6: false,
                    local_ip: [data.get_value_u32(Field::IpLocalAddress as usize), 0, 0, 0],
                    remote_ip: [data.get_value_u32(Field::IpRemoteAddress as usize), 0, 0, 0],
                    ..Default::default()
                }
            }
            Layer::FwpmLayerAleAuthConnectV4 => {
                type Field = layer::FwpsFieldsAleAuthConnectV4;
                Self {
                    process_id: data.get_process_id(),
                    process_path: data.get_process_path(),
                    direction: 0,
                    ip_v6: false,
                    protocol: data.get_value_u8(Field::IpProtocol as usize),
                    local_ip: [data.get_value_u32(Field::IpLocalAddress as usize), 0, 0, 0],
                    remote_ip: [data.get_value_u32(Field::IpRemoteAddress as usize), 0, 0, 0],
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    remote_port: data.get_value_u16(Field::IpRemotePort as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerAleAuthRecvAcceptV4 => {
                type Field = layer::FwpsFieldsAleAuthRecvAcceptV4;
                Self {
                    process_id: data.get_process_id(),
                    process_path: data.get_process_path(),
                    direction: 1,
                    ip_v6: false,
                    protocol: data.get_value_u8(Field::IpProtocol as usize),
                    local_ip: [data.get_value_u32(Field::IpLocalAddress as usize), 0, 0, 0],
                    remote_ip: [data.get_value_u32(Field::IpRemoteAddress as usize), 0, 0, 0],
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    remote_port: data.get_value_u16(Field::IpRemotePort as usize),
                    ..Default::default()
                }
            }
            _ => {
                err!("unsupported layer");
                Self::default()
            }
        }
    }
}

impl Debug for PacketInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let local_ip: [u8; 4] = self.local_ip[0].to_be_bytes();
        let remote_ip: [u8; 4] = self.remote_ip[0].to_be_bytes();
        let local = format!(
            "{}.{}.{}.{}:{}",
            local_ip[0],
            local_ip[1],
            local_ip[2],
            local_ip[3],
            u16::to_be(self.local_port)
        );
        let remote = format!(
            "{}.{}.{}.{}:{}",
            remote_ip[0],
            remote_ip[1],
            remote_ip[2],
            remote_ip[3],
            u16::to_be(self.remote_port)
        );
        f.debug_struct("Key")
            .field("local", &local)
            .field("remote", &remote)
            .field("protocol", &self.protocol)
            .field("direction", &self.direction)
            .finish()
    }
}

// impl PacketInfo {
// pub fn get_verdict_key(&self) -> Key {
//     Key {
//         local_ip: self.local_ip,
//         local_port: self.local_port,
//         remote_ip: self.remote_ip,
//         remote_port: self.remote_port,
//         protocol: self.protocol,
//     }
// }

// pub fn get_redirect_key(&self) -> Key {
//     Key {
//         local_ip: self.local_ip,
//         local_port: self.local_port,
//         remote_ip: self.local_ip,
//         remote_port: 0,
//         protocol: self.protocol,
//     }
// }
// }
