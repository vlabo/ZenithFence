use alloc::{format, string::String};
use core::fmt::{Debug, Display};
use num_derive::FromPrimitive;
use serde::{Deserialize, Serialize};
use wdk::{
    err,
    filter_engine::{
        callout_data::{CalloutData, ClassifyPromise},
        layer::{self, Layer},
    },
};

#[derive(Copy, Clone, FromPrimitive, Serialize, Deserialize)]
#[repr(u8)]
pub enum Verdict {
    // VerdictUndecided is the default status of new connections.
    Undecided = 0,
    Undeterminable = 1,
    Accept = 2,
    Block = 3,
    Drop = 4,
    Redirect = 5,
    Failed = 7,
}

impl Display for Verdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Verdict::Undecided => write!(f, "Undecided"),
            Verdict::Undeterminable => write!(f, "Undeterminable"),
            Verdict::Accept => write!(f, "Accept"),
            Verdict::Block => write!(f, "Block"),
            Verdict::Drop => write!(f, "Drop"),
            Verdict::Redirect => write!(f, "Redirect"),
            Verdict::Failed => write!(f, "Failed"),
        }
    }
}

#[derive(Default)]
pub struct PacketInfo {
    pub process_id: Option<u64>,
    pub process_path: Option<String>,
    pub direction: u8,
    pub ip_v6: bool,
    pub protocol: u8,
    pub flags: u8,
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub interface_index: u32,
    pub sub_interface_index: u32,
    pub classify_promise: Option<ClassifyPromise>,
}

impl PacketInfo {
    pub fn from_callout_data(data: &CalloutData) -> Self {
        match data.layer {
            Layer::FwpmLayerInboundIppacketV4 => {
                type Field = layer::FwpsFieldsInboundIppacketV4;
                Self {
                    direction: 1,
                    ip_v6: false,
                    local_ip: data
                        .get_value_u32(Field::IpLocalAddress as usize)
                        .to_le_bytes(),
                    remote_ip: data
                        .get_value_u32(Field::IpRemoteAddress as usize)
                        .to_le_bytes(),
                    interface_index: data.get_value_u32(Field::InterfaceIndex as usize),
                    sub_interface_index: data.get_value_u32(Field::SubInterfaceIndex as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerOutboundIppacketV4 => {
                type Field = layer::FwpsFieldsOutboundIppacketV4;
                Self {
                    direction: 0,
                    ip_v6: false,
                    local_ip: data
                        .get_value_u32(Field::IpLocalAddress as usize)
                        .to_le_bytes(),
                    remote_ip: data
                        .get_value_u32(Field::IpRemoteAddress as usize)
                        .to_le_bytes(),
                    interface_index: data.get_value_u32(Field::InterfaceIndex as usize),
                    sub_interface_index: data.get_value_u32(Field::SubInterfaceIndex as usize),
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
                    local_ip: data
                        .get_value_u32(Field::IpLocalAddress as usize)
                        .to_le_bytes(),
                    remote_ip: data
                        .get_value_u32(Field::IpRemoteAddress as usize)
                        .to_le_bytes(),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    remote_port: data.get_value_u16(Field::IpRemotePort as usize),
                    interface_index: data.get_value_u32(Field::InterfaceIndex as usize),
                    sub_interface_index: data.get_value_u32(Field::SubInterfaceIndex as usize),
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
                    local_ip: data
                        .get_value_u32(Field::IpLocalAddress as usize)
                        .to_le_bytes(),
                    remote_ip: data
                        .get_value_u32(Field::IpRemoteAddress as usize)
                        .to_le_bytes(),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    remote_port: data.get_value_u16(Field::IpRemotePort as usize),
                    interface_index: data.get_value_u32(Field::InterfaceIndex as usize),
                    sub_interface_index: data.get_value_u32(Field::SubInterfaceIndex as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerAleConnectRedirectV4 => {
                type Field = layer::FwpsFieldsAleConnectRedirectV4;
                Self {
                    direction: 0,
                    ip_v6: false,
                    protocol: data.get_value_u8(Field::IpProtocol as usize),
                    local_ip: data
                        .get_value_u32(Field::IpLocalAddress as usize)
                        .to_le_bytes(),
                    remote_ip: data
                        .get_value_u32(Field::IpRemoteAddress as usize)
                        .to_le_bytes(),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    remote_port: data.get_value_u16(Field::IpRemotePort as usize),
                    ..Default::default()
                }
            }
            _ => {
                let guid = data.layer.get_guid();
                err!("unsupported layer: {:#x}", guid.data1);
                Self::default()
            }
        }
    }
}

impl Debug for PacketInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let local = format!(
            "{}.{}.{}.{}:{}",
            self.local_ip[3], self.local_ip[2], self.local_ip[1], self.local_ip[0], self.local_port
        );
        let remote = format!(
            "{}.{}.{}.{}:{}",
            self.remote_ip[3],
            self.remote_ip[2],
            self.remote_ip[1],
            self.remote_ip[0],
            self.remote_port
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
