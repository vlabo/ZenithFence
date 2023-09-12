use alloc::format;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};
use wdk::utils::CallData;

#[derive(Serialize, Deserialize, Clone, Copy)] // needed for codegen
pub struct PacketInfo {
    pub id: u32,
    pub process_id: Option<u64>,
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

// unsafe impl Zeroable for PacketInfo {
//     fn zeroed() -> Self {
//         unsafe { core::mem::zeroed() }
//     }
// }

// unsafe impl Pod for PacketInfo {}

impl PacketInfo {
    pub fn from_call_data(data: CallData) -> Self {
        return Self {
            id: 0,
            process_id: None,
            direction: data.get_direction(),
            ip_v6: false, // FIXME: get value form call data
            protocol: 6,  // FIXME: get value form call data
            flags: 0,
            local_ip: [data.get_local_ipv4(), 0, 0, 0],
            remote_ip: [data.get_remote_ipv4(), 0, 0, 0],
            local_port: 0,  // data.get_local_port(),
            remote_port: 0, // data.get_remote_port(),
            compartment_id: 0,
            interface_index: 0,
            sub_interface_index: 0,
            packet_size: 0,
        };
    }
}

impl Debug for PacketInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let local_ip: [u8; 4] = unsafe { core::mem::transmute(u32::to_be(self.local_ip[0])) };
        let remote_ip: [u8; 4] = unsafe { core::mem::transmute(u32::to_be(self.remote_ip[0])) };
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
