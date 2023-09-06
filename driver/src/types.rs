use alloc::format;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

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

impl Debug for PacketInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let local_ip: [u8; 16] = unsafe { core::mem::transmute(self.local_ip) };
        let remote_ip: [u8; 16] = unsafe { core::mem::transmute(self.remote_ip) };
        let local = format!(
            "{}.{}.{}.{}:{}",
            local_ip[0], local_ip[1], local_ip[2], local_ip[3], self.local_port
        );
        let remote = format!(
            "{}.{}.{}.{}:{}",
            remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], self.remote_port
        );
        f.debug_struct("Key")
            .field("local", &local)
            .field("remote", &remote)
            .field("protocol", &self.protocol)
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
