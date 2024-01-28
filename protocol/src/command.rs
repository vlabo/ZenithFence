// Commands from user space

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[repr(u8)]
#[derive(Clone, Copy, FromPrimitive)]
pub enum CommandType {
    Shutdown,
    Verdict,
    RedirectV4,
    RedirectV6,
    UpdateV4,
    UpdateV6,
    ClearCache,
    GetLogs,
}

#[repr(C, packed)]
pub struct Command {
    pub command_type: CommandType,
    value: [u8; 0],
}

#[repr(C, packed)]
pub struct Verdict {
    pub id: u64,
    pub verdict: u8,
}

#[repr(C, packed)]
pub struct RedirectV4 {
    pub id: u64,
    pub remote_address: [u8; 4],
    pub remote_port: u16,
}

#[repr(C, packed)]
pub struct RedirectV6 {
    pub id: u64,
    pub remote_address: [u8; 16],
    pub remote_port: u16,
}

#[repr(C, packed)]
pub struct UpdateV4 {
    pub protocol: u8,
    pub local_address: [u8; 4],
    pub local_port: u16,
    pub remote_address: [u8; 4],
    pub remote_port: u16,
    pub verdict: u8,
    pub redirect_address: [u8; 4],
    pub redirect_port: u16,
}

#[repr(C, packed)]
pub struct UpdateV6 {
    pub protocol: u8,
    pub local_address: [u8; 16],
    pub local_port: u16,
    pub remote_address: [u8; 16],
    pub remote_port: u16,
    pub verdict: u8,
    pub redirect_address: [u8; 16],
    pub redirect_port: u16,
}

pub fn parse_type(bytes: &[u8]) -> Option<CommandType> {
    FromPrimitive::from_u8(bytes[0])
}

pub fn parse_verdict(bytes: &[u8]) -> &Verdict {
    as_type(bytes)
}

pub fn parse_redirect_v4(bytes: &[u8]) -> &RedirectV4 {
    as_type(bytes)
}

pub fn parse_redirect_v6(bytes: &[u8]) -> &RedirectV6 {
    as_type(bytes)
}

pub fn parse_update_v4(bytes: &[u8]) -> &UpdateV4 {
    as_type(bytes)
}

pub fn parse_update_v6(bytes: &[u8]) -> &UpdateV6 {
    as_type(bytes)
}

fn as_type<T>(bytes: &[u8]) -> &T {
    let ptr: *const u8 = &bytes[0];
    let t_ptr: *const T = ptr as _;
    unsafe { t_ptr.as_ref().unwrap() }
}
