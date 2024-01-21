#[repr(u8)]
#[derive(Clone, Copy)]
pub enum CommandType {
    Shutdown,
    Verdict,
    RedirectV4,
    UpdateV4,
    ClearCache,
    GetLogs,
}

// Commands from user space
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

pub fn parse_type(bytes: &[u8]) -> CommandType {
    let ptr: *const u8 = &bytes[0];
    let command_type: *const CommandType = ptr as _;
    unsafe { *command_type.as_ref().unwrap() }
}

pub fn parse_verdict(bytes: &[u8]) -> &Verdict {
    let ptr: *const u8 = &bytes[0];
    let verdict_ptr: *const Verdict = ptr as _;
    unsafe { verdict_ptr.as_ref().unwrap() }
}

pub fn parse_redirect_v4(bytes: &[u8]) -> &RedirectV4 {
    let ptr: *const u8 = &bytes[0];
    let redirect_ptr: *const RedirectV4 = ptr as _;
    unsafe { redirect_ptr.as_ref().unwrap() }
}

pub fn parse_update_v4(bytes: &[u8]) -> &UpdateV4 {
    let ptr: *const u8 = &bytes[0];
    let update_ptr: *const UpdateV4 = ptr as _;
    unsafe { update_ptr.as_ref().unwrap() }
}
