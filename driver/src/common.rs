#![allow(dead_code)]

pub const ICMPV4_CODE_DESTINATION_UNREACHABLE: u32 = 3;
pub const ICMPV4_CODE_DU_PORT_UNREACHABLE: u32 = 3; // Destination Unreachable (Port unreachable) ;
pub const ICMPV4_CODE_DU_ADMINISTRATIVELY_PROHIBITED: u32 = 13; // Destination Unreachable (Communication Administratively Prohibited) ;

pub const ICMPV6_CODE_DESTINATION_UNREACHABLE: u32 = 1;
pub const ICMPV6_CODE_DU_PORT_UNREACHABLE: u32 = 4; // Destination Unreachable (Port unreachable) ;

enum Direction {
    Outbound = 0,
    Inbound = 1,
}

const SIOCTL_TYPE: u32 = 40000;
macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        ($device_type << 16) | ($access << 14) | ($function << 2) | $method
    };
}

pub const METHOD_BUFFERED: u32 = 0;
pub const METHOD_IN_DIRECT: u32 = 1;
pub const METHOD_OUT_DIRECT: u32 = 2;
pub const METHOD_NEITHER: u32 = 3;

pub const FILE_READ_DATA: u32 = 0x0001; // file & pipe
pub const FILE_WRITE_DATA: u32 = 0x0002; // file & pipe

pub const IOCTL_VERSION: u32 = ctl_code!(
    SIOCTL_TYPE,
    0x800,
    METHOD_BUFFERED,
    FILE_READ_DATA | FILE_WRITE_DATA
);
