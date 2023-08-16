use winapi::{
    km::wdm::{FILE_READ_DATA, FILE_WRITE_DATA},
    um::winioctl::METHOD_BUFFERED,
};

const SIOCTL_TYPE: u32 = 40000;

macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        ($device_type << 16) | ($access << 14) | ($function << 2) | ($method)
    };
}

#[repr(u32)]
enum IOCTL {
    Version = ctl_code!(
        SIOCTL_TYPE,
        0x800,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    ShutdownRequest = ctl_code!(
        SIOCTL_TYPE,
        0x801,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    RecvVerdictReq = ctl_code!(
        SIOCTL_TYPE,
        0x802,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    SetVerdict = ctl_code!(
        SIOCTL_TYPE,
        0x803,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    GetPayload = ctl_code!(
        SIOCTL_TYPE,
        0x804,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    ClearCache = ctl_code!(
        SIOCTL_TYPE,
        0x805,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    UpdateVerdict = ctl_code!(
        SIOCTL_TYPE,
        0x806,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
    GetConnectionsStat = ctl_code!(
        SIOCTL_TYPE,
        0x807,
        METHOD_BUFFERED,
        FILE_READ_DATA | FILE_WRITE_DATA
    ),
}

impl TryFrom<u32> for IOCTL {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == IOCTL::Version as u32 => Ok(IOCTL::Version),
            x if x == IOCTL::ShutdownRequest as u32 => Ok(IOCTL::ShutdownRequest),
            x if x == IOCTL::RecvVerdictReq as u32 => Ok(IOCTL::RecvVerdictReq),
            x if x == IOCTL::SetVerdict as u32 => Ok(IOCTL::SetVerdict),
            x if x == IOCTL::GetPayload as u32 => Ok(IOCTL::GetPayload),
            x if x == IOCTL::ClearCache as u32 => Ok(IOCTL::ClearCache),
            x if x == IOCTL::UpdateVerdict as u32 => Ok(IOCTL::UpdateVerdict),
            x if x == IOCTL::GetConnectionsStat as u32 => Ok(IOCTL::GetConnectionsStat),
            _ => Err(()),
        }
    }
}
