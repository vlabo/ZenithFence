use alloc::boxed::Box;

#[repr(u8)]
#[derive(Clone, Copy)]
enum InfoType {
    ConnectionIPV4,
}

#[repr(C, packed)]
pub struct Info {
    info_type: InfoType,
    value: [u8; 0],
}

impl Info {
    pub fn get_info_type(&self) -> u8 {
        self.info_type as u8
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self.info_type {
            InfoType::ConnectionIPV4 => {
                let info_ptr: *const Info = self as _;
                let ptr: *const u8 = info_ptr as _;
                unsafe {
                    core::slice::from_raw_parts(
                        ptr,
                        core::mem::size_of::<InternalInfo<ConnectionInfoV4>>(),
                    )
                }
            }
        }
    }
}

#[repr(C, packed)]
struct InternalInfo<T> {
    info_type: InfoType,
    value: T,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnectionInfoV4 {
    pub id: u64,
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
}

impl ConnectionInfoV4 {
    pub fn as_info(self) -> Box<Info> {
        let internal_info = Box::new(InternalInfo {
            info_type: InfoType::ConnectionIPV4,
            value: self,
        });
        unsafe { Box::from_raw(Box::into_raw(internal_info) as *mut Info) }
    }
}

#[test]
fn connection_info() {
    let conn_info = ConnectionInfoV4 {
        id: 1,
        process_id: 2,
        direction: 3,
        protocol: 4,
        local_ip: [5, 6, 7, 8],
        remote_ip: [9, 10, 11, 12],
        local_port: 13,
        remote_port: 14,
    };
    let info = conn_info.as_info();
    let bytes = info.as_bytes();
    assert_eq!(
        bytes.len(),
        core::mem::size_of::<InternalInfo<ConnectionInfoV4>>()
    );

    assert_eq!(
        bytes,
        [
            0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
            0, 14, 0, 0, 0
        ]
    );
}
