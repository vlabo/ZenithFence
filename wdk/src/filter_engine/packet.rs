use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{ffi::c_void, mem::MaybeUninit};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE, NTSTATUS},
    Networking::WinSock::ADDRESS_FAMILY,
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SCOPE_ID},
    System::Kernel::{COMPARTMENT_ID, UNSPECIFIED_COMPARTMENT_ID},
};

use crate::utils::check_ntstatus;

use super::{
    callout_data::CalloutData,
    net_buffer::{
        FwpsDereferenceNetBufferList0, FwpsInjectionHandleDestroy0, FwpsReferenceNetBufferList0,
        NetworkAllocator, NET_BUFFER_LIST,
    },
};

const FWPS_INJECTION_TYPE_STREAM: u32 = 0x00000001;
const FWPS_INJECTION_TYPE_TRANSPORT: u32 = 0x00000002;
const FWPS_INJECTION_TYPE_NETWORK: u32 = 0x00000004;
const FWPS_INJECTION_TYPE_FORWARD: u32 = 0x00000008;
const FWPS_INJECTION_TYPE_L2: u32 = 0x00000010;
const FWPS_INJECTION_TYPE_VSWITCH_TRANSPORT: u32 = 0x00000020;

#[allow(non_camel_case_types)]
type FWPS_INJECT_COMPLETE0 = unsafe extern "C" fn(
    context: *mut c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    dispatch_level: bool,
);

#[allow(non_camel_case_types)]
#[repr(C)]
struct FWPS_TRANSPORT_SEND_PARAMS1 {
    remote_address: *const u8,
    remote_scope_id: SCOPE_ID,
    control_data: *mut c_void, //WSACMSGHDR,
    control_data_length: u32,
    header_include_header: *mut u8,
    header_include_header_length: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
enum FWPS_PACKET_INJECTION_STATE {
    FWPS_PACKET_NOT_INJECTED,
    FWPS_PACKET_INJECTED_BY_SELF,
    FWPS_PACKET_INJECTED_BY_OTHER,
    FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF,
    FWPS_PACKET_INJECTION_STATE_MAX,
}

#[allow(dead_code)]
extern "C" {
    fn FwpsInjectNetworkSendAsync0(
        injectionHandle: HANDLE,
        injectionContext: HANDLE,
        flags: u32,
        compartmentId: COMPARTMENT_ID,
        netBufferList: *mut NET_BUFFER_LIST,
        completionFn: FWPS_INJECT_COMPLETE0,
        completionContext: *mut c_void,
    ) -> NTSTATUS;

    fn FwpsInjectNetworkReceiveAsync0(
        injectionHandle: HANDLE,
        injectionContext: HANDLE,
        flags: u32,
        compartmentId: COMPARTMENT_ID,
        interfaceIndex: u32,
        subInterfaceIndex: u32,
        netBufferList: *mut NET_BUFFER_LIST,
        completionFn: FWPS_INJECT_COMPLETE0,
        completionContext: *mut c_void,
    ) -> NTSTATUS;

    fn FwpsInjectTransportSendAsync1(
        injectionHandle: HANDLE,
        injectionContext: HANDLE,
        endpointHandle: u64,
        flags: u32,
        sendArgs: *mut FWPS_TRANSPORT_SEND_PARAMS1,
        addressFamily: ADDRESS_FAMILY,
        compartmentId: COMPARTMENT_ID,
        netBufferList: *mut NET_BUFFER_LIST,
        completionFn: FWPS_INJECT_COMPLETE0,
        completionContext: *mut c_void,
    ) -> NTSTATUS;

    fn FwpsInjectTransportReceiveAsync0(
        injectionHandle: HANDLE,
        injectionContext: HANDLE,
        reserved: *const c_void,
        flags: u32,
        addressFamily: ADDRESS_FAMILY,
        compartmentId: COMPARTMENT_ID,
        interfaceIndex: u32,
        subInterfaceIndex: u32,
        netBufferList: *mut NET_BUFFER_LIST,
        completionFn: FWPS_INJECT_COMPLETE0,
        completionContext: *mut c_void,
    ) -> NTSTATUS;

    fn FwpsInjectionHandleCreate0(
        addressFamily: ADDRESS_FAMILY,
        flags: u32,
        injectionHandle: &mut HANDLE,
    ) -> NTSTATUS;

    fn FwpsQueryPacketInjectionState0(
        injectionHandle: HANDLE,
        netBufferList: *const NET_BUFFER_LIST,
        injectionContext: *mut HANDLE,
    ) -> FWPS_PACKET_INJECTION_STATE;
}

pub struct PacketList {
    ale: bool,
    nbl: *mut NET_BUFFER_LIST,
    inbound: bool,
    remote_ip: [u8; 4],
    compartment_id: COMPARTMENT_ID,
    interface_index: u32,
    sub_interface_index: u32,
    endpoint_handle: u64,
    remote_scope_id: SCOPE_ID,
    control_data: Option<Vec<u8>>,
}

impl Drop for PacketList {
    fn drop(&mut self) {
        if !self.nbl.is_null() {
            if self.ale {
                unsafe {
                    FwpsDereferenceNetBufferList0(self.nbl, false);
                }
            } else {
                NetworkAllocator::free_net_buffer(self.nbl);
            }
        }
    }
}

pub struct Injector {
    transport_inject_handle: HANDLE,
    network_inject_handle: HANDLE,
}

impl Injector {
    pub fn new() -> Self {
        let mut transport_inject_handle: HANDLE = INVALID_HANDLE_VALUE;
        let mut network_inject_handle: HANDLE = INVALID_HANDLE_VALUE;
        unsafe {
            let status = FwpsInjectionHandleCreate0(
                AF_UNSPEC,
                FWPS_INJECTION_TYPE_TRANSPORT,
                &mut transport_inject_handle,
            );
            if let Err(err) = check_ntstatus(status) {
                crate::err!("error allocating transport inject handle: {}", err);
            }
            let status = FwpsInjectionHandleCreate0(
                AF_INET,
                FWPS_INJECTION_TYPE_NETWORK,
                &mut network_inject_handle,
            );

            if let Err(err) = check_ntstatus(status) {
                crate::err!("error allocating network inject handle: {}", err);
            }
        }
        Self {
            transport_inject_handle,
            network_inject_handle,
        }
    }

    pub fn from_ale_callout(
        callout_data: &CalloutData,
        inbound: bool,
        remote_ip: [u8; 4],
        interface_index: u32,
        sub_interface_index: u32,
    ) -> PacketList {
        unsafe {
            FwpsReferenceNetBufferList0(callout_data.layer_data as _, true);
        }
        let mut control_data = None;
        if let Some(cd) = callout_data.get_control_data() {
            control_data = Some(cd.to_vec());
        }

        PacketList {
            ale: true,
            nbl: callout_data.layer_data as _,
            inbound,
            remote_ip,
            compartment_id: UNSPECIFIED_COMPARTMENT_ID,
            interface_index,
            sub_interface_index,
            endpoint_handle: callout_data.get_transport_endpoint_handle().unwrap_or(0),
            remote_scope_id: callout_data
                .get_remote_scope_id()
                .unwrap_or(unsafe { MaybeUninit::zeroed().assume_init() }),
            control_data,
        }
    }

    pub fn from_ip_callout(
        nbl: *mut NET_BUFFER_LIST,
        inbound: bool,
        interface_index: u32,
        sub_interface_index: u32,
    ) -> PacketList {
        PacketList {
            ale: false,
            nbl,
            inbound,
            remote_ip: [0; 4],
            compartment_id: UNSPECIFIED_COMPARTMENT_ID,
            interface_index,
            sub_interface_index,
            endpoint_handle: 0,
            remote_scope_id: unsafe { MaybeUninit::zeroed().assume_init() },
            control_data: None,
        }
    }

    pub fn inject_packet_list_transport(&self, packet_list: PacketList) -> Result<(), String> {
        if self.transport_inject_handle == INVALID_HANDLE_VALUE {
            return Err("failed to inject packet: invalid handle value".to_string());
        }
        unsafe {
            let packet_list_boxed = Box::new(packet_list);
            let packet_list = Box::into_raw(packet_list_boxed).as_mut().unwrap();
            let mut control_data_length = 0;
            let control_data = match &packet_list.control_data {
                Some(cd) => {
                    control_data_length = cd.len();
                    cd.as_ptr()
                }
                None => core::ptr::null_mut(),
            };

            let mut send_params = FWPS_TRANSPORT_SEND_PARAMS1 {
                remote_address: &packet_list.remote_ip as _,
                remote_scope_id: packet_list.remote_scope_id,
                control_data: control_data as _,
                control_data_length: control_data_length as u32,
                header_include_header: core::ptr::null_mut(),
                header_include_header_length: 0,
            };

            let status = FwpsInjectTransportSendAsync1(
                self.transport_inject_handle,
                0,
                packet_list.endpoint_handle,
                0,
                &mut send_params,
                AF_INET,
                packet_list.compartment_id,
                packet_list.nbl,
                free_packet,
                (packet_list as *mut PacketList) as _,
            );
            if let Err(err) = check_ntstatus(status) {
                _ = Box::from_raw(packet_list);
                return Err(err);
            }
        }

        return Ok(());
    }

    pub fn inject_packet_list_network(&self, packet_list: PacketList) -> Result<(), String> {
        if self.network_inject_handle == INVALID_HANDLE_VALUE {
            return Err("failed to inject packet: invalid handle value".to_string());
        }

        unsafe {
            if packet_list.inbound {
                let packet_list_boxed = Box::new(packet_list);
                let packet_list = Box::into_raw(packet_list_boxed).as_mut().unwrap();
                let status = FwpsInjectNetworkReceiveAsync0(
                    self.network_inject_handle,
                    0,
                    0,
                    packet_list.compartment_id,
                    packet_list.interface_index,
                    packet_list.sub_interface_index,
                    packet_list.nbl,
                    free_packet,
                    (packet_list as *mut PacketList) as _,
                );
                if let Err(err) = check_ntstatus(status) {
                    _ = Box::from_raw(packet_list);
                    return Err(err);
                }
            } else {
                let packet_list_boxed = Box::new(packet_list);
                let packet_list = Box::into_raw(packet_list_boxed).as_mut().unwrap();
                let status = FwpsInjectNetworkSendAsync0(
                    self.network_inject_handle,
                    0,
                    0,
                    packet_list.compartment_id,
                    packet_list.nbl,
                    free_packet,
                    (packet_list as *mut PacketList) as _,
                );
                if let Err(err) = check_ntstatus(status) {
                    _ = Box::from_raw(packet_list);
                    return Err(err);
                }
            }
        }
        return Ok(());
    }

    pub fn was_netwrok_packet_injected_by_self(&self, nbl: *const NET_BUFFER_LIST) -> bool {
        if self.network_inject_handle == INVALID_HANDLE_VALUE || self.network_inject_handle == 0 {
            return false;
        }

        unsafe {
            let state = FwpsQueryPacketInjectionState0(
                self.network_inject_handle,
                nbl,
                core::ptr::null_mut(),
            );

            match state {
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_NOT_INJECTED => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_OTHER => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTION_STATE_MAX => true,
            }
        }
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        unsafe {
            if self.transport_inject_handle != INVALID_HANDLE_VALUE
                && self.transport_inject_handle != 0
            {
                FwpsInjectionHandleDestroy0(self.transport_inject_handle);
                self.transport_inject_handle = INVALID_HANDLE_VALUE;
            }
            if self.network_inject_handle != INVALID_HANDLE_VALUE && self.network_inject_handle != 0
            {
                FwpsInjectionHandleDestroy0(self.network_inject_handle);
                self.network_inject_handle = INVALID_HANDLE_VALUE;
            }
        }
    }
}

unsafe extern "C" fn free_packet(
    context: *mut c_void,
    _net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: bool,
) {
    _ = Box::from_raw(context as *mut PacketList);
}
