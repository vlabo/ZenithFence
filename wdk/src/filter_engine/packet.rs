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
        NET_BUFFER_LIST,
    },
};

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
}

pub struct PacketList {
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
            unsafe {
                FwpsDereferenceNetBufferList0(self.nbl, false);
            }
        }
    }
}

pub struct Injector {
    inject_handle: HANDLE,
}

impl Injector {
    pub fn new() -> Self {
        let mut inject_handle: HANDLE = INVALID_HANDLE_VALUE;
        unsafe {
            FwpsInjectionHandleCreate0(AF_UNSPEC, 0x2, &mut inject_handle);
        }
        Self { inject_handle }
    }

    pub fn clone_layer_data(
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

    pub fn inject_packet_list_transport(&self, packet_list: PacketList) -> Result<(), String> {
        if self.inject_handle == INVALID_HANDLE_VALUE {
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
                self.inject_handle,
                0,
                packet_list.endpoint_handle,
                0,
                &mut send_params,
                AF_INET,
                packet_list.compartment_id,
                packet_list.nbl,
                free_nbl,
                (packet_list as *mut PacketList) as _,
            );
            if let Err(err) = check_ntstatus(status) {
                _ = Box::from_raw(packet_list);
                return Err(err);
            }
        }

        return Ok(());
    }

    // pub fn inject_packet_list_network(&self, mut packet_list: PacketList) -> Result<(), String> {
    //     if self.inject_handle == INVALID_HANDLE_VALUE {
    //         return Err("failed to inject packet: invalid handle value".to_string());
    //     }

    //     unsafe {
    //         if packet_list.inbound {
    //             let status = FwpsInjectNetworkReceiveAsync0(
    //                 self.inject_handle,
    //                 0,
    //                 0,
    //                 packet_list.compartment_id,
    //                 packet_list.interface_index,
    //                 packet_list.sub_interface_index,
    //                 packet_list.nbl,
    //                 free_nbl,
    //                 core::ptr::null_mut(),
    //             );
    //             check_ntstatus(status)?;
    //             packet_list.nbl = core::ptr::null_mut();
    //         } else {
    //             let status = FwpsInjectNetworkSendAsync0(
    //                 self.inject_handle,
    //                 0,
    //                 0,
    //                 packet_list.compartment_id,
    //                 packet_list.nbl,
    //                 free_nbl,
    //                 core::ptr::null_mut(),
    //             );
    //             check_ntstatus(status)?;
    //             packet_list.nbl = core::ptr::null_mut();
    //         }

    //     }
    //     return Ok(());
    // }
}

impl Drop for Injector {
    fn drop(&mut self) {
        unsafe {
            FwpsInjectionHandleDestroy0(self.inject_handle);
            self.inject_handle = INVALID_HANDLE_VALUE;
        }
    }
}

unsafe extern "C" fn free_nbl(
    context: *mut c_void,
    _net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: bool,
) {
    _ = Box::from_raw(context as *mut PacketList);
}
