use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{ffi::c_void, mem::MaybeUninit};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Networking::WinSock::{AF_INET, AF_UNSPEC, SCOPE_ID},
    System::Kernel::UNSPECIFIED_COMPARTMENT_ID,
};

use crate::{
    ffi::{
        FwpsDereferenceNetBufferList0, FwpsInjectNetworkReceiveAsync0, FwpsInjectNetworkSendAsync0,
        FwpsInjectTransportSendAsync1, FwpsInjectionHandleCreate0, FwpsInjectionHandleDestroy0,
        FwpsQueryPacketInjectionState0, FwpsReferenceNetBufferList0, FWPS_INJECTION_TYPE_NETWORK,
        FWPS_INJECTION_TYPE_TRANSPORT, FWPS_PACKET_INJECTION_STATE, FWPS_TRANSPORT_SEND_PARAMS1,
        NET_BUFFER_LIST,
    },
    utils::check_ntstatus,
};

use super::{callout_data::CalloutData, net_buffer::NetworkAllocator};

pub struct TransportPacketList {
    nbl: *mut NET_BUFFER_LIST,
    remote_ip: [u8; 4],
    endpoint_handle: u64,
    remote_scope_id: SCOPE_ID,
    control_data: Option<Vec<u8>>,
}

pub struct NetworkPacketList {
    nbl: *mut NET_BUFFER_LIST,
    inbound: bool,
    loopback: bool,
    interface_index: u32,
    sub_interface_index: u32,
}

impl Drop for TransportPacketList {
    fn drop(&mut self) {
        if !self.nbl.is_null() {
            unsafe {
                FwpsDereferenceNetBufferList0(self.nbl, false);
            }
        }
    }
}

impl Drop for NetworkPacketList {
    fn drop(&mut self) {
        if !self.nbl.is_null() {
            NetworkAllocator::free_net_buffer(self.nbl);
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

    pub fn from_ale_callout(callout_data: &CalloutData, remote_ip: [u8; 4]) -> TransportPacketList {
        unsafe {
            FwpsReferenceNetBufferList0(callout_data.layer_data as _, true);
        }
        let mut control_data = None;
        if let Some(cd) = callout_data.get_control_data() {
            control_data = Some(cd.to_vec());
        }

        TransportPacketList {
            nbl: callout_data.layer_data as _,
            remote_ip,
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
        loopback: bool,
        interface_index: u32,
        sub_interface_index: u32,
    ) -> NetworkPacketList {
        NetworkPacketList {
            nbl,
            inbound,
            loopback,
            interface_index,
            sub_interface_index,
        }
    }

    pub fn inject_packet_list_transport(
        &self,
        packet_list: TransportPacketList,
    ) -> Result<(), String> {
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
                UNSPECIFIED_COMPARTMENT_ID,
                packet_list.nbl,
                free_packet_transport,
                (packet_list as *mut TransportPacketList) as _,
            );
            if let Err(err) = check_ntstatus(status) {
                _ = Box::from_raw(packet_list);
                return Err(err);
            }
        }

        return Ok(());
    }

    pub fn inject_packet_list_network(&self, packet_list: NetworkPacketList) -> Result<(), String> {
        if self.network_inject_handle == INVALID_HANDLE_VALUE {
            return Err("failed to inject packet: invalid handle value".to_string());
        }

        unsafe {
            if packet_list.inbound && !packet_list.loopback {
                let packet_list_boxed = Box::new(packet_list);
                let packet_list = Box::into_raw(packet_list_boxed).as_mut().unwrap();
                let status = FwpsInjectNetworkReceiveAsync0(
                    self.network_inject_handle,
                    0,
                    0,
                    UNSPECIFIED_COMPARTMENT_ID,
                    packet_list.interface_index,
                    packet_list.sub_interface_index,
                    packet_list.nbl,
                    free_packet_network,
                    (packet_list as *mut NetworkPacketList) as _,
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
                    UNSPECIFIED_COMPARTMENT_ID,
                    packet_list.nbl,
                    free_packet_network,
                    (packet_list as *mut NetworkPacketList) as _,
                );
                if let Err(err) = check_ntstatus(status) {
                    _ = Box::from_raw(packet_list);
                    return Err(err);
                }
            }
        }
        return Ok(());
    }

    pub fn was_network_packet_injected_by_self(&self, nbl: *const NET_BUFFER_LIST) -> bool {
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
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_OTHER => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTION_STATE_MAX => false,
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

unsafe extern "C" fn free_packet_transport(
    context: *mut c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: bool,
) {
    if let Some(nbl) = net_buffer_list.as_ref() {
        if let Err(err) = check_ntstatus(nbl.Status) {
            crate::err!("inject status: {}", err);
        } else {
            crate::dbg!("packet injected successfully");
        }
    }
    _ = Box::from_raw(context as *mut TransportPacketList);
}

unsafe extern "C" fn free_packet_network(
    context: *mut c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: bool,
) {
    if let Some(nbl) = net_buffer_list.as_ref() {
        if let Err(err) = check_ntstatus(nbl.Status) {
            crate::err!("inject status: {}", err);
        } else {
            crate::dbg!("packet injected successfully");
        }
    }
    _ = Box::from_raw(context as *mut NetworkPacketList);
}
