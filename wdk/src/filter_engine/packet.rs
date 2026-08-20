use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::{ffi::c_void, mem::MaybeUninit};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SCOPE_ID},
    System::Kernel::{COMPARTMENT_ID, UNSPECIFIED_COMPARTMENT_ID},
};

use crate::{
    ffi::{
        FwpsInjectMacSendAsync0, FwpsInjectNetworkReceiveAsync0, FwpsInjectNetworkSendAsync0,
        FwpsInjectTransportReceiveAsync0, FwpsInjectTransportSendAsync1,
        FwpsInjectionHandleCreate0, FwpsInjectionHandleDestroy0, FwpsQueryPacketInjectionState0,
        FWPS_INJECTION_TYPE_L2, FWPS_INJECTION_TYPE_NETWORK, FWPS_INJECTION_TYPE_TRANSPORT,
        FWPS_PACKET_INJECTION_STATE, FWPS_TRANSPORT_SEND_PARAMS1, NET_BUFFER_LIST,
    },
    utils::check_ntstatus,
};

use super::{callout_data::CalloutData, net_buffer::NetBufferList};

pub struct TransportPacketList {
    ipv6: bool,
    pub net_buffer_list_queue: NetBufferList,
    remote_ip: [u8; 16],
    endpoint_handle: u64,
    remote_scope_id: SCOPE_ID,
    control_data: Option<Box<[u8]>>,
    inbound: bool,
    interface_index: u32,
    sub_interface_index: u32,
}

/// Owns everything an asynchronous transport injection references.
///
/// `FwpsInjectTransport*Async*` returns before the packet is actually sent, and
/// the network stack keeps reading the NET_BUFFER_LIST, the control data blob
/// (`FWPS_TRANSPORT_SEND_PARAMS1.control_data`) and the remote address buffer
/// (`remote_address`) after the call returns. All three must therefore stay
/// alive until the injection completion routine (`free_transport_packet`) runs,
/// not just for the duration of the inject call. The `FWPS_TRANSPORT_SEND_PARAMS1`
/// struct itself does not need to outlive the call — WFP copies it synchronously —
/// only the buffers it points into.
struct TransportInjectContext {
    nbl: NetBufferList,
    control_data: Option<Box<[u8]>>,
    remote_ip: [u8; 16],
}

pub struct InjectInfo {
    pub ipv6: bool,
    pub inbound: bool,
    pub loopback: bool,
    pub interface_index: u32,
    pub sub_interface_index: u32,
    pub compartment_id: COMPARTMENT_ID,
}

/// Everything `FwpsInjectMacSendAsync0` needs to put a frame back where it was taken from. All
/// three values come from the MAC layer classify that absorbed it; there is no address family
/// here, the frame carries its own headers.
pub struct MacInjectInfo {
    /// Run time layer id of the layer the frame was classified at.
    pub layer_id: u16,
    pub interface_index: u32,
    pub ndis_port: u32,
}

pub struct Injector {
    transport_inject_handle: HANDLE,
    packet_inject_handle_v4: HANDLE,
    packet_inject_handle_v6: HANDLE,
    l2_inject_handle: HANDLE,
}

// TODO: Implement custom allocator for the packet buffers for reusing memory and reducing allocations. This should improve latency.
impl Injector {
    pub fn new() -> Self {
        let mut transport_inject_handle: HANDLE = INVALID_HANDLE_VALUE;
        let mut packet_inject_handle_v4: HANDLE = INVALID_HANDLE_VALUE;
        let mut packet_inject_handle_v6: HANDLE = INVALID_HANDLE_VALUE;
        let mut l2_inject_handle: HANDLE = INVALID_HANDLE_VALUE;
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
                &mut packet_inject_handle_v4,
            );

            if let Err(err) = check_ntstatus(status) {
                crate::err!("error allocating network inject handle: {}", err);
            }
            let status = FwpsInjectionHandleCreate0(
                AF_INET6,
                FWPS_INJECTION_TYPE_NETWORK,
                &mut packet_inject_handle_v6,
            );

            if let Err(err) = check_ntstatus(status) {
                crate::err!("error allocating network inject handle: {}", err);
            }
            // The MAC layers carry whole frames and no address family, so the handle is created
            // with AF_UNSPEC like the transport one.
            let status = FwpsInjectionHandleCreate0(
                AF_UNSPEC,
                FWPS_INJECTION_TYPE_L2,
                &mut l2_inject_handle,
            );

            if let Err(err) = check_ntstatus(status) {
                crate::err!("error allocating l2 inject handle: {}", err);
            }
        }
        Self {
            transport_inject_handle,
            packet_inject_handle_v4,
            packet_inject_handle_v6,
            l2_inject_handle,
        }
    }

    // TODO: pick a better name
    pub fn from_ale_callout(
        ipv6: bool,
        callout_data: &CalloutData,
        net_buffer_list: NetBufferList,
        remote_ip_slice: &[u8],
        inbound: bool,
        interface_index: u32,
        sub_interface_index: u32,
    ) -> TransportPacketList {
        // Copy the transport control data into a buffer we own. The pointer in
        // the WFP metadata is only valid for the duration of this classify
        // callout, but the packet is injected later, once user space returns a
        // verdict.
        let control_data = callout_data.get_control_data_copy();
        let mut remote_ip: [u8; 16] = [0; 16];
        if ipv6 {
            remote_ip[0..16].copy_from_slice(&remote_ip_slice);
        } else {
            remote_ip[0..4].copy_from_slice(&remote_ip_slice);
        }

        TransportPacketList {
            ipv6,
            net_buffer_list_queue: net_buffer_list,
            remote_ip,
            endpoint_handle: callout_data.get_transport_endpoint_handle().unwrap_or(0),
            remote_scope_id: callout_data
                .get_remote_scope_id()
                .unwrap_or(unsafe { MaybeUninit::zeroed().assume_init() }),
            control_data,
            inbound,
            interface_index,
            sub_interface_index,
        }
    }

    // TODO: pick a better name. This is not transport
    pub fn inject_packet_list_transport(
        &self,
        packet_list: TransportPacketList,
    ) -> Result<(), String> {
        if self.transport_inject_handle == INVALID_HANDLE_VALUE {
            return Err("failed to inject packet: invalid handle value".to_string());
        }
        unsafe {
            let address_family = if packet_list.ipv6 { AF_INET6 } else { AF_INET };
            let inbound = packet_list.inbound;
            let endpoint_handle = packet_list.endpoint_handle;
            let remote_scope_id = packet_list.remote_scope_id;
            let interface_index = packet_list.interface_index;
            let sub_interface_index = packet_list.sub_interface_index;

            // Escape the stack. The NBL, the control data blob and the remote
            // address are all read by the network stack *after* this asynchronous
            // inject call returns, so they must remain valid until the completion
            // routine (`free_transport_packet`) runs. Move them onto the heap and
            // hand ownership to WFP as the completion context.
            let context = Box::new(TransportInjectContext {
                nbl: packet_list.net_buffer_list_queue,
                control_data: packet_list.control_data,
                remote_ip: packet_list.remote_ip,
            });
            let raw_ptr = Box::into_raw(context);
            let raw_nbl = (*raw_ptr).nbl.nbl;

            // Derive the pointers from the heap-stable context, not the stack.
            let (control_data, control_data_length): (*mut c_void, u32) =
                match &(*raw_ptr).control_data {
                    Some(cd) => (cd.as_ptr() as *mut c_void, cd.len() as u32),
                    None => (core::ptr::null_mut(), 0),
                };

            // `send_params` itself may live on the stack: WFP copies the struct
            // synchronously. Only the buffers it points into must outlive the call.
            let mut send_params = FWPS_TRANSPORT_SEND_PARAMS1 {
                remote_address: &(*raw_ptr).remote_ip as _,
                remote_scope_id,
                control_data,
                control_data_length,
                header_include_header: core::ptr::null_mut(),
                header_include_header_length: 0,
            };

            // Inject
            let status = if inbound {
                FwpsInjectTransportReceiveAsync0(
                    self.transport_inject_handle,
                    0,
                    core::ptr::null_mut(),
                    0,
                    address_family,
                    UNSPECIFIED_COMPARTMENT_ID,
                    interface_index,
                    sub_interface_index,
                    raw_nbl,
                    free_transport_packet,
                    raw_ptr as _,
                )
            } else {
                FwpsInjectTransportSendAsync1(
                    self.transport_inject_handle,
                    0,
                    endpoint_handle,
                    0,
                    &mut send_params,
                    address_family,
                    UNSPECIFIED_COMPARTMENT_ID,
                    raw_nbl,
                    free_transport_packet,
                    raw_ptr as _,
                )
            };
            // Check for success
            if let Err(err) = check_ntstatus(status) {
                // Injection never started; reclaim and drop the whole context.
                _ = Box::from_raw(raw_ptr);
                return Err(err);
            }
        }

        return Ok(());
    }

    pub fn inject_net_buffer_list(
        &self,
        net_buffer_list: NetBufferList,
        inject_info: InjectInfo,
    ) -> Result<(), String> {
        if self.packet_inject_handle_v4 == INVALID_HANDLE_VALUE {
            return Err("failed to inject packet: invalid handle value".to_string());
        }
        // Escape the stack, so the data can be freed after inject is complete.
        let packet_boxed = Box::new(net_buffer_list);
        let nbl = packet_boxed.nbl;
        let packet_pointer = Box::into_raw(packet_boxed);

        let inject_handle = if inject_info.ipv6 {
            self.packet_inject_handle_v6
        } else {
            self.packet_inject_handle_v4
        };

        let status = if inject_info.inbound && !inject_info.loopback {
            // Inject inbound.
            unsafe {
                FwpsInjectNetworkReceiveAsync0(
                    inject_handle,
                    0,
                    0,
                    inject_info.compartment_id,
                    inject_info.interface_index,
                    inject_info.sub_interface_index,
                    nbl,
                    free_packet,
                    (packet_pointer as *mut NetBufferList) as _,
                )
            }
        } else {
            // Inject outbound.
            unsafe {
                FwpsInjectNetworkSendAsync0(
                    inject_handle,
                    0,
                    0,
                    inject_info.compartment_id,
                    nbl,
                    free_packet,
                    (packet_pointer as *mut NetBufferList) as _,
                )
            }
        };

        // Check for error.
        if let Err(err) = check_ntstatus(status) {
            unsafe {
                // Get back ownership for data.
                _ = Box::from_raw(packet_pointer);
            }
            return Err(err);
        }

        return Ok(());
    }

    /// Re-sends a frame that a MAC layer callout absorbed. The net buffer list must still start
    /// at the MAC header, exactly as it was received, because nothing below re-adds it.
    pub fn inject_mac_send(
        &self,
        net_buffer_list: NetBufferList,
        inject_info: MacInjectInfo,
    ) -> Result<(), String> {
        if self.l2_inject_handle == INVALID_HANDLE_VALUE || self.l2_inject_handle == 0 {
            return Err("failed to inject frame: invalid l2 handle".to_string());
        }
        // Escape the stack, so the data can be freed after inject is complete.
        let packet_boxed = Box::new(net_buffer_list);
        let nbl = packet_boxed.nbl;
        let packet_pointer = Box::into_raw(packet_boxed);

        let status = unsafe {
            FwpsInjectMacSendAsync0(
                self.l2_inject_handle,
                0,
                0,
                inject_info.layer_id,
                inject_info.interface_index,
                inject_info.ndis_port,
                nbl,
                free_packet,
                (packet_pointer as *mut NetBufferList) as _,
            )
        };

        if let Err(err) = check_ntstatus(status) {
            unsafe {
                // Get back ownership for data.
                _ = Box::from_raw(packet_pointer);
            }
            return Err(err);
        }

        return Ok(());
    }

    /// True for frames this driver injected at a MAC layer. Without it every reinjected frame
    /// would be classified again and absorbed again, forever.
    pub fn was_mac_packet_injected_by_self(&self, nbl: *const NET_BUFFER_LIST) -> bool {
        if self.l2_inject_handle == INVALID_HANDLE_VALUE || self.l2_inject_handle == 0 {
            return false;
        }

        unsafe {
            let state =
                FwpsQueryPacketInjectionState0(self.l2_inject_handle, nbl, core::ptr::null_mut());

            match state {
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_NOT_INJECTED => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_OTHER => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTION_STATE_MAX => false,
            }
        }
    }

    pub fn was_network_packet_injected_by_self(
        &self,
        nbl: *const NET_BUFFER_LIST,
        ipv6: bool,
    ) -> bool {
        let inject_handle = if ipv6 {
            self.packet_inject_handle_v6
        } else {
            self.packet_inject_handle_v4
        };
        if inject_handle == INVALID_HANDLE_VALUE || inject_handle == 0 {
            return false;
        }

        unsafe {
            let state = FwpsQueryPacketInjectionState0(inject_handle, nbl, core::ptr::null_mut());

            match state {
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_NOT_INJECTED => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTED_BY_OTHER => false,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF => true,
                FWPS_PACKET_INJECTION_STATE::FWPS_PACKET_INJECTION_STATE_MAX => false,
            }
        }
    }

    pub fn was_network_packet_injected_by_self_ale(&self, nbl: *const NET_BUFFER_LIST) -> bool {
        unsafe {
            let state = FwpsQueryPacketInjectionState0(
                self.transport_inject_handle,
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
            if self.packet_inject_handle_v4 != INVALID_HANDLE_VALUE
                && self.packet_inject_handle_v4 != 0
            {
                FwpsInjectionHandleDestroy0(self.packet_inject_handle_v4);
                self.packet_inject_handle_v4 = INVALID_HANDLE_VALUE;
            }
            if self.packet_inject_handle_v6 != INVALID_HANDLE_VALUE
                && self.packet_inject_handle_v6 != 0
            {
                FwpsInjectionHandleDestroy0(self.packet_inject_handle_v6);
                self.packet_inject_handle_v6 = INVALID_HANDLE_VALUE;
            }
            if self.l2_inject_handle != INVALID_HANDLE_VALUE && self.l2_inject_handle != 0 {
                FwpsInjectionHandleDestroy0(self.l2_inject_handle);
                self.l2_inject_handle = INVALID_HANDLE_VALUE;
            }
        }
    }
}

unsafe extern "C" fn free_packet(
    context: *mut c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: bool,
) {
    if let Some(nbl) = net_buffer_list.as_ref() {
        if let Err(err) = check_ntstatus(nbl.Status) {
            crate::err!("inject status: {}", err);
        }
    }
    _ = Box::from_raw(context as *mut NetBufferList);
}

// Completion routine for transport injections. Reclaims the whole
// `TransportInjectContext` — dropping the NBL together with the control data
// blob and the remote address buffer that the send referenced asynchronously.
unsafe extern "C" fn free_transport_packet(
    context: *mut c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    _dispatch_level: bool,
) {
    if let Some(nbl) = net_buffer_list.as_ref() {
        if let Err(err) = check_ntstatus(nbl.Status) {
            crate::err!("inject status: {}", err);
        }
    }
    _ = Box::from_raw(context as *mut TransportInjectContext);
}
