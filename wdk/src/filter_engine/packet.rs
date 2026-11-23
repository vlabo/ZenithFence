use alloc::string::{String, ToString};
use core::{ffi::c_void, mem::MaybeUninit};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SCOPE_ID},
    System::Kernel::{COMPARTMENT_ID, UNSPECIFIED_COMPARTMENT_ID},
};

use crate::{
    ffi::{
        FwpsInjectNetworkReceiveAsync0, FwpsInjectNetworkSendAsync0,
        FwpsInjectTransportReceiveAsync0, FwpsInjectTransportSendAsync1,
        FwpsInjectionHandleCreate0, FwpsInjectionHandleDestroy0, FwpsQueryPacketInjectionState0,
        FWPS_INJECTION_TYPE_NETWORK, FWPS_INJECTION_TYPE_TRANSPORT, FWPS_PACKET_INJECTION_STATE,
        FWPS_TRANSPORT_SEND_PARAMS1, NET_BUFFER_LIST,
    },
    utils::check_ntstatus,
};

use super::{
    callout_data::CalloutData,
    net_buffer::{NetBuffer, NetBufferList, NetworkAllocator, PACKET_BUFFER_ALIGN},
};

pub struct TransportPacketList {
    ipv6: bool,
    /// The packet copy. Its prefix holds a `TransportPrefix` and the control data.
    pub net_buffer_list_queue: NetBufferList,
    endpoint_handle: u64,
    remote_scope_id: SCOPE_ID,
    inbound: bool,
    interface_index: u32,
    sub_interface_index: u32,
}

/// What a transport injection reads besides the packet, kept in the prefix of the packet copy
/// (`NetBufferList::prefix_mut`), where `control_data_len` bytes of control data follow it.
///
/// `FwpsInjectTransport*Async*` returns before the packet is actually sent, and
/// the network stack keeps reading the NET_BUFFER_LIST, the control data blob
/// (`FWPS_TRANSPORT_SEND_PARAMS1.control_data`) and the remote address buffer
/// (`remote_address`) after the call returns. All three must therefore stay
/// alive until the injection completion routine (`free_transport_packet`) runs,
/// not just for the duration of the inject call. In the packet copy's own allocation they live
/// exactly that long, and nothing else is allocated for them. The `FWPS_TRANSPORT_SEND_PARAMS1`
/// struct itself does not need to outlive the call — WFP copies it synchronously —
/// only the buffers it points into.
#[repr(C, align(16))]
struct TransportPrefix {
    remote_ip: [u8; 16],
    control_data_len: u32,
}

impl TransportPrefix {
    /// The prefix that holds a `TransportPrefix` and `control_data_len` bytes of control data.
    /// Both sizes are multiples of `PACKET_BUFFER_ALIGN`, so the control data is aligned.
    fn prefix_len(control_data_len: usize) -> usize {
        core::mem::size_of::<TransportPrefix>()
            + control_data_len.next_multiple_of(PACKET_BUFFER_ALIGN)
    }
}

pub struct InjectInfo {
    pub ipv6: bool,
    pub inbound: bool,
    pub loopback: bool,
    pub interface_index: u32,
    pub sub_interface_index: u32,
    pub compartment_id: COMPARTMENT_ID,
}

pub struct Injector {
    transport_inject_handle: HANDLE,
    packet_inject_handle_v4: HANDLE,
    packet_inject_handle_v6: HANDLE,
}

// TODO: Implement custom allocator for the packet buffers for reusing memory and reducing allocations. This should improve latency.
impl Injector {
    pub fn new() -> Self {
        let mut transport_inject_handle: HANDLE = INVALID_HANDLE_VALUE;
        let mut packet_inject_handle_v4: HANDLE = INVALID_HANDLE_VALUE;
        let mut packet_inject_handle_v6: HANDLE = INVALID_HANDLE_VALUE;
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
        }
        Self {
            transport_inject_handle,
            packet_inject_handle_v4,
            packet_inject_handle_v6,
        }
    }

    // TODO: pick a better name
    /// Copies `net_buffer` for a later transport injection, together with the remote address and
    /// the control data, all in one allocation.
    pub fn from_ale_callout(
        ipv6: bool,
        callout_data: &CalloutData,
        net_buffer: &NetBuffer,
        net_allocator: &NetworkAllocator,
        remote_ip_slice: &[u8],
        inbound: bool,
        interface_index: u32,
        sub_interface_index: u32,
    ) -> Result<TransportPacketList, String> {
        // Copy the transport control data into the packet copy. The pointer in
        // the WFP metadata is only valid for the duration of this classify
        // callout, but the packet is injected later, once user space returns a
        // verdict.
        let control_data: &[u8] = match callout_data.get_control_data() {
            Some(data) => unsafe { data.as_ref() },
            None => &[],
        };
        let mut remote_ip: [u8; 16] = [0; 16];
        if ipv6 {
            remote_ip[0..16].copy_from_slice(&remote_ip_slice);
        } else {
            remote_ip[0..4].copy_from_slice(&remote_ip_slice);
        }

        let mut net_buffer_list = net_buffer.clone_as_nbl_with_prefix(
            net_allocator,
            TransportPrefix::prefix_len(control_data.len()),
        )?;
        let Some(prefix) = net_buffer_list.prefix_mut() else {
            return Err("packet copy has no prefix".to_string());
        };
        let (header, control) = prefix.split_at_mut(core::mem::size_of::<TransportPrefix>());
        // The prefix starts the allocation, which is aligned for `TransportPrefix`.
        unsafe {
            (header.as_mut_ptr() as *mut TransportPrefix).write(TransportPrefix {
                remote_ip,
                control_data_len: control_data.len() as u32,
            })
        };
        control[..control_data.len()].copy_from_slice(control_data);

        Ok(TransportPacketList {
            ipv6,
            net_buffer_list_queue: net_buffer_list,
            endpoint_handle: callout_data.get_transport_endpoint_handle().unwrap_or(0),
            remote_scope_id: callout_data
                .get_remote_scope_id()
                .unwrap_or(unsafe { MaybeUninit::zeroed().assume_init() }),
            inbound,
            interface_index,
            sub_interface_index,
        })
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

            // The NBL, the control data blob and the remote address are all read by
            // the network stack *after* this asynchronous inject call returns, so they
            // must remain valid until the completion routine (`free_transport_packet`)
            // runs. All three are in the packet copy, which is handed over to the
            // injection; the start of its allocation is the completion context.
            let prefix_len = packet_list.net_buffer_list_queue.prefix_len();
            let (raw_nbl, context) = packet_list.net_buffer_list_queue.into_injected();
            if context.is_null() || prefix_len < core::mem::size_of::<TransportPrefix>() {
                // Not a copy made by `from_ale_callout`: there is nothing to inject it with.
                _ = NetBufferList::from_injected(raw_nbl, context, prefix_len);
                return Err("failed to inject packet: no transport prefix".to_string());
            }

            // Derive the pointers from the packet copy, not the stack.
            let prefix = context as *const TransportPrefix;
            let control_data_length = (*prefix).control_data_len;
            let control_data = if control_data_length == 0 {
                core::ptr::null_mut()
            } else {
                (context as *mut u8).add(core::mem::size_of::<TransportPrefix>()) as *mut c_void
            };

            // `send_params` itself may live on the stack: WFP copies the struct
            // synchronously. Only the buffers it points into must outlive the call.
            let mut send_params = FWPS_TRANSPORT_SEND_PARAMS1 {
                remote_address: (*prefix).remote_ip.as_ptr(),
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
                    context,
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
                    context,
                )
            };
            // Check for success
            if let Err(err) = check_ntstatus(status) {
                // Injection never started; take the packet copy back and free it.
                _ = NetBufferList::from_injected(raw_nbl, context, prefix_len);
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
        let inject_handle = if inject_info.ipv6 {
            self.packet_inject_handle_v6
        } else {
            self.packet_inject_handle_v4
        };
        // Check the handle the packet goes through, not always the v4 one.
        if inject_handle == INVALID_HANDLE_VALUE {
            return Err("failed to inject packet: invalid handle value".to_string());
        }
        // The list is read after this returns, until `free_packet` runs. Hand it over to the
        // injection; the packet copy itself is the completion context, so nothing is allocated.
        let (nbl, context) = net_buffer_list.into_injected();

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
                    context,
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
                    context,
                )
            }
        };

        // Check for error.
        if let Err(err) = check_ntstatus(status) {
            // The injection never started: take the list back and free it.
            _ = unsafe { NetBufferList::from_injected(nbl, context, 0) };
            return Err(err);
        }

        return Ok(());
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
        }
    }
}

// Completion routine for network injections. `net_buffer_list` is the injected list and `context`
// the packet copy (`NetBufferList::into_injected`); freeing the list frees both.
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
    _ = NetBufferList::from_injected(net_buffer_list, context, 0);
}

// Completion routine for transport injections. `context` is the packet copy with its
// `TransportPrefix` (`inject_packet_list_transport` only injects those); freeing the list frees
// the copy, and with it the control data blob and the remote address the send referenced
// asynchronously.
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
    let prefix = context as *const TransportPrefix;
    let prefix_len = TransportPrefix::prefix_len((*prefix).control_data_len as usize);
    _ = NetBufferList::from_injected(net_buffer_list, context, prefix_len);
}
