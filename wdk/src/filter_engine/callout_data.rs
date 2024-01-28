use crate::{
    ffi::{FwpsCompleteOperation0, FwpsPendOperation0},
    utils::check_ntstatus,
};

use super::{
    classify::ClassifyOut,
    layer::{Layer, Value, ValueType},
    metadata::FwpsIncomingMetadataValues,
    net_buffer::NetBufferList,
    packet::TransportPacketList,
    FilterEngine,
};
use alloc::string::{String, ToString};
use core::{ffi::c_void, ptr::NonNull};
use windows_sys::Win32::{
    Foundation::HANDLE,
    NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_FLAG_IS_REAUTHORIZE,
    Networking::WinSock::SCOPE_ID,
};

pub enum ClassifyDefer {
    Initial(HANDLE, Option<TransportPacketList>),
    Reauthorization(usize, Option<TransportPacketList>),
}

impl ClassifyDefer {
    pub fn complete(
        self,
        filter_engine: &mut FilterEngine,
    ) -> Result<Option<TransportPacketList>, String> {
        unsafe {
            match self {
                ClassifyDefer::Initial(context, packet_list) => {
                    FwpsCompleteOperation0(context, core::ptr::null_mut());
                    return Ok(packet_list);
                }
                ClassifyDefer::Reauthorization(callout_id, packet_list) => {
                    filter_engine.reset_callout_filter(callout_id)?;
                    return Ok(packet_list);
                }
            }
        }
    }

    pub fn add_net_buffer(&mut self, nbl: NetBufferList) {
        if let Some(packet_list) = match self {
            ClassifyDefer::Initial(_, packet_list) => packet_list,
            ClassifyDefer::Reauthorization(_, packet_list) => packet_list,
        } {
            packet_list.net_buffer_list_queue.push(nbl);
        }
    }
}

pub struct CalloutData<'a> {
    pub layer: Layer,
    pub(crate) callout_id: usize,
    pub(crate) values: &'a [Value],
    pub(crate) metadata: *const FwpsIncomingMetadataValues,
    pub(crate) classify_out: *mut ClassifyOut,
    pub(crate) layer_data: *mut c_void,
}

impl<'a> CalloutData<'a> {
    pub fn get_value_type(&self, index: usize) -> ValueType {
        return self.values[index].value_type;
    }

    pub fn get_value_u8(&'a self, index: usize) -> u8 {
        unsafe {
            return self.values[index].value.uint8;
        };
    }

    pub fn get_value_u16(&'a self, index: usize) -> u16 {
        unsafe {
            return self.values[index].value.uint16;
        };
    }

    pub fn get_value_u32(&'a self, index: usize) -> u32 {
        unsafe {
            return self.values[index].value.uint32;
        };
    }

    pub fn get_value_byte_array16(&'a self, index: usize) -> &[u8; 16] {
        unsafe {
            return self.values[index].value.byte_array16.as_ref().unwrap();
        };
    }

    pub fn get_process_id(&self) -> Option<u64> {
        unsafe { (*self.metadata).get_process_id() }
    }

    pub fn get_process_path(&self) -> Option<String> {
        unsafe {
            return (*self.metadata).get_process_path();
        }
    }

    pub fn get_transport_endpoint_handle(&self) -> Option<u64> {
        unsafe {
            return (*self.metadata).get_transport_endpoint_handle();
        }
    }

    pub fn get_remote_scope_id(&self) -> Option<SCOPE_ID> {
        unsafe {
            return (*self.metadata).get_remote_scope_id();
        }
    }

    pub fn get_control_data(&self) -> Option<NonNull<[u8]>> {
        unsafe {
            return (*self.metadata).get_control_data();
        }
    }

    pub fn get_layer_data(&self) -> *mut c_void {
        return self.layer_data;
    }

    pub fn pend_operation(
        &mut self,
        packet_list: Option<TransportPacketList>,
    ) -> Result<ClassifyDefer, String> {
        unsafe {
            let mut completion_context = 0;
            if let Some(completion_handle) = (*self.metadata).get_completion_handle() {
                let status = FwpsPendOperation0(completion_handle, &mut completion_context);
                check_ntstatus(status)?;

                return Ok(ClassifyDefer::Initial(completion_context, packet_list));
            }

            Err("callout not supported".to_string())
        }
    }

    pub fn pend_filter_rest(&mut self, packet_list: Option<TransportPacketList>) -> ClassifyDefer {
        return ClassifyDefer::Reauthorization(self.callout_id, packet_list);
    }

    pub fn action_permit(&mut self) {
        unsafe {
            (*self.classify_out).action_permit();
        }
    }

    pub fn action_continue(&mut self) {
        unsafe {
            (*self.classify_out).action_continue();
        }
    }

    pub fn action_block(&mut self) {
        unsafe {
            (*self.classify_out).action_block();
        }
    }

    pub fn block_and_absorb(&mut self) {
        unsafe {
            (*self.classify_out).action_block();
            (*self.classify_out).set_absorb();
        }
    }
    pub fn clear_write_flag(&mut self) {
        unsafe {
            (*self.classify_out).clear_write_flag();
        }
    }

    pub fn is_reauthorize(&self, flags_index: usize) -> bool {
        self.get_value_u32(flags_index) & FWP_CONDITION_FLAG_IS_REAUTHORIZE > 0
    }

    pub fn parmit_and_absorb(&mut self) {
        unsafe {
            (*self.classify_out).action_permit();
            (*self.classify_out).set_absorb();
        }
    }

    pub fn get_callout_id(&self) -> usize {
        return self.callout_id;
    }
}
