use core::ffi::c_void;
use core::marker::PhantomData;

use super::classify::ClassifyOut;
use super::layer::{Layer, ValueType};
use super::net_buffer::NET_BUFFER_LIST;
use super::packet::TransportPacketList;
use super::FilterEngine;

/// One classify "fixed value". The real type is a tagged C union; the mock uses
/// a safe enum the harness can build directly. A callout reads it through the
/// `get_value_*` accessors below.
#[derive(Clone, Debug)]
pub enum Value {
    Empty,
    U8(u8),
    U16(u16),
    U32(u32),
    Bytes16([u8; 16]),
}

static ZERO16: [u8; 16] = [0u8; 16];

/// Host mock of `wdk::filter_engine::callout_data::ClassifyDefer`.
/// The first payload of `Initial` mirrors the real `HANDLE` (isize); the driver
/// only ever binds it as `_`.
pub enum ClassifyDefer {
    Initial(isize, Option<TransportPacketList>),
    Reauthorization(usize, Option<TransportPacketList>),
}

impl ClassifyDefer {
    pub fn complete(
        self,
        _filter_engine: &mut FilterEngine,
    ) -> Result<Option<TransportPacketList>, String> {
        match self {
            ClassifyDefer::Initial(_, packet_list) => Ok(packet_list),
            ClassifyDefer::Reauthorization(_, packet_list) => Ok(packet_list),
        }
    }
}

/// Host mock of `wdk::filter_engine::callout_data::CalloutData`.
///
/// Construct one with [`CalloutData::mock`]. `classify_out` and `layer_data`
/// are raw pointers to harness-owned storage (a `ClassifyOut` and an NBL chain
/// respectively), matching the real layout; either may be null in harnesses
/// that don't exercise that path (the accessors null-check).
pub struct CalloutData<'a> {
    pub layer: Layer,
    callout_id: usize,
    values: Vec<Value>,
    process_id: Option<u64>,
    classify_out: *mut ClassifyOut,
    layer_data: *mut NET_BUFFER_LIST,
    ip_header_size: u32,
    transport_header_size: u32,
    _marker: PhantomData<&'a ()>,
}

impl<'a> CalloutData<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn mock(
        layer: Layer,
        values: Vec<Value>,
        process_id: Option<u64>,
        classify_out: *mut ClassifyOut,
        layer_data: *mut NET_BUFFER_LIST,
        ip_header_size: u32,
        transport_header_size: u32,
    ) -> Self {
        Self {
            layer,
            callout_id: 0,
            values,
            process_id,
            classify_out,
            layer_data,
            ip_header_size,
            transport_header_size,
            _marker: PhantomData,
        }
    }

    pub fn get_value_type(&self, index: usize) -> ValueType {
        match &self.values[index] {
            Value::Empty => ValueType::FwpEmpty,
            Value::U8(_) => ValueType::FwpUint8,
            Value::U16(_) => ValueType::FwpUint16,
            Value::U32(_) => ValueType::FwpUint32,
            Value::Bytes16(_) => ValueType::FwpByteArray16Type,
        }
    }

    pub fn get_value_u8(&self, index: usize) -> u8 {
        match &self.values[index] {
            Value::U8(v) => *v,
            _ => 0,
        }
    }

    pub fn get_value_u16(&self, index: usize) -> u16 {
        match &self.values[index] {
            Value::U16(v) => *v,
            _ => 0,
        }
    }

    pub fn get_value_u32(&self, index: usize) -> u32 {
        match &self.values[index] {
            Value::U32(v) => *v,
            _ => 0,
        }
    }

    pub fn get_value_byte_array16(&self, index: usize) -> &[u8; 16] {
        match &self.values[index] {
            Value::Bytes16(a) => a,
            _ => &ZERO16,
        }
    }

    pub fn get_process_id(&self) -> Option<u64> {
        self.process_id
    }

    pub fn get_ip_header_size(&self) -> u32 {
        self.ip_header_size
    }

    pub fn get_transport_header_size(&self) -> u32 {
        self.transport_header_size
    }

    pub fn get_layer_data(&self) -> *mut c_void {
        self.layer_data as *mut c_void
    }

    pub fn pend_operation(
        &mut self,
        packet_list: Option<TransportPacketList>,
    ) -> Result<ClassifyDefer, String> {
        Ok(ClassifyDefer::Initial(0, packet_list))
    }

    pub fn pend_filter_rest(&mut self, packet_list: Option<TransportPacketList>) -> ClassifyDefer {
        ClassifyDefer::Reauthorization(self.callout_id, packet_list)
    }

    pub fn action_permit(&mut self) {
        if let Some(co) = unsafe { self.classify_out.as_mut() } {
            co.action_permit();
        }
    }

    pub fn action_continue(&mut self) {
        if let Some(co) = unsafe { self.classify_out.as_mut() } {
            co.action_continue();
        }
    }

    pub fn action_block(&mut self) {
        if let Some(co) = unsafe { self.classify_out.as_mut() } {
            co.clear_write_flag();
            co.action_block();
        }
    }

    pub fn action_none(&mut self) {
        if let Some(co) = unsafe { self.classify_out.as_mut() } {
            co.set_none();
        }
    }

    pub fn block_and_absorb(&mut self) {
        if let Some(co) = unsafe { self.classify_out.as_mut() } {
            co.clear_write_flag();
            co.action_block();
            co.set_absorb();
        }
    }

    pub fn parmit_and_absorb(&mut self) {
        if let Some(co) = unsafe { self.classify_out.as_mut() } {
            co.action_permit();
            co.set_absorb();
        }
    }

    pub fn clear_write_flag(&mut self) {
        if let Some(co) = unsafe { self.classify_out.as_mut() } {
            co.clear_write_flag();
        }
    }

    pub fn is_reauthorize(&self, flags_index: usize) -> bool {
        self.get_value_u32(flags_index) & crate::consts::FWP_CONDITION_FLAG_IS_REAUTHORIZE > 0
    }

    pub fn get_callout_id(&self) -> usize {
        self.callout_id
    }
}
