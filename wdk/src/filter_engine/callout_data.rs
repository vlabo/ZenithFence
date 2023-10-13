use crate::utils::check_ntstatus;

use super::{
    classify::ClassifyOut,
    connect_request::FwpsConnectRequest0,
    ffi::{self, FwpsPendOperation0},
    layer::{Layer, Value},
    metadata::FwpsIncomingMetadataValues,
    FilterEngine,
};
use alloc::string::{String, ToString};
use core::ffi::c_void;
use windows_sys::Win32::{
    Foundation::HANDLE,
    NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_FLAG_IS_REAUTHORIZE,
};

#[derive(Clone)]
pub enum ClassifyPromise {
    Initial(HANDLE),
    Reauthorization(usize),
}

impl ClassifyPromise {
    pub fn complete(&mut self, filter_engine: &FilterEngine) -> Result<(), String> {
        unsafe {
            match self {
                ClassifyPromise::Initial(context) => {
                    ffi::FwpsCompleteOperation0(*context, core::ptr::null_mut());
                    return Ok(());
                }
                ClassifyPromise::Reauthorization(callout_index) => {
                    return filter_engine.reset_callout_filter(*callout_index);
                }
            }
        }
    }
}

pub struct CalloutData<'a> {
    pub layer: Layer,
    pub(crate) callout_index: usize,
    pub(crate) values: &'a [Value],
    pub(crate) metadata: *const FwpsIncomingMetadataValues,
    pub(crate) classify_out: *mut ClassifyOut,
    pub(crate) classify_context: *mut c_void,
    pub(crate) filter_id: u64,
}

impl<'a> CalloutData<'a> {
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

    pub fn get_process_id(&self) -> Option<u64> {
        unsafe { (*self.metadata).get_process_id() }
    }

    pub fn get_process_path(&self) -> Option<String> {
        unsafe {
            return (*self.metadata).get_process_path();
        }
    }

    pub fn pend_operation(&mut self) -> Result<ClassifyPromise, String> {
        unsafe {
            let mut completion_context = 0;
            if let Some(completion_handle) = (*self.metadata).get_completeion_handle() {
                let status = FwpsPendOperation0(completion_handle, &mut completion_context);
                check_ntstatus(status)?;

                if let Some(classify_out) = self.classify_out.as_mut() {
                    classify_out.action_block();
                    classify_out.set_absorb();
                }
                return Ok(ClassifyPromise::Initial(completion_context));
            }

            Err("callout not supported".to_string())
        }
    }

    pub fn pend_classification(&mut self) -> ClassifyPromise {
        return ClassifyPromise::Reauthorization(self.callout_index);
    }

    pub fn permit(&mut self) {
        unsafe {
            (*self.classify_out).action_permit();
        }
    }

    pub fn block(&mut self) {
        unsafe {
            (*self.classify_out).action_block();
            (*self.classify_out).clear_write_flag();
        }
    }

    pub fn block_and_absorb(&mut self) {
        unsafe {
            (*self.classify_out).action_block();
            (*self.classify_out).set_absorb();
            (*self.classify_out).clear_write_flag();
        }
    }

    pub fn is_reauthorize(&self, flags_index: usize) -> bool {
        self.get_value_u32(flags_index) & FWP_CONDITION_FLAG_IS_REAUTHORIZE > 0
    }

    pub fn redirect(&mut self, remote_ip: &[u8], remote_port: u16) -> Result<(), String> {
        unsafe {
            let mut classify_handle: u64 = 0;
            let status =
                ffi::FwpsAcquireClassifyHandle0(self.classify_context, 0, &mut classify_handle);
            check_ntstatus(status)?;

            let mut layer_data: *mut FwpsConnectRequest0 = core::ptr::null_mut();

            let status = ffi::FwpsAcquireWritableLayerDataPointer0(
                classify_handle,
                self.filter_id,
                0,
                core::ptr::addr_of_mut!(layer_data) as _,
                self.classify_out,
            );

            if let Err(err) = check_ntstatus(status) {
                // TODO: use guard for releasing the handle.
                ffi::FwpsReleaseClassifyHandle0(classify_handle);
                return Err(err);
            }

            if let Some(data) = layer_data.as_mut() {
                data.set_remote(remote_ip, remote_port);
            }

            ffi::FwpsApplyModifiedLayerData0(classify_handle, layer_data as _, 0);
            ffi::FwpsReleaseClassifyHandle0(classify_handle);

            return Ok(());
        }
    }
}
