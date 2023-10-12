use super::{ffi, FilterEngine};
use alloc::{format, string::String};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_TXN_READ_ONLY;

/// Transaction guard for Filter Engine. Internaly useses a lock. DO NOT USE WITH OTHER LOCKS.
pub(super) struct Transaction<'a> {
    filter_engine: &'a FilterEngine,
    commited: bool,
}

impl<'a> Transaction<'a> {
    fn begin(filter_engine: &'a FilterEngine, flags: u32) -> Result<Self, String> {
        if let Err(code) =
            ffi::filter_engine_transaction_begin(filter_engine.filter_engine_handle, flags)
        {
            return Err(format!(
                "filter-engine: failed to begin transaction: {}",
                code
            ));
        }

        Ok(Self {
            filter_engine,
            commited: false,
        })
    }

    /// Creates a read only guard for filter engine transaction.
    #[allow(dead_code)]
    pub(super) fn begin_read(filter_engine: &'a FilterEngine) -> Result<Self, String> {
        return Self::begin(filter_engine, FWPM_TXN_READ_ONLY);
    }

    /// Creates a read/write guard for filter engine transaction.
    pub(super) fn begin_write(filter_engine: &'a FilterEngine) -> Result<Self, String> {
        return Self::begin(filter_engine, 0);
    }

    /// Appling all the changes and releases the lock.
    pub(super) fn commit(&mut self) -> Result<(), String> {
        if let Err(code) =
            ffi::filter_engine_transaction_commit(self.filter_engine.filter_engine_handle)
        {
            return Err(format!(
                "filter-engine: failed to commit transaction: {}",
                code
            ));
        }
        self.commited = true;

        Ok(())
    }
}

impl<'a> Drop for Transaction<'a> {
    /// Releases the lock of transaction was not commited.
    fn drop(&mut self) {
        if !self.commited {
            _ = ffi::filter_engine_transaction_abort(self.filter_engine.filter_engine_handle);
        }
    }
}
