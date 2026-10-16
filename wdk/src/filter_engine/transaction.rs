use core::ops::{Deref, DerefMut};

use super::{ffi, FilterEngine};
use crate::consts::STATUS_FWP_TXN_IN_PROGRESS;
use crate::utils::{ntstatus_name, sleep_ms};
use alloc::{format, string::String};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_TXN_READ_ONLY;

/// Why beginning a filter engine transaction failed.
pub(super) enum BeginError {
    /// Another transaction is already in progress on the filter engine session. Only one can be
    /// open at a time. Nothing was changed, so the caller may simply try again later.
    InProgress,
    /// Anything else. Not worth repeating.
    Failed(String),
}

impl From<BeginError> for String {
    fn from(err: BeginError) -> Self {
        match err {
            BeginError::InProgress => format!(
                "filter-engine: failed to begin transaction: {}",
                ntstatus_name(STATUS_FWP_TXN_IN_PROGRESS)
            ),
            BeginError::Failed(message) => message,
        }
    }
}

/// Transaction guard for Filter Engine. Internally useses a lock. DO NOT USE WITH OTHER LOCKS.
pub(super) struct Transaction<'a> {
    filter_engine: &'a mut FilterEngine,
    committed: bool,
}

impl<'a> Transaction<'a> {
    fn begin(filter_engine: &'a mut FilterEngine, flags: u32) -> Result<Self, BeginError> {
        if let Err(status) = ffi::filter_engine_transaction_begin(filter_engine.handle, flags) {
            if status == STATUS_FWP_TXN_IN_PROGRESS {
                return Err(BeginError::InProgress);
            }
            return Err(BeginError::Failed(format!(
                "filter-engine: failed to begin transaction: {}",
                ntstatus_name(status)
            )));
        }

        Ok(Self {
            filter_engine,
            committed: false,
        })
    }

    /// Creates a read only guard for filter engine transaction.
    #[allow(dead_code)]
    pub(super) fn begin_read(filter_engine: &'a mut FilterEngine) -> Result<Self, BeginError> {
        return Self::begin(filter_engine, FWPM_TXN_READ_ONLY);
    }

    /// Creates a read/write guard for filter engine transaction.
    pub(super) fn begin_write(filter_engine: &'a mut FilterEngine) -> Result<Self, BeginError> {
        return Self::begin(filter_engine, 0);
    }

    /// Same as `begin_write`, but waits and tries again while another transaction is in progress.
    ///
    /// Sleeps between the attempts, so it is only usable at IRQL <= APC_LEVEL. Callers that must
    /// not block, or that want to batch the retries with other work (the driver does that for the
    /// filter resets), use `begin_write` and handle `BeginError::InProgress` themselves.
    pub(super) fn begin_write_retrying(
        filter_engine: &'a mut FilterEngine,
    ) -> Result<Self, String> {
        // The handle is read up front so the mutable borrow of the filter engine is only taken by
        // the attempt that actually succeeds.
        let handle = filter_engine.handle;
        let max_attempts = 20;
        for _ in 0..max_attempts {
            match ffi::filter_engine_transaction_begin(handle, 0) {
                Ok(()) => {
                    return Ok(Self {
                        filter_engine,
                        committed: false,
                    })
                }
                Err(status) if status == STATUS_FWP_TXN_IN_PROGRESS => {
                    // Nothing was changed by the failed attempt. Give the transaction that holds
                    // the session a chance to finish and try again.
                    if let Err(err) = sleep_ms(10) {
                        return Err(format!(
                            "filter-engine: cannot wait for the transaction in progress: {}",
                            err
                        ));
                    }
                }
                Err(status) => {
                    return Err(format!(
                        "filter-engine: failed to begin transaction: {}",
                        ntstatus_name(status)
                    ))
                }
            }
        }

        return Err(format!(
            "filter-engine: failed to begin transaction: {} after {} attempts",
            ntstatus_name(STATUS_FWP_TXN_IN_PROGRESS),
            max_attempts
        ));
    }

    /// Applying all the changes and releases the lock.
    pub(super) fn commit(&mut self) -> Result<(), String> {
        if let Err(code) = ffi::filter_engine_transaction_commit(self.filter_engine.handle) {
            return Err(format!(
                "filter-engine: failed to commit transaction: {}",
                code
            ));
        }
        self.committed = true;

        Ok(())
    }
}

impl<'a> Deref for Transaction<'a> {
    type Target = FilterEngine;

    fn deref(&self) -> &Self::Target {
        self.filter_engine
    }
}

impl<'a> DerefMut for Transaction<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.filter_engine
    }
}

impl<'a> Drop for Transaction<'a> {
    /// Releases the lock of transaction was not committed.
    fn drop(&mut self) {
        if !self.committed {
            _ = ffi::filter_engine_transaction_abort(self.filter_engine.handle);
        }
    }
}
