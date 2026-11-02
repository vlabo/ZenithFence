//! Host mock of `wdk::worker::PeriodicWorker`: a `std::thread` instead of a
//! kernel system thread, stopped through a `Condvar` instead of a KEVENT.

use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// Set once the worker is stopped; the thread waits on it between runs.
struct StopSignal {
    stopped: Mutex<bool>,
    cond: Condvar,
}

/// A thread that calls a routine at a fixed interval until stopped. Like the
/// kernel version, the routine is never called again once `stop` has returned.
pub struct PeriodicWorker {
    signal: Arc<StopSignal>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl PeriodicWorker {
    /// Starts a thread that calls `routine` every `interval_ms` milliseconds, the
    /// first time one interval from now.
    pub fn start(interval_ms: u32, routine: fn()) -> Result<Self, String> {
        let signal = Arc::new(StopSignal {
            stopped: Mutex::new(false),
            cond: Condvar::new(),
        });
        let interval = Duration::from_millis(u64::from(interval_ms));
        let thread_signal = Arc::clone(&signal);
        let thread = std::thread::Builder::new()
            .name("zf-maintenance".into())
            .spawn(move || loop {
                let stopped = thread_signal
                    .stopped
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                // Waits out the interval, or returns early once stopped.
                let (stopped, _) = thread_signal
                    .cond
                    .wait_timeout_while(stopped, interval, |stopped| !*stopped)
                    .unwrap_or_else(|p| p.into_inner());
                if *stopped {
                    return;
                }
                drop(stopped);
                routine();
            })
            .map_err(|err| format!("failed to create worker thread: {}", err))?;

        Ok(Self {
            signal,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// Stops the thread and waits until it has ended; a routine that is running
    /// finishes first. Safe to call more than once. Never from the routine itself.
    pub fn stop(&self) {
        let Some(thread) = self.thread.lock().unwrap_or_else(|p| p.into_inner()).take() else {
            return;
        };
        *self
            .signal
            .stopped
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = true;
        self.signal.cond.notify_all();
        _ = thread.join();
    }
}

impl Drop for PeriodicWorker {
    fn drop(&mut self) {
        self.stop();
    }
}
