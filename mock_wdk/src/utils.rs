use core::sync::atomic::{AtomicU64, Ordering};

// When non-zero, overrides the host clock. Lets state-machine/eviction tests
// drive `get_system_timestamp_ms` deterministically. 0 means "use real clock".
static MOCK_TIME_MS: AtomicU64 = AtomicU64::new(0);

/// Test helper: pin the mock clock to a fixed millisecond value.
/// Pass 0 to fall back to the real host clock.
pub fn set_mock_time_ms(value: u64) {
    MOCK_TIME_MS.store(value, Ordering::SeqCst);
}

/// Test helper: advance the pinned mock clock by `delta` ms. Only meaningful
/// after `set_mock_time_ms` has pinned the clock to a non-zero value.
pub fn advance_mock_time_ms(delta: u64) {
    MOCK_TIME_MS.fetch_add(delta, Ordering::SeqCst);
}

pub fn get_system_timestamp_ms() -> u64 {
    let pinned = MOCK_TIME_MS.load(Ordering::SeqCst);
    if pinned != 0 {
        return pinned;
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn get_startup_time_ns() -> u64 {
    0
}
