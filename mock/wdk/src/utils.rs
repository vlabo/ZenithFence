use core::sync::atomic::{AtomicU64, Ordering};

// When non-zero, overrides the host clock. Lets state-machine/eviction tests
// drive `get_monotonic_ms` deterministically. 0 means "use real clock".
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

/// Milliseconds since "boot", like the kernel's interrupt time. Monotonic: the
/// host clock is `Instant`, counted from the first call in the process (the
/// mock's boot), unless a test pinned it with `set_mock_time_ms`.
pub fn get_monotonic_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static BOOT: OnceLock<Instant> = OnceLock::new();

    let pinned = MOCK_TIME_MS.load(Ordering::SeqCst);
    if pinned != 0 {
        return pinned;
    }
    BOOT.get_or_init(Instant::now).elapsed().as_millis() as u64
}

pub fn get_startup_time_ns() -> u64 {
    0
}

/// Mock of `wdk::utils::sleep_ms`: the kernel version waits non-alertably and
/// fails above APC_LEVEL. The host has no IRQL, so this just sleeps the thread.
pub fn sleep_ms(milliseconds: u32) -> Result<(), String> {
    std::thread::sleep(std::time::Duration::from_millis(u64::from(milliseconds)));
    Ok(())
}
