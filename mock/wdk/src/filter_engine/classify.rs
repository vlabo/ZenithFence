// Host mock of `wdk::filter_engine::classify::ClassifyOut`.
// Mirrors the real action/flags semantics so a harness can assert the verdict
// a callout produced. `FWPS_CLASSIFY_OUT_FLAG_ABSORB` is inlined (no windows-sys).
#![allow(dead_code)]

const FWP_ACTION_FLAG_TERMINATING: u32 = 0x00001000;
const FWP_ACTION_FLAG_NON_TERMINATING: u32 = 0x00002000;
const FWP_ACTION_FLAG_CALLOUT: u32 = 0x00004000;

pub const FWP_ACTION_BLOCK: u32 = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;
pub const FWP_ACTION_PERMIT: u32 = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;
pub const FWP_ACTION_CONTINUE: u32 = 0x00000006 | FWP_ACTION_FLAG_NON_TERMINATING;
pub const FWP_ACTION_NONE: u32 = 0x00000007;

const FWPS_RIGHT_ACTION_WRITE: u32 = 0x00000001;
const FWPS_CLASSIFY_OUT_FLAG_ABSORB: u32 = 0x00000001;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClassifyOut {
    action_type: u32,
    _out_context: u64,
    _filter_id: u64,
    rights: u32,
    flags: u32,
    reserved: u32,
}

impl Default for ClassifyOut {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassifyOut {
    /// Construct a fresh `ClassifyOut` as the kernel would hand one to a
    /// callout: action unset, write right granted.
    pub fn new() -> Self {
        Self {
            action_type: 0,
            _out_context: 0,
            _filter_id: 0,
            rights: FWPS_RIGHT_ACTION_WRITE,
            flags: 0,
            reserved: 0,
        }
    }

    pub fn can_set_action(&self) -> bool {
        self.rights & FWPS_RIGHT_ACTION_WRITE > 0
    }

    pub fn action_block(&mut self) {
        self.action_type = FWP_ACTION_BLOCK;
    }

    pub fn action_permit(&mut self) {
        self.action_type = FWP_ACTION_PERMIT;
    }

    pub fn action_continue(&mut self) {
        self.action_type = FWP_ACTION_CONTINUE;
    }

    pub fn set_none(&mut self) {
        self.action_type = FWP_ACTION_NONE;
    }

    pub fn set_absorb(&mut self) {
        self.flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    }

    pub fn clear_write_flag(&mut self) {
        self.rights &= !FWPS_RIGHT_ACTION_WRITE;
    }

    // ---- Test accessors (not present on the real type) ----

    /// The action the callout set (0 if none).
    pub fn action(&self) -> u32 {
        self.action_type
    }

    /// The current flags word (e.g. ABSORB).
    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn is_absorb(&self) -> bool {
        self.flags & FWPS_CLASSIFY_OUT_FLAG_ABSORB > 0
    }
}
