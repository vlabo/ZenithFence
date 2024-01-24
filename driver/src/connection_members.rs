use core::fmt::{Debug, Display};
use num_derive::FromPrimitive;

#[derive(Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum Verdict {
    // Undecided is the default status of new connections.
    Undecided = 0,
    Undeterminable = 1,
    Accept = 2,
    Block = 3,
    Drop = 4,
    Redirect = 5,
    RedirectTunnel = 6,
    Failed = 7,
}

impl Display for Verdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Verdict::Undecided => write!(f, "Undecided"),
            Verdict::Undeterminable => write!(f, "Undeterminable"),
            Verdict::Accept => write!(f, "Accept"),
            Verdict::Block => write!(f, "Block"),
            Verdict::Drop => write!(f, "Drop"),
            Verdict::Redirect => write!(f, "Redirect"),
            Verdict::RedirectTunnel => write!(f, "RedirectTunnel"),
            Verdict::Failed => write!(f, "Failed"),
        }
    }
}

#[derive(Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum Direction {
    Outbound = 0,
    Inbound = 1,
    NotApplicable = 0xFF,
}

impl Display for Direction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Direction::Outbound => write!(f, "Outbound"),
            Direction::Inbound => write!(f, "Inbound"),
            Direction::NotApplicable => write!(f, "NotApplicable"),
        }
    }
}

impl Debug for Direction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}
