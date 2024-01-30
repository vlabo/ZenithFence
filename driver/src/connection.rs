use alloc::boxed::Box;
use core::fmt::{Debug, Display};
use num_derive::FromPrimitive;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};
use wdk::filter_engine::callout_data::ClassifyDefer;

use crate::connection_cache::Key;

pub static PM_DNS_PORT: u16 = 53;
pub static PM_SPN_PORT: u16 = 717;

#[derive(Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum Verdict {
    // Undecided is the default status of new connections.
    Undecided = 0,
    Undeterminable = 1,
    Accept = 2,
    Block = 3,
    Drop = 4,
    RedirectNameServer = 5,
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
            Verdict::RedirectNameServer => write!(f, "Redirect"),
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
}

impl Display for Direction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Direction::Outbound => write!(f, "Outbound"),
            Direction::Inbound => write!(f, "Inbound"),
        }
    }
}

impl Debug for Direction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

// #[derive(Clone)]
// pub enum ConnectionAction {
//     Verdict(Verdict),
//     RedirectIP {
//         redirect_address: IpAddress,
//         redirect_port: u16,
//     },
// }

// impl Display for ConnectionAction {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         match self {
//             ConnectionAction::Verdict(verdict) => write!(f, "{}", verdict),
//             ConnectionAction::RedirectIP {
//                 redirect_address,
//                 redirect_port,
//             } => write!(f, "Redirect: {}:{}", redirect_address, redirect_port),
//         }
//     }
// }

pub struct ConnectionV4 {
    pub(crate) protocol: IpProtocol,
    pub(crate) local_address: Ipv4Address,
    pub(crate) local_port: u16,
    pub(crate) remote_address: Ipv4Address,
    pub(crate) remote_port: u16,
    pub(crate) verdict: Verdict,
    // Less frequently used data
    pub(crate) extra: Box<ConnectionExtra>,
}

pub struct ConnectionV6 {
    pub(crate) protocol: IpProtocol,
    pub(crate) local_address: Ipv6Address,
    pub(crate) local_port: u16,
    pub(crate) remote_address: Ipv6Address,
    pub(crate) remote_port: u16,
    pub(crate) verdict: Verdict,
    // Less frequently used data
    pub(crate) extra: Box<ConnectionExtra>,
}

pub struct ConnectionExtra {
    pub(crate) endpoint_handle: u64,
    pub(crate) direction: Direction,
    pub(crate) packet_queue: Option<ClassifyDefer>,
    pub(crate) callout_id: usize,
}

impl ConnectionV4 {
    pub fn remote_equals(&self, key: &Key) -> bool {
        if self.remote_port != key.remote_port {
            return false;
        }
        if let IpAddress::Ipv4(remote_address) = &key.remote_address {
            return self.remote_address.eq(remote_address);
        }
        return false;
    }
    pub fn get_key(&self) -> Key {
        Key {
            protocol: self.protocol,
            local_address: IpAddress::Ipv4(self.local_address),
            local_port: self.local_port,
            remote_address: IpAddress::Ipv4(self.remote_address),
            remote_port: self.remote_port,
        }
    }

    pub fn redirect_equals(&self, key: &Key) -> bool {
        match self.verdict {
            Verdict::RedirectNameServer => {
                if key.remote_port != PM_DNS_PORT {
                    return false;
                }

                match key.remote_address {
                    IpAddress::Ipv4(a) => a.is_loopback(),
                    IpAddress::Ipv6(_) => false,
                }
            }
            Verdict::RedirectTunnel => {
                if key.remote_port != PM_SPN_PORT {
                    return false;
                }
                key.local_address.eq(&key.remote_address)
            }
            _ => false,
        }
    }
}

impl ConnectionV6 {
    pub fn remote_equals(&self, key: &Key) -> bool {
        if self.remote_port != key.remote_port {
            return false;
        }
        if let IpAddress::Ipv6(remote_address) = &key.remote_address {
            return self.remote_address.eq(remote_address);
        }
        return false;
    }
    pub fn get_key(&self) -> Key {
        Key {
            protocol: self.protocol,
            local_address: IpAddress::Ipv6(self.local_address),
            local_port: self.local_port,
            remote_address: IpAddress::Ipv6(self.remote_address),
            remote_port: self.remote_port,
        }
    }

    pub fn redirect_equals(&self, key: &Key) -> bool {
        match self.verdict {
            Verdict::RedirectNameServer => {
                if key.remote_port != PM_DNS_PORT {
                    return false;
                }

                match key.remote_address {
                    IpAddress::Ipv4(_) => false,
                    IpAddress::Ipv6(a) => a.is_loopback(),
                }
            }
            Verdict::RedirectTunnel => {
                if key.remote_port != PM_SPN_PORT {
                    return false;
                }
                key.local_address.eq(&key.remote_address)
            }
            _ => false,
        }
    }
}
