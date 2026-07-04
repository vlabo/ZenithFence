//! Live DNS resolution for the high-level `dns` scenario op.
//!
//! Unlike the rest of the harness -- which fabricates packets so a run stays
//! offline and reproducible -- this module performs a REAL DNS query against the
//! machine's default resolver (or an explicit one) and hands back the actual
//! query and response datagrams that crossed the socket. The `dns` op feeds those
//! real bytes to the driver's callouts, so a domain-aware policy sees genuine DNS
//! traffic. Touching the network makes `dns` records non-deterministic and
//! dependent on connectivity; a failed lookup is reported, never silently faked.
//!
//! The OS default resolver is read via `GetNetworkParams` (iphlpapi) -- raw FFI in
//! the same spirit as the named-pipe server, pulling in no `windows-sys`.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

/// A completed lookup: the server actually queried, the first address of the
/// requested family (if the reply carried one), and the raw query/response
/// datagrams exactly as they went over the wire.
pub struct Resolution {
    pub resolver: IpAddr,
    pub resolved: Option<IpAddr>,
    pub query: Vec<u8>,
    pub response: Vec<u8>,
}

/// Per-attempt timeout waiting for the resolver to answer.
const RECV_TIMEOUT: Duration = Duration::from_secs(2);
/// How many times to (re)send the query before giving up.
const ATTEMPTS: usize = 2;

/// Resolve `domain` for real. `want_v6` selects the record type (AAAA vs A), and
/// hence the family of `resolved`; the query itself travels to `resolver` (the
/// explicit override, else the OS default) over whatever family that server is.
/// Returns the wire bytes on success, or a human-readable reason on failure.
pub fn resolve(
    domain: &str,
    want_v6: bool,
    resolver: Option<IpAddr>,
) -> Result<Resolution, String> {
    if domain.is_empty() {
        return Err("`domain` must not be empty".into());
    }
    let resolver = match resolver {
        Some(ip) => ip,
        None => os_default_resolver().ok_or_else(|| {
            "no OS default DNS server found; set `resolver` to query one explicitly".to_string()
        })?,
    };

    let query = crate::scenarios::dns_query_for(query_id(domain), domain, want_v6);

    let bind = if resolver.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(bind).map_err(|e| format!("bind UDP socket: {e}"))?;
    socket
        .connect(SocketAddr::new(resolver, 53))
        .map_err(|e| format!("connect to resolver {resolver}:53: {e}"))?;
    socket
        .set_read_timeout(Some(RECV_TIMEOUT))
        .map_err(|e| format!("set socket timeout: {e}"))?;

    let mut buf = [0u8; 1500];
    let mut last = format!("resolver {resolver} did not answer");
    for _ in 0..ATTEMPTS {
        socket
            .send(&query)
            .map_err(|e| format!("send query to {resolver}: {e}"))?;
        match socket.recv(&mut buf) {
            // A matching reply echoes our transaction id in the first two bytes.
            Ok(n) if n >= 12 && buf[..2] == query[..2] => {
                let response = buf[..n].to_vec();
                let resolved = crate::scenarios::dns_answer_ip(&response, want_v6)
                    .and_then(|bytes| ip_from_bytes(&bytes));
                return Ok(Resolution {
                    resolver,
                    resolved,
                    query,
                    response,
                });
            }
            Ok(_) => last = format!("resolver {resolver} sent an unexpected reply"),
            Err(e) => last = format!("no reply from {resolver}: {e}"),
        }
    }
    Err(last)
}

/// Parse a 4- or 16-byte address into an [`IpAddr`]; `None` for any other width.
pub fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

/// A DNS transaction id derived from the name (FNV-1a), so a query is stable for
/// a given domain without needing a random source.
fn query_id(domain: &str) -> u16 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in domain.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h ^ (h >> 32)) as u16
}

// ---- OS default resolver (Windows, GetNetworkParams) ---------------------------

// FIXED_INFO / IP_ADDR_STRING as laid out by iptypes.h. `#[repr(C)]` reproduces
// the C padding, so reading `dns_server_list` lands on the bytes the API wrote.
// The server addresses arrive as NUL-terminated ASCII (e.g. "192.168.1.1").

#[repr(C)]
struct IpAddrString {
    next: *mut IpAddrString,
    ip_address: [u8; 16], // IP_ADDRESS_STRING.String ("255.255.255.255\0")
    ip_mask: [u8; 16],
    context: u32,
}

#[repr(C)]
struct FixedInfo {
    host_name: [u8; 132],   // MAX_HOSTNAME_LEN + 4
    domain_name: [u8; 132], // MAX_DOMAIN_NAME_LEN + 4
    current_dns_server: *mut IpAddrString,
    dns_server_list: IpAddrString,
    node_type: u32,
    scope_id: [u8; 260], // MAX_SCOPE_ID_LEN + 4
    enable_routing: u32,
    enable_proxy: u32,
    enable_dns: u32,
}

#[link(name = "iphlpapi")]
extern "system" {
    fn GetNetworkParams(fixed_info: *mut FixedInfo, out_buf_len: *mut u32) -> u32;
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// The machine's primary configured DNS server, or `None` if none can be read.
/// Walks `DnsServerList`, skipping any unspecified (0.0.0.0) placeholder entry.
fn os_default_resolver() -> Option<IpAddr> {
    unsafe {
        // First call sizes the buffer (extra servers chain inside it).
        let mut len: u32 = 0;
        let ret = GetNetworkParams(std::ptr::null_mut(), &mut len);
        if ret != ERROR_BUFFER_OVERFLOW && ret != ERROR_SUCCESS {
            return None;
        }
        let needed = len.max(std::mem::size_of::<FixedInfo>() as u32);
        // Over-align to 8 (FIXED_INFO holds pointers) by backing it with u64s.
        let mut backing = vec![0u64; (needed as usize + 7) / 8];
        let info = backing.as_mut_ptr() as *mut FixedInfo;
        len = needed;
        if GetNetworkParams(info, &mut len) != ERROR_SUCCESS {
            return None;
        }
        // The list nodes point into `backing`, which outlives this walk.
        let mut node: *const IpAddrString = &(*info).dns_server_list;
        while !node.is_null() {
            if let Some(ip) = parse_ascii_ip(&(*node).ip_address) {
                if !ip.is_unspecified() {
                    return Some(ip);
                }
            }
            node = (*node).next;
        }
        None
    }
}

/// Parse a NUL-terminated ASCII address string (as `GetNetworkParams` fills in).
fn parse_ascii_ip(bytes: &[u8]) -> Option<IpAddr> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).ok()?.parse().ok()
}
