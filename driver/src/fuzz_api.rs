//! Public test/fuzz surface for the `driver` crate.
//!
//! Compiled only under the `mock` feature, so it is never part of the
//! production driver's public API. It re-exports the packet-handling functions
//! (some of which are `pub(crate)`) and provides small constructors that build
//! mock inputs, so external fuzz targets (in the `fuzz/` crate) can drive the
//! driver without knowing the internal module layout.
#![allow(missing_docs)]

use alloc::string::String;
use alloc::vec::Vec;
use smoltcp::wire::{IpAddress, IpProtocol};

pub use crate::connection::{Direction, Key, Verdict};
pub use crate::device::{Device, Packet};
pub use crate::entry::{clear_device, get_device, set_device};
pub use crate::packet_util::{get_key_from_nbl_v4, get_key_from_nbl_v6, recalc_header_checksums};

// Re-export the mock NBL type so fuzz targets can construct packet buffers.
pub use wdk::driver::Driver;
pub use wdk::filter_engine::net_buffer::{NetBufferList, NET_BUFFER_LIST};

/// Fuzz `get_ports` directly on an arbitrary transport-header slice.
pub fn fuzz_get_ports(packet: &[u8], protocol: IpProtocol) -> (u16, u16) {
    crate::packet_util::get_ports(packet, protocol)
}

/// Fuzz the outbound redirect path on an arbitrary packet buffer (in place).
pub fn fuzz_redirect_outbound(
    packet: &mut [u8],
    remote_address: IpAddress,
    remote_port: u16,
    unify: bool,
) {
    crate::packet_util::redirect_outbound_packet(packet, remote_address, remote_port, unify);
}

/// Fuzz the inbound redirect path on an arbitrary packet buffer (in place).
pub fn fuzz_redirect_inbound(
    packet: &mut [u8],
    local_address: IpAddress,
    original_remote_address: IpAddress,
    original_remote_port: u16,
) {
    crate::packet_util::redirect_inbound_packet(
        packet,
        local_address,
        original_remote_address,
        original_remote_port,
    );
}

/// Build an owned mock `NetBufferList` from raw bytes and extract the IPv4 key.
pub fn fuzz_key_from_bytes_v4(bytes: &[u8], direction: Direction) -> Result<Key, String> {
    let nbl = NetBufferList::owned_from_bytes(bytes.to_vec());
    get_key_from_nbl_v4(&nbl, direction)
}

/// Build an owned mock `NetBufferList` from raw bytes and extract the IPv6 key.
pub fn fuzz_key_from_bytes_v6(bytes: &[u8], direction: Direction) -> Result<Key, String> {
    let nbl = NetBufferList::owned_from_bytes(bytes.to_vec());
    get_key_from_nbl_v6(&nbl, direction)
}

/// Construct a mock `Device` for end-to-end harnesses (command channel / callouts).
pub fn new_mock_device() -> Result<Device, String> {
    let driver = Driver::mock();
    Device::new(&driver)
}

/// Feed an arbitrary byte buffer into the user-space command channel
/// (`Device::write`). Mirrors what a `handle.Write` from user space does.
pub fn fuzz_device_write(device: &mut Device, command_bytes: &[u8]) {
    let mut write_request = wdk::irp_helpers::WriteRequest::from_bytes(command_bytes);
    device.write(&mut write_request);
}

/// Convenience: collect a `Vec<u8>` packet into an owned NBL (for redirect tests
/// that go through the `Redirect for Packet` trait).
pub fn owned_nbl(bytes: Vec<u8>) -> NetBufferList {
    NetBufferList::owned_from_bytes(bytes)
}
