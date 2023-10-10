#![cfg_attr(not(test), no_std)]
#![no_main]
#![feature(allocator_api)]

extern crate alloc;

mod array_holder;
mod connection_cache;
mod entry;
mod id_cache;
mod protocol;
mod types;

use wdk::allocator::WindowsAllocator;

#[cfg(not(test))]
use core::panic::PanicInfo;

// Declaration of the global memory allocator
#[global_allocator]
static HEAP: WindowsAllocator = WindowsAllocator {};

// macro converts struct S to struct H

// #[no_mangle]
// pub extern "C" fn respondWithVerdict(packet_id: u32, verdict: Verdict) {
//     if packet_id == 0 || verdict == Verdict::Error {
//         return;
//     }

//     let result = unsafe {
//         if let Some(cache) = &mut cache::PACKET_CACHE {
//             cache.get(packet_id)
//         } else {
//             return;
//         }
//     };

//     if let Some((info_p, data, size)) = result {
//         unsafe {
//             if let Some(info) = info_p.as_mut() {
//                 if info.is_ipv6() {
//                     // Add to ipv6 verdict cache
//                     if let Some(cache) = &mut cache::VERDICT_CACHE_IPV6 {
//                         if let Some(replaced_info) = cache.add(info, verdict) {
//                             wdk::free(replaced_info as *mut u8);
//                         }
//                     }
//                 } else {
//                     // Add to ipv4 verdict cache
//                     if let Some(cache) = &mut cache::VERDICT_CACHE_IPV4 {
//                         if let Some(replaced_info) = cache.add(info, verdict) {
//                             wdk::free(replaced_info as *mut u8);
//                         }
//                     }
//                 }
//             }
//         }

//         match verdict {
//             Verdict::Accept => {
//                 wdk::inject_packet_callout(info_p, data, size);
//             }
//             Verdict::Block => {
//                 wdk::send_blocked_packet(info_p, data, size);
//             }
//             Verdict::Drop => wdk::free(data as *mut u8),
//             Verdict::RedirectDns | Verdict::RedirectTunnel => {
//                 wdk::redirect_packet(info_p, info_p, data, size)
//             }
//             _ => wdk::free(data as *mut u8),
//         }
//     } else {
//         log!(
//             "received verdict response for unknown packet id: {}",
//             packet_id
//         );
//     }
// }

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use wdk::err;

    err!("{}", info);
    loop {}
}
