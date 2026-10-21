//! ALE callouts driven end to end over the mock WDK.
//!
//! Runs the real driver code (mock/driver) over the mock WDK.

use driver::ale_callouts::ale_layer_accept_v4;
use driver::connection::{Key, Verdict};
use driver::entry::get_device;
use driver_harness::loader::{self, Reads};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address};
use wdk::filter_engine::callout_data::{CalloutData, Value};
use wdk::filter_engine::classify::{ClassifyOut, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT};
use wdk::filter_engine::layer::{FieldsAleAuthRecvAcceptV4, FieldsInboundIppacketV4, Layer};
use wdk::filter_engine::net_buffer::NET_BUFFER_LIST;
use wdk::irp_helpers::WriteRequest;

// Callouts reach the device through the driver's process-wide global, so the
// tests that load the driver must not run concurrently: each holds the harness
// driver lock for its whole duration.
fn install_device() {
    loader::reload(Reads::NonBlocking);
}

fn uninstall_device() {
    loader::unload();
}

fn ale_recv_v4_values(
    proto: u8,
    local_ip: [u8; 4],
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
) -> Vec<Value> {
    type F = FieldsAleAuthRecvAcceptV4;
    let mut v = vec![Value::U32(0); F::Max as usize];
    v[F::IpProtocol as usize] = Value::U8(proto);
    v[F::IpLocalAddress as usize] = Value::U32(u32::from_be_bytes(local_ip));
    v[F::IpLocalPort as usize] = Value::U16(local_port);
    v[F::IpRemoteAddress as usize] = Value::U32(u32::from_be_bytes(remote_ip));
    v[F::IpRemotePort as usize] = Value::U16(remote_port);
    v[F::Flags as usize] = Value::U32(0);
    v
}

fn inbound_ippacket_v4_values() -> Vec<Value> {
    vec![Value::U32(0); FieldsInboundIppacketV4::Max as usize]
}

// Minimal IPv4 + TCP header carrying the given addresses/ports. Only the
// fields `get_key_from_nb_v4` reads are populated.
fn ipv4_tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45; // version 4, IHL 5
    p[9] = 6; // TCP
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&src_port.to_be_bytes());
    p[22..24].copy_from_slice(&dst_port.to_be_bytes());
    p
}

fn ale_key() -> Key {
    Key {
        protocol: IpProtocol::Tcp,
        local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 5)),
        local_port: 8080,
        remote_address: IpAddress::Ipv4(Ipv4Address::new(93, 184, 216, 34)),
        remote_port: 12345,
    }
}

// Full pipeline: inbound ALE accept (pends) -> user-space PermanentAccept
// verdict -> packet layer permits the matching flow. Asserts the verdict set
// via the command channel is the one observed at the packet layer.
#[test]
fn ale_accept_verdict_packet_pipeline() {
    let _g = loader::lock();
    install_device();

    // 1. New inbound connection -> block + absorb, pended for user space.
    let mut co = ClassifyOut::new();
    let mut ale_nbl = NET_BUFFER_LIST::new_box(vec![0u8; 60], 40);
    let data = CalloutData::mock(
        Layer::AleAuthRecvAcceptV4,
        ale_recv_v4_values(6, [10, 0, 0, 5], 8080, [93, 184, 216, 34], 12345),
        Some(4321),
        &mut co as *mut _,
        ale_nbl.as_mut() as *mut _,
        20,
        20,
    );
    ale_layer_accept_v4(data);

    assert_eq!(co.action(), FWP_ACTION_BLOCK);
    assert!(co.is_absorb());
    {
        let device = get_device().unwrap();
        assert_eq!(
            device.connection_cache.get_verdict(&ale_key()).map(|v| v as u8),
            Some(Verdict::Undecided as u8),
        );
        assert_eq!(device.packet_cache.get_entries_count(), 1);
    }

    // 2. User space returns PermanentAccept for packet id 1.
    let mut cmd = vec![1u8]; // CommandType::Verdict
    cmd.extend_from_slice(&1u64.to_le_bytes());
    cmd.push(Verdict::PermanentAccept as u8);
    {
        let device = get_device().unwrap();
        let mut wr = WriteRequest::from_bytes(&cmd);
        device.write(&mut wr);
        assert_eq!(
            device.connection_cache.get_verdict(&ale_key()).map(|v| v as u8),
            Some(Verdict::PermanentAccept as u8),
        );
        assert_eq!(device.packet_cache.get_entries_count(), 0);
    }

    // 3. Packet layer sees the same flow and permits it.
    let mut co2 = ClassifyOut::new();
    let mut pkt_nbl = NET_BUFFER_LIST::new_box(
        ipv4_tcp_packet([93, 184, 216, 34], [10, 0, 0, 5], 12345, 8080),
        20,
    );
    let data2 = CalloutData::mock(
        Layer::InboundIppacketV4,
        inbound_ippacket_v4_values(),
        None,
        &mut co2 as *mut _,
        pkt_nbl.as_mut() as *mut _,
        0,
        0,
    );
    driver::packet_callouts::ip_packet_layer_inbound_v4(data2);
    assert_eq!(co2.action(), FWP_ACTION_PERMIT);

    uninstall_device();
}

// The ALE accept callout must not panic for any protocol value, and must
// always set some action.
#[test]
fn ale_accept_never_panics_across_protocols() {
    let _g = loader::lock();
    install_device();
    for proto in [6u8, 17, 1, 0, 255] {
        let mut co = ClassifyOut::new();
        let mut nbl = NET_BUFFER_LIST::new_box(vec![0u8; 60], 40);
        let data = CalloutData::mock(
            Layer::AleAuthRecvAcceptV4,
            ale_recv_v4_values(proto, [10, 0, 0, 9], 1111, [1, 2, 3, 4], 2222),
            Some(7),
            &mut co as *mut _,
            nbl.as_mut() as *mut _,
            20,
            20,
        );
        ale_layer_accept_v4(data);
        assert_ne!(co.action(), 0);
    }
    uninstall_device();
}

// Sanity check that the `fuzz_api` callout harness actually links the
// pipeline (ALE pend -> verdict command -> packet layer reads the verdict)
// and that its Tier-3 oracle is not vacuous. Holds the driver lock like the
// other global-device tests. Mirrors what the `callouts` fuzz target asserts.
#[test]
fn fuzz_api_pipeline_links_and_oracle_holds() {
    use driver_harness::fuzz_api;
    let _g = loader::lock();
    install_device();

    // PermanentAccept pipeline on pool connection 0 (v4 TCP).
    let r = fuzz_api::run_ale_accept_v4(0, 0, false, 100, &[], false);
    assert_ne!(r.action, 0, "ALE accept must set an action");
    let ids = fuzz_api::live_ids();
    assert_eq!(ids.len(), 1, "ALE accept must pend exactly one packet");
    fuzz_api::device_write_verdict(ids[0], Verdict::PermanentAccept as u8);
    assert_eq!(
        fuzz_api::verdict_for_v4(0, 0),
        Some(Verdict::PermanentAccept as u8),
        "verdict command must reach the connection cache",
    );
    let r = fuzz_api::run_packet_in_v4(0, 0, &[], false);
    assert_eq!(r.action, FWP_ACTION_PERMIT, "PermanentAccept must permit");
    assert!(!r.absorb);

    // PermanentBlock pipeline on pool connection 1 (v4 UDP).
    let r = fuzz_api::run_ale_accept_v4(1, 1, false, 100, &[], false);
    assert_ne!(r.action, 0);
    let ids = fuzz_api::live_ids();
    assert_eq!(ids.len(), 1, "previous packet should have been consumed");
    fuzz_api::device_write_verdict(ids[0], Verdict::PermanentBlock as u8);
    let r = fuzz_api::run_packet_in_v4(1, 1, &[], false);
    assert_eq!(r.action, FWP_ACTION_BLOCK, "PermanentBlock must block");
    assert!(!r.absorb, "PermanentBlock must not absorb");

    uninstall_device();
}

// One worker thread: a deterministic, varied mix of every callout + command
// op, all aimed at a small "hot" set of connection slots so threads collide
// hard on the same RCU ports and the packet cache. The only per-call
// invariant asserted is that an ALE callout always sets an action -- true
// regardless of how the threads interleave.
fn mt_worker(tid: u64, iters: u64) {
    use driver_harness::fuzz_api as api;
    // Inline xorshift64, seeded per thread (deterministic per run).
    let mut st = tid.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    const HOT: u8 = 6; // few connections -> maximum contention
    for _ in 0..iters {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17;
        let r = st;
        let conn = (r as u8) % HOT;
        let proto = (r >> 8) as u8;
        let pid = (r >> 16) as u16 as u64;
        let verdict = ((r >> 32) as u8) % 10;
        match ((r >> 24) as u8) % 14 {
            0 => assert_ne!(
                api::run_ale_connect_v4(conn, proto, false, pid, &[], false).action,
                0
            ),
            1 => assert_ne!(
                api::run_ale_accept_v4(conn, proto, false, pid, &[], false).action,
                0
            ),
            2 => assert_ne!(
                api::run_ale_connect_v6(conn, proto, false, pid, &[], false).action,
                0
            ),
            3 => assert_ne!(
                api::run_ale_accept_v6(conn, proto, false, pid, &[], false).action,
                0
            ),
            4 => {
                api::run_packet_in_v4(conn, proto, &[], false);
            }
            5 => {
                api::run_packet_out_v4(conn, proto, &[], false);
            }
            6 => {
                api::run_packet_in_v6(conn, proto, &[], false);
            }
            7 => {
                api::run_packet_out_v6(conn, proto, &[], false);
            }
            8 => {
                let ids = api::live_ids();
                let id = if ids.is_empty() {
                    r
                } else {
                    ids[(r as usize) % ids.len()]
                };
                api::device_write_verdict(id, verdict);
            }
            9 => api::device_write_update_v4(conn, proto, verdict),
            10 => api::device_write_update_v6(conn, proto, verdict),
            11 => api::run_endpoint_close_v4(conn, proto, pid),
            12 => api::run_resource_v4((r >> 40) as u8, proto, (r >> 48) as u16),
            _ => api::drain_events(2),
        }
    }
}

// Stress: many threads pounding ONE shared device with concurrent callouts +
// commands in every combination. This is the "should never fail" check, and
// it runs natively on Windows via `just test-driver`. It exercises the real
// reader-writer lock in mock_wdk and the RCU reclamation path under genuine
// contention; it catches panics, deadlocks (test hang), use-after-free /
// double-free, and the kind of duplicate-id race the atomic IdCache fix
// closed. If the mock lock were still a no-op this test would corrupt/crash.
#[test]
fn callouts_mt_shared_device_stress() {
    let _g = loader::lock();
    install_device();

    const THREADS: usize = 8;
    const ITERS: u64 = 10_000;

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for t in 0..THREADS {
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait(); // release all workers together for maximum overlap
            mt_worker(t as u64 + 1, ITERS);
        }));
    }
    for h in handles {
        h.join()
            .expect("a worker thread panicked under concurrent callouts");
    }

    // Quiesce oracle: with all workers joined, a shutdown must fully drain
    // the packet cache regardless of how the threads interleaved.
    driver_harness::fuzz_api::device_shutdown();
    assert_eq!(
        driver_harness::fuzz_api::packet_cache_len(),
        0,
        "packet cache not drained after MT quiesce + shutdown"
    );

    uninstall_device();
}
