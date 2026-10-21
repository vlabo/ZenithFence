//! Model-based property test of the connection cache.
//!
//! Runs the real driver code (mock/driver) over the mock WDK.

use driver::connection_cache::*;
use driver::connection::{ConnectionV4, ConnectionV6, Direction, Key, Verdict};
use proptest::prelude::*;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};

// A non-loopback 2001:: address whose last byte is `last`.
fn v6(last: u8) -> Ipv6Address {
    Ipv6Address::from_octets([
        0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last,
    ])
}

// Fixed pool of 6 distinct keys. None use the DNS (53) / SPN (717) remote
// port or a loopback/equal remote, so `redirect_equals` never matches and
// `get_verdict` resolves a key to at most its own connection. Key 5 shares
// the TCP/1000 bucket with key 0 (tests multiple connections per port).
fn key(i: usize) -> Key {
    match i {
        0 => Key {
            protocol: IpProtocol::Tcp,
            local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
            local_port: 1000,
            remote_address: IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)),
            remote_port: 80,
        },
        1 => Key {
            protocol: IpProtocol::Udp,
            local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
            local_port: 1000,
            remote_address: IpAddress::Ipv4(Ipv4Address::new(8, 8, 8, 8)),
            remote_port: 5353,
        },
        2 => Key {
            protocol: IpProtocol::Tcp,
            local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)),
            local_port: 2000,
            remote_address: IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)),
            remote_port: 443,
        },
        3 => Key {
            protocol: IpProtocol::Tcp,
            local_address: IpAddress::Ipv6(v6(1)),
            local_port: 3000,
            remote_address: IpAddress::Ipv6(v6(0x80)),
            remote_port: 80,
        },
        4 => Key {
            protocol: IpProtocol::Udp,
            local_address: IpAddress::Ipv6(v6(2)),
            local_port: 4000,
            remote_address: IpAddress::Ipv6(v6(0x88)),
            remote_port: 5353,
        },
        _ => Key {
            protocol: IpProtocol::Tcp,
            local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
            local_port: 1000,
            remote_address: IpAddress::Ipv4(Ipv4Address::new(2, 2, 2, 2)),
            remote_port: 80,
        },
    }
}

const POOL: usize = 6;

fn verdict_from(v: u8) -> Verdict {
    num_traits::FromPrimitive::from_u8(v).unwrap()
}

#[derive(Clone, Copy, Debug)]
struct ConnModel {
    verdict: u8,
    ended: bool,
    end_time: u64,
    last_access: u64,
}

#[derive(Clone, Debug)]
enum Op {
    Add(usize),
    Update(usize, u8),
    End(usize),
    EndAllOnPort(usize),
    Clean,
    Clear,
    Advance(u64),
    CheckVerdict(usize),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..POOL).prop_map(Op::Add),
        (0..POOL, prop::sample::select(vec![0u8, 1, 2, 3, 4, 5, 6, 7, 10]))
            .prop_map(|(i, v)| Op::Update(i, v)),
        (0..POOL).prop_map(Op::End),
        (0..POOL).prop_map(Op::EndAllOnPort),
        Just(Op::Clean),
        Just(Op::Clear),
        prop::sample::select(vec![0u64, 30_000, 70_000, 130_000]).prop_map(Op::Advance),
        (0..POOL).prop_map(Op::CheckVerdict),
    ]
}

proptest! {
    // Integration tests have no src/lib.rs above them, so point proptest at the
    // saved-failure file explicitly (relative to this crate's root).
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::Direct(
                "proptest-regressions/connection_cache.txt",
            ),
        )),
        ..ProptestConfig::default()
    })]

    // Model-based test of the connection cache against a simple reference
    // model. Exercises the real RCU / unlinked-queue reclamation
    // (alloc_zeroed + Box::from_raw) under randomized op sequences, asserting
    // verdict lookups and active/ended counts stay consistent with the model.
    #[test]
    fn cache_state_machine(ops in proptest::collection::vec(op_strategy(), 0..32)) {
        let mut now: u64 = 1_000_000;
        wdk::utils::set_mock_time_ms(now);

        let cache = ConnectionCache::new();
        let mut model: [Option<ConnModel>; POOL] = [None; POOL];

        for op in ops {
            match op {
                Op::Add(i) => {
                    if model[i].is_none() {
                        let k = key(i);
                        if k.is_ipv6() {
                            let c = ConnectionV6::from_key(&k, 1, Direction::Outbound).unwrap();
                            cache.add_v6(c);
                        } else {
                            let c = ConnectionV4::from_key(&k, 1, Direction::Outbound).unwrap();
                            cache.add_v4(c);
                        }
                        model[i] = Some(ConnModel {
                            verdict: 0,
                            ended: false,
                            end_time: 0,
                            last_access: now,
                        });
                    }
                }
                Op::Update(i, v) => {
                    cache.update_connection(key(i), verdict_from(v));
                    if let Some(cm) = &mut model[i] {
                        cm.verdict = v;
                    }
                }
                Op::End(i) => {
                    let k = key(i);
                    if k.is_ipv6() {
                        cache.end_v6(k);
                    } else {
                        cache.end_v4(k);
                    }
                    if let Some(cm) = &mut model[i] {
                        cm.ended = true;
                        cm.end_time = now;
                    }
                }
                Op::EndAllOnPort(i) => {
                    let k = key(i);
                    if k.is_ipv6() {
                        cache.end_all_on_port_v6((k.protocol, k.local_port));
                    } else {
                        cache.end_all_on_port_v4((k.protocol, k.local_port));
                    }
                    for j in 0..POOL {
                        let kj = key(j);
                        if kj.is_ipv6() == k.is_ipv6()
                            && kj.protocol == k.protocol
                            && kj.local_port == k.local_port
                        {
                            if let Some(cm) = &mut model[j] {
                                if !cm.ended {
                                    cm.ended = true;
                                    cm.end_time = now;
                                }
                            }
                        }
                    }
                }
                Op::Clean => {
                    cache.clean_ended_connections();
                    for slot in model.iter_mut() {
                        if let Some(cm) = *slot {
                            let remove = (cm.ended && cm.end_time < now.saturating_sub(60_000))
                                || (cm.last_access < now.saturating_sub(120_000));
                            if remove {
                                *slot = None;
                            }
                        }
                    }
                }
                Op::Clear => {
                    cache.clear();
                    for slot in model.iter_mut() {
                        *slot = None;
                    }
                }
                Op::Advance(d) => {
                    now += d;
                    wdk::utils::set_mock_time_ms(now);
                }
                Op::CheckVerdict(i) => {
                    let got = cache.get_verdict(&key(i)).map(|v| v as u8);
                    let expected = model[i].map(|cm| cm.verdict);
                    prop_assert_eq!(got, expected);
                    if let Some(cm) = &mut model[i] {
                        cm.last_access = now;
                    }
                }
            }
        }

        // Final invariants: verdict lookups and active/ended counts match.
        for i in 0..POOL {
            let got = cache.get_verdict(&key(i)).map(|v| v as u8);
            let expected = model[i].map(|cm| cm.verdict);
            prop_assert_eq!(got, expected, "verdict mismatch for key {}", i);
        }
        let (active, ended) = cache.get_entries_count();
        let exp_active = model.iter().filter(|m| matches!(m, Some(c) if !c.ended)).count();
        let exp_ended = model.iter().filter(|m| matches!(m, Some(c) if c.ended)).count();
        prop_assert_eq!(active, exp_active, "active count mismatch");
        prop_assert_eq!(ended, exp_ended, "ended count mismatch");
    }
}
