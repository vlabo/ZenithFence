//! Windows-runnable driver for the fuzz targets.
//!
//! Unlike the libFuzzer targets in `fuzz_targets/` (which only link under
//! `cargo fuzz` on Linux), this is an ordinary binary with a real `main`, so it
//! builds and runs on Windows with plain `cargo run`.
//!
//! Usage:
//!   cargo run --bin replay -- <target> [file ...]
//!     with files : run the target on each file's bytes (replay a corpus/crash input)
//!     no files   : run a random-input smoke loop (env: ITERS, SEED)
//!
//! Targets: callouts, callouts_mt, simulation
//!
//! Note: this is NOT coverage-guided -- it is random/replay testing. Use it to
//! reproduce a Linux fuzzer crash on Windows or for a quick "does anything
//! panic" sweep. The coverage-guided runs happen via `cargo fuzz run` on Linux.

use std::{env, fs, process};

use driver_fuzz::targets;

// Deterministic xorshift64 PRNG (no external deps; reproducible given a seed).
fn next(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || !targets::NAMES.contains(&args[1].as_str()) {
        eprintln!("usage: replay <target> [file ...]");
        eprintln!("targets: {}", targets::NAMES.join(" "));
        eprintln!("  with files : run the target on each file (replay a corpus/crash input)");
        eprintln!("  no files   : run a random-input smoke loop (env: ITERS, SEED)");
        process::exit(2);
    }
    let target = args[1].clone();
    let files = &args[2..];

    // Replay mode: run each supplied file through the target.
    if !files.is_empty() {
        for f in files {
            let data = fs::read(f).unwrap_or_else(|e| {
                eprintln!("error reading {f}: {e}");
                process::exit(1);
            });
            targets::run(&target, &data);
            println!("ok: {f} ({} bytes)", data.len());
        }
        println!("replay complete: no panic");
        return;
    }

    // Smoke mode: feed many random buffers through the target.
    let iters: u64 = env::var("ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let seed: u64 = env::var("SEED").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15)
    });

    let mut state = seed | 1; // xorshift must not be seeded with 0
    let mut buf = vec![0u8; 1024];
    for _ in 0..iters {
        let len = (next(&mut state) as usize) % (buf.len() + 1);
        for b in buf[..len].iter_mut() {
            *b = next(&mut state) as u8;
        }
        targets::run(&target, &buf[..len]);
    }
    println!("ok: {target} survived {iters} random inputs (seed {seed})");
}
