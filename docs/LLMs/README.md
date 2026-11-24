# docs/LLMs — LLM Reference Files

This directory contains auto-generated reference files for LLMs (AI assistants)
working on the ZenithFence codebase. They give a compact, structured overview of
every type, function signature and doc comment, so an assistant can find the
right code without reading the whole source tree.

Regenerate all files after significant code changes:

```bash
just gen-llm-docs
```

The generators live in `tools/godoc-gen` (Go) and `tools/rustdoc-gen` (Rust, uses `syn`).
Do not edit the generated files by hand.

---

## Files

| File | Size | ~Tokens | Contents |
|---|---|---|---|
| `RUSTDOC-driver.md` | ~38 KB | ~11k | `driver/src` (callouts, device, caches, queues) and `driver/kernel` (the kernel-image build root) |
| `RUSTDOC-protocol.md` | ~7 KB | ~2k | `protocol/src` — command parsing (user→kernel) and info serialization (kernel→user) |
| `RUSTDOC-wdk.md` | ~96 KB | ~28k | `wdk/src` — unsafe wrappers over WFP, NDIS, IRP, IOQueue, locks, allocator, FFI |
| `RUSTDOC-mock.md` | ~89 KB | ~25k | `mock/` — `mock/wdk` (host mock of `wdk`), `mock/harness` (loader, callout API, event decoding), `mock/sim` (the `zfsim` Python extension, PyO3); `mock/driver` has no sources of its own, it compiles `driver/src` |
| `RUSTDOC-tools.md` | ~1.5 KB | <1k | `release/src` (packaging) |
| `GODOC.md` | ~15 KB | ~4k | Go user space: `kext_interface` (exported API) and `kext_tester` (all decls) |

Token estimates assume ~3.5 characters per token (typical for mixed code and prose).

---

## When to load which file

Load only the file(s) relevant to the current task to conserve context:

- **Driver logic** (callouts, verdicts, caches, device I/O) → `RUSTDOC-driver.md`
- **Protocol changes** (new command or info event) → `RUSTDOC-protocol.md` + `GODOC.md` — both sides must change together
- **Kernel API wrappers** (`wdk/`, unsafe) → `RUSTDOC-wdk.md`
- **Simulation / zfsim** (`mock/sim`, `just sim-*`) → `RUSTDOC-driver.md` + `RUSTDOC-mock.md` + `GODOC.md`
- **Go user-space library or tester** → `GODOC.md`

`RUSTDOC-wdk.md` and `RUSTDOC-mock.md` both define the WFP layer field enums;
load only the one the task builds against.

---

## What each file contains

**RUSTDOC files** — one section per source file (headed by its repo-relative path), each containing:
- Module doc comment (`//!`)
- `pub use` re-exports
- Constants and statics (long initializers elided as `...`)
- `macro_rules!` names with their docs
- Full type definitions — structs, enums, unions, aliases, traits — with field/variant docs,
  followed by the type's inherent `impl` blocks as method signatures with their docs
- Trait implementations as one-line headers (e.g. `unsafe impl Sync for ArrayHolder`)
- Free function signatures with their docs
- `extern` blocks (FFI declarations)
- Inline submodules as their own sections

Private items are included: most of the driver's logic lives in crate-private functions.

**GODOC.md** — one section per Go package, each containing:
- Import path, source file list and package doc comment
- Variables, constants, types (full struct/interface body) with methods grouped under their type
- Function signatures (no bodies)
- Library packages show exported symbols only; `package main` shows all declarations

---

## What is excluded

- Function and method bodies
- Test code: Rust `#[test]` / `#[cfg(test)]` items, `tests/` directories; Go `_test.go` files
- Generated Go files (`Code generated` header)
- `build.rs`, `target/`, `release/build/`, `c_helper/`, `libs/`, `npcap/`, and the doc tools themselves
- Non-code docs — read `PacketDoc.md` for the packet path and `CLAUDE.md` for the architecture overview
