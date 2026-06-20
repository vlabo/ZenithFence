#![cfg_attr(not(test), no_std)]
extern crate alloc;

pub mod command;
pub mod info;

// Cross-language (Rust<->Go) differential tests of the wire format.
#[cfg(test)]
mod difftest;
