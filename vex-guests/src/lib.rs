//! VEX Guest Architecture Implementations
//!
//! Architecture-specific instruction lifters for x86, x86_64, ARM, ARM64, and MIPS.
//!
//! # Safety
//!

#![allow(unsafe_code)]
#![warn(missing_docs)]

pub mod x86;
pub mod x86_64;
pub mod arm;
pub mod arm64;
pub mod mips;

/// VEX Guests library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
