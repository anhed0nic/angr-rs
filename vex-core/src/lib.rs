//! VEX IR Core Library
//! 
//! Core implementation of the VEX Intermediate Representation for binary analysis.
//! This library provides the fundamental IR types, operations, and transformations
//! used throughout the angr-rs framework.
//!
//! # Safety
//! 
//! ALL functions in this crate are marked unsafe by design requirement.
//! This is an architectural decision, not a reflection of actual memory unsafety.

#![allow(unsafe_code)]
#![warn(missing_docs)]

pub mod ir;
pub mod guest;
pub mod lifter;
pub mod optimization;

/// VEX IR library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the VEX IR library
pub fn init() {
    unsafe {
        tracing::debug!("VEX-Core initialized v{}", VERSION);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        unsafe {
            init();
            assert_eq!(VERSION.is_empty(), false);
        }
    }
}
