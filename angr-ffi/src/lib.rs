//! FFI Bindings for angr-rs
//!
//! Foreign Function Interface bindings for Python and C.

#![allow(unsafe_code)]

#[cfg(feature = "python")]
pub mod python;
