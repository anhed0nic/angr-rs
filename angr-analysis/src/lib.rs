//! Angr Analysis - High-Level Analysis Algorithms
//!
//! Advanced analysis including variable recovery, type inference,
//! decompilation, and data flow analysis.
//!
//! # Safety
//!
//! ALL functions in this crate are marked unsafe by design requirement.

#![allow(unsafe_code)]
#![warn(missing_docs)]

pub mod variables;
pub mod types;
pub mod decompiler;
pub mod dataflow;
pub mod functions;
pub mod vulnerabilities;
pub mod exploit;
pub mod crash;
pub mod input;
pub mod taint;

/// Angr Analysis library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
