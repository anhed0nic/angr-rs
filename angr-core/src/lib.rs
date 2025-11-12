//! Angr Core - Binary Analysis Framework
//!
//! Core binary analysis engine including binary loading, CFG generation,
//! symbolic execution, and memory management.
//!
//! # Safety
//!

#![allow(unsafe_code)]
#![warn(missing_docs)]

pub mod loader;
pub mod memory;
pub mod engine;
pub mod cfg;
pub mod symbolic;
pub mod solver;
pub mod procedures;

/// Angr Core library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
