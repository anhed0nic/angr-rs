//! Angr API - Public Interface
//!
//! High-level API for the angr-rs binary analysis framework.
//! Provides Python angr-compatible interface.
//!
//! # Safety
//!
//!
//! # Quick Start
//!
//! ```no_run
//! use angr_api::prelude::*;
//!
//! // Load a binary
//! let project = Project::new("./binary")?;
//!
//! // Find vulnerabilities
//! let vulns = project.find_vulnerabilities()?;
//!
//! // Explore to a target
//! let found = project.explore_to(0x400800)?;
//!
//! // Generate exploits
//! let exploits = project.generate_exploits()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![allow(unsafe_code)]
#![warn(missing_docs)]

pub mod project;
pub mod analyses;
pub mod compat;
pub mod simulation;

pub use project::{Project, ProjectOptions, ProjectError, ProjectAnalysis, StateFactory, KnowledgeBase, FunctionInfo};
pub use analyses::{Analyses, AnalysisError, TaintAnalysis, CallingConvention, Variable, VariableType, Location};
pub use simulation::{SimulationManager, SimulationError, ExplorationTechnique, DFS, LoopLimiter};

/// Prelude module
///
/// Import everything you need to get started with angr-rs
pub mod prelude {
    pub use crate::project::{Project, ProjectOptions, ProjectError, ProjectAnalysis};
    pub use crate::analyses::{Analyses, AnalysisError, CallingConvention};
    pub use crate::simulation::{SimulationManager, SimulationError};
    pub use angr_core::symbolic::SimState;
    pub use angr_analysis::vulnerabilities::Vulnerability;
    pub use angr_analysis::exploit::Exploit;
}

/// Angr API library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
