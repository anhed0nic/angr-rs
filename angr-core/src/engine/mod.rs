//! Analysis Engines

pub mod pathgroup;
pub mod stepper;
pub mod merge;
pub mod executor;

pub use pathgroup::{PathGroup, ExplorationStrategy};
pub use stepper::{SymbolicStepper, StepResult};
pub use merge::{MergeManager, MergeStrategy, MergeResult, MergePoint, split_state, merge_states, can_merge};
pub use executor::SymbolicExecutor;

/// Analysis engine trait
pub trait AnalysisEngine {
    /// Get the name of this engine
    ///
    fn name(&self) -> &str;
}
