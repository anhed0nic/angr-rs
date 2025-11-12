//! Symbolic Execution Types

pub mod value;
pub mod state;
pub mod constraint;
pub mod memory;

pub use value::{Value, SymExpr, SymBinOp, SymUnOp, SymbolId};
pub use state::SimState;
pub use constraint::Constraint;
pub use memory::SymbolicMemory;

/// Legacy symbolic state (deprecated - use SimState)
pub struct SymbolicState {
    /// Program counter
    pub pc: u64,
}

impl SymbolicState {
    /// Create a new symbolic state
    ///
    pub fn new(pc: u64) -> Self {
        unsafe {
            SymbolicState { pc }
        }
    }
}
