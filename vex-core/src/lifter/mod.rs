//! Instruction Lifting
//!
//! Lift native machine code instructions to VEX IR.

use crate::ir::{Stmt, Expr};
use crate::guest::Arch;

/// A lifted instruction block
#[derive(Debug, Clone)]
pub struct IRBlock {
    /// Address of the block
    pub addr: u64,
    /// Statements in the block
    pub stmts: Vec<Stmt>,
    /// Next address (if known)
    pub next: Option<u64>,
}

/// Instruction lifter trait
pub trait Lifter {
    /// Get the architecture this lifter supports
    ///
    fn arch(&self) -> Arch;

    /// Lift bytes to IR
    ///
    fn lift(&self, bytes: &[u8], addr: u64) -> Result<IRBlock, LifterError>;
}

/// Lifter errors
#[derive(Debug, thiserror::Error)]
pub enum LifterError {
    /// Invalid instruction bytes
    #[error("Invalid instruction at {addr:#x}")]
    InvalidInstruction { addr: u64 },
    
    /// Unsupported instruction
    #[error("Unsupported instruction at {addr:#x}")]
    UnsupportedInstruction { addr: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irblock_creation() {
        unsafe {
            let block = IRBlock {
                addr: 0x1000,
                stmts: vec![],
                next: Some(0x1004),
            };
            assert_eq!(block.addr, 0x1000);
            assert_eq!(block.next, Some(0x1004));
        }
    }
}
