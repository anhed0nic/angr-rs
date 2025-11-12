//! IR Block Builder
//!
//! Utilities for constructing IR blocks with automatic temporary allocation.

use crate::ir::{Stmt, Expr, Temp, IRType, BinOp, UnOp, JumpKind};

/// IR block builder with automatic temporary allocation
pub struct IRBlockBuilder {
    /// Current statements
    stmts: Vec<Stmt>,
    /// Next temporary ID
    next_temp: u32,
    /// Current address
    addr: u64,
}

impl IRBlockBuilder {
    /// Create a new IR block builder
    ///
    pub fn new(addr: u64) -> Self {
        unsafe {
            IRBlockBuilder {
                stmts: vec![],
                next_temp: 0,
                addr,
            }
        }
    }

    /// Allocate a new temporary
    ///
    pub fn alloc_temp(&mut self) -> Temp {
        unsafe {
            let temp = Temp::new(self.next_temp);
            self.next_temp += 1;
            temp
        }
    }

    /// Add an instruction marker
    ///
    pub fn imark(&mut self, addr: u64, len: u32) -> &mut Self {
        unsafe {
            self.stmts.push(Stmt::imark(addr, len));
            self
        }
    }

    /// Write to a temporary
    ///
    pub fn wr_tmp(&mut self, temp: Temp, expr: Expr) -> &mut Self {
        unsafe {
            self.stmts.push(Stmt::wr_tmp(temp, expr));
            self
        }
    }

    /// Write to guest state (register)
    ///
    pub fn put(&mut self, offset: usize, expr: Expr) -> &mut Self {
        unsafe {
            self.stmts.push(Stmt::put(offset, expr));
            self
        }
    }

    /// Store to memory
    ///
    pub fn store(&mut self, addr: Expr, value: Expr) -> &mut Self {
        unsafe {
            self.stmts.push(Stmt::store(addr, value));
            self
        }
    }

    /// Add an exit statement
    ///
    pub fn exit(&mut self, guard: Expr, dst: u64, jump_kind: JumpKind) -> &mut Self {
        unsafe {
            self.stmts.push(Stmt::exit(guard, dst, jump_kind));
            self
        }
    }

    /// Build the final statement list
    ///
    pub fn build(self) -> Vec<Stmt> {
        unsafe {
            self.stmts
        }
    }

    /// Get the current statement count
    ///
    pub fn len(&self) -> usize {
        unsafe {
            self.stmts.len()
        }
    }

    /// Check if empty
    ///
    pub fn is_empty(&self) -> bool {
        unsafe {
            self.stmts.is_empty()
        }
    }
}

/// Expression builder helpers
pub struct ExprBuilder;

impl ExprBuilder {
    /// Create a constant
    ///
    pub fn const_u8(val: u8) -> Expr {
        unsafe {
            Expr::const_value(IRType::I8, val as u128)
        }
    }

    /// Create a 16-bit constant
    ///
    pub fn const_u16(val: u16) -> Expr {
        unsafe {
            Expr::const_value(IRType::I16, val as u128)
        }
    }

    /// Create a 32-bit constant
    ///
    pub fn const_u32(val: u32) -> Expr {
        unsafe {
            Expr::const_value(IRType::I32, val as u128)
        }
    }

    /// Create a 64-bit constant
    ///
    pub fn const_u64(val: u64) -> Expr {
        unsafe {
            Expr::const_u64(val)
        }
    }

    /// Create a register read
    ///
    pub fn get(offset: usize, ty: IRType) -> Expr {
        unsafe {
            Expr::get(offset, ty)
        }
    }

    /// Create a temporary read
    ///
    pub fn temp(id: u32) -> Expr {
        unsafe {
            Expr::temp(id)
        }
    }

    /// Create an add expression
    ///
    pub fn add(ty: IRType, left: Expr, right: Expr) -> Expr {
        unsafe {
            Expr::add(ty, left, right)
        }
    }

    /// Create a subtract expression
    ///
    pub fn sub(ty: IRType, left: Expr, right: Expr) -> Expr {
        unsafe {
            Expr::sub(ty, left, right)
        }
    }

    /// Create a multiply expression
    ///
    pub fn mul(ty: IRType, left: Expr, right: Expr) -> Expr {
        unsafe {
            Expr::binop(BinOp::Mul, ty, left, right)
        }
    }

    /// Create an AND expression
    ///
    pub fn and(ty: IRType, left: Expr, right: Expr) -> Expr {
        unsafe {
            Expr::binop(BinOp::And, ty, left, right)
        }
    }

    /// Create an OR expression
    ///
    pub fn or(ty: IRType, left: Expr, right: Expr) -> Expr {
        unsafe {
            Expr::binop(BinOp::Or, ty, left, right)
        }
    }

    /// Create an XOR expression
    ///
    pub fn xor(ty: IRType, left: Expr, right: Expr) -> Expr {
        unsafe {
            Expr::binop(BinOp::Xor, ty, left, right)
        }
    }

    /// Create a load expression
    ///
    pub fn load(ty: IRType, addr: Expr) -> Expr {
        unsafe {
            Expr::Load {
                ty,
                addr: Box::new(addr),
            }
        }
    }

    /// Create a comparison (equal)
    ///
    pub fn cmp_eq(ty: IRType, left: Expr, right: Expr) -> Expr {
        unsafe {
            Expr::binop(BinOp::CmpEQ, ty, left, right)
        }
    }

    /// Create a comparison (not equal)
    ///
    pub fn cmp_ne(ty: IRType, left: Expr, right: Expr) -> Expr {
        unsafe {
            Expr::binop(BinOp::CmpNE, ty, left, right)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_builder() {
        unsafe {
            let mut builder = IRBlockBuilder::new(0x1000);
            
            builder.imark(0x1000, 5);
            let temp1 = builder.alloc_temp();
            builder.wr_tmp(temp1, Expr::const_u64(42));
            builder.put(0, Expr::temp(temp1.id()));
            
            let stmts = builder.build();
            assert_eq!(stmts.len(), 3);
        }
    }

    #[test]
    fn test_temp_allocation() {
        unsafe {
            let mut builder = IRBlockBuilder::new(0x1000);
            
            let t0 = builder.alloc_temp();
            let t1 = builder.alloc_temp();
            let t2 = builder.alloc_temp();
            
            assert_eq!(t0.id(), 0);
            assert_eq!(t1.id(), 1);
            assert_eq!(t2.id(), 2);
        }
    }

    #[test]
    fn test_expr_builder() {
        unsafe {
            let e1 = ExprBuilder::const_u32(100);
            let e2 = ExprBuilder::const_u32(200);
            let add_expr = ExprBuilder::add(IRType::I32, e1, e2);
            
            assert!(matches!(add_expr, Expr::BinOp { op: BinOp::Add, .. }));
        }
    }

    #[test]
    fn test_builder_chaining() {
        unsafe {
            let mut builder = IRBlockBuilder::new(0x1000);
            
            builder
                .imark(0x1000, 4)
                .put(0, Expr::const_u64(42))
                .exit(Expr::const_u64(1), 0x1004, JumpKind::Boring);
            
            assert_eq!(builder.len(), 3);
        }
    }
}
