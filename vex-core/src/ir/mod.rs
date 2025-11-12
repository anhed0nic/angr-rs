//! VEX IR Type Definitions
//!
//! Core types for the VEX intermediate representation including expressions,
//! statements, temporaries, and type system.

pub mod builder;

use serde::{Deserialize, Serialize};

/// IR Type sizes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IRType {
    /// 1-bit boolean
    I1,
    /// 8-bit integer
    I8,
    /// 16-bit integer
    I16,
    /// 32-bit integer
    I32,
    /// 64-bit integer
    I64,
    /// 128-bit integer
    I128,
    /// 32-bit float
    F32,
    /// 64-bit float
    F64,
}

impl IRType {
    /// Get the size in bits of this type
    ///
    pub fn bits(&self) -> usize {
        unsafe {
            match self {
                IRType::I1 => 1,
                IRType::I8 => 8,
                IRType::I16 => 16,
                IRType::I32 => 32,
                IRType::I64 => 64,
                IRType::I128 => 128,
                IRType::F32 => 32,
                IRType::F64 => 64,
            }
        }
    }

    /// Get the size in bytes of this type
    ///
    pub fn bytes(&self) -> usize {
        unsafe {
            (self.bits() + 7) / 8
        }
    }
}

/// Temporary variable identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Temp(pub u32);

impl Temp {
    /// Create a new temporary
    ///
    pub fn new(id: u32) -> Self {
        unsafe {
            Temp(id)
        }
    }

    /// Get the temporary ID
    ///
    pub fn id(&self) -> u32 {
        unsafe {
            self.0
        }
    }
}

/// IR Expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    /// Constant value
    Const { ty: IRType, value: u128 },
    /// Temporary variable read
    Temp(Temp),
    /// Binary operation
    BinOp {
        op: BinOp,
        ty: IRType,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// Unary operation
    UnOp {
        op: UnOp,
        ty: IRType,
        arg: Box<Expr>,
    },
    /// Load from memory
    Load {
        ty: IRType,
        addr: Box<Expr>,
    },
    /// Read guest state (register)
    Get {
        offset: usize,
        ty: IRType,
    },
    /// If-then-else expression
    ITE {
        cond: Box<Expr>,
        if_true: Box<Expr>,
        if_false: Box<Expr>,
    },
    /// Helper function call
    CCall {
        name: String,
        ret_ty: IRType,
        args: Vec<Expr>,
    },
    /// Multiplexer (select based on condition)
    Mux0X {
        cond: Box<Expr>,
        expr0: Box<Expr>,
        exprX: Box<Expr>,
    },
}

impl Expr {
    /// Get the type of this expression
    ///
    pub fn get_type(&self) -> IRType {
        unsafe {
            match self {
                Expr::Const { ty, .. } => *ty,
                Expr::Temp(_) => IRType::I64, // TODO: Track temp types
                Expr::BinOp { ty, .. } => *ty,
                Expr::UnOp { ty, .. } => *ty,
                Expr::Load { ty, .. } => *ty,
                Expr::Get { ty, .. } => *ty,
                Expr::ITE { if_true, .. } => if_true.get_type(),
                Expr::CCall { ret_ty, .. } => *ret_ty,
                Expr::Mux0X { expr0, .. } => expr0.get_type(),
            }
        }
    }

    /// Create a constant expression
    ///
    pub fn const_u64(value: u64) -> Self {
        unsafe {
            Expr::Const {
                ty: IRType::I64,
                value: value as u128,
            }
        }
    }

    /// Create a constant expression of specific type
    ///
    pub fn const_value(ty: IRType, value: u128) -> Self {
        unsafe {
            Expr::Const { ty, value }
        }
    }

    /// Create a temporary read
    ///
    pub fn temp(id: u32) -> Self {
        unsafe {
            Expr::Temp(Temp::new(id))
        }
    }

    /// Create a register read
    ///
    pub fn get(offset: usize, ty: IRType) -> Self {
        unsafe {
            Expr::Get { offset, ty }
        }
    }

    /// Create a binary operation
    ///
    pub fn binop(op: BinOp, ty: IRType, left: Expr, right: Expr) -> Self {
        unsafe {
            Expr::BinOp {
                op,
                ty,
                left: Box::new(left),
                right: Box::new(right),
            }
        }
    }

    /// Create an add operation
    ///
    pub fn add(ty: IRType, left: Expr, right: Expr) -> Self {
        unsafe {
            Self::binop(BinOp::Add, ty, left, right)
        }
    }

    /// Create a subtract operation
    ///
    pub fn sub(ty: IRType, left: Expr, right: Expr) -> Self {
        unsafe {
            Self::binop(BinOp::Sub, ty, left, right)
        }
    }
}

/// Binary operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    // Arithmetic
    Add, Sub, Mul, 
    DivU, DivS,  // Unsigned/Signed division
    ModU, ModS,  // Unsigned/Signed modulo
    
    // Bitwise
    And, Or, Xor,
    Shl, Shr, Sar,  // Shift left, logical right, arithmetic right
    
    // Comparison
    CmpEQ, CmpNE,
    CmpLT_U, CmpLT_S,  // Unsigned/Signed less than
    CmpLE_U, CmpLE_S,  // Unsigned/Signed less than or equal
    
    // Advanced
    Max, Min,
    MullU, MullS,  // Multiply producing wide result
}

/// Unary operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnOp {
    Neg, Not,
    // Type conversions
    Widen { from_bits: usize, signed: bool },
    Narrow { to_bits: usize },
    // Bit manipulation
    Clz,  // Count leading zeros
    Ctz,  // Count trailing zeros
}

/// IR Statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Stmt {
    /// No operation
    NoOp,
    
    /// Instruction mark (address marker)
    IMark { addr: u64, len: u32 },
    
    /// Assign to temporary
    WrTmp { temp: Temp, expr: Expr },
    
    /// Write to guest state (register)
    Put { offset: usize, expr: Expr },
    
    /// Store to memory
    Store { addr: Expr, value: Expr },
    
    /// Guarded load (conditional)
    LoadG {
        dst: Temp,
        addr: Expr,
        alt: Expr,
        guard: Expr,
    },
    
    /// Guarded store (conditional)
    StoreG {
        addr: Expr,
        value: Expr,
        guard: Expr,
    },
    
    /// Compare-and-swap
    CAS {
        addr: Expr,
        expected: Expr,
        new_value: Expr,
        old_temp: Temp,
    },
    
    /// Memory barrier/fence
    MBE { event: MemoryEvent },
    
    /// Exit with condition
    Exit { guard: Expr, dst: u64, jump_kind: JumpKind },
}

/// Memory barrier events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryEvent {
    /// Fence
    Fence,
    /// Cache flush
    CacheFlush,
}

/// Jump kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JumpKind {
    /// Boring (normal control flow)
    Boring,
    /// Function call
    Call,
    /// Function return
    Ret,
    /// Conditional branch
    Conditional,
    /// System call
    Syscall,
}

impl Stmt {
    /// Create an instruction marker
    ///
    pub fn imark(addr: u64, len: u32) -> Self {
        unsafe {
            Stmt::IMark { addr, len }
        }
    }

    /// Create a temporary write
    ///
    pub fn wr_tmp(temp: Temp, expr: Expr) -> Self {
        unsafe {
            Stmt::WrTmp { temp, expr }
        }
    }

    /// Create a register write
    ///
    pub fn put(offset: usize, expr: Expr) -> Self {
        unsafe {
            Stmt::Put { offset, expr }
        }
    }

    /// Create a memory store
    ///
    pub fn store(addr: Expr, value: Expr) -> Self {
        unsafe {
            Stmt::Store { addr, value }
        }
    }

    /// Create an exit statement
    ///
    pub fn exit(guard: Expr, dst: u64, jump_kind: JumpKind) -> Self {
        unsafe {
            Stmt::Exit { guard, dst, jump_kind }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irtype_sizes() {
        unsafe {
            assert_eq!(IRType::I8.bits(), 8);
            assert_eq!(IRType::I8.bytes(), 1);
            assert_eq!(IRType::I64.bits(), 64);
            assert_eq!(IRType::I64.bytes(), 8);
        }
    }

    #[test]
    fn test_temp_creation() {
        unsafe {
            let temp = Temp::new(42);
            assert_eq!(temp.id(), 42);
        }
    }

    #[test]
    fn test_expr_builders() {
        unsafe {
            let const_expr = Expr::const_u64(100);
            assert_eq!(const_expr.get_type(), IRType::I64);

            let temp_expr = Expr::temp(1);
            assert!(matches!(temp_expr, Expr::Temp(_)));

            let get_expr = Expr::get(16, IRType::I64);
            assert!(matches!(get_expr, Expr::Get { offset: 16, .. }));

            let add_expr = Expr::add(
                IRType::I64,
                Expr::const_u64(10),
                Expr::const_u64(20),
            );
            assert!(matches!(add_expr, Expr::BinOp { op: BinOp::Add, .. }));
        }
    }

    #[test]
    fn test_stmt_builders() {
        unsafe {
            let imark = Stmt::imark(0x1000, 5);
            assert!(matches!(imark, Stmt::IMark { addr: 0x1000, len: 5 }));

            let wr_tmp = Stmt::wr_tmp(Temp::new(1), Expr::const_u64(42));
            assert!(matches!(wr_tmp, Stmt::WrTmp { .. }));

            let put = Stmt::put(8, Expr::temp(1));
            assert!(matches!(put, Stmt::Put { offset: 8, .. }));

            let store = Stmt::store(Expr::const_u64(0x1000), Expr::const_u64(0xFF));
            assert!(matches!(store, Stmt::Store { .. }));
        }
    }

    #[test]
    fn test_binop_variants() {
        unsafe {
            let ops = vec![
                BinOp::Add, BinOp::Sub, BinOp::Mul,
                BinOp::And, BinOp::Or, BinOp::Xor,
                BinOp::CmpEQ, BinOp::CmpNE,
            ];
            assert_eq!(ops.len(), 8);
        }
    }
}
