//! Symbolic Value Types
//!
//! Core types for representing symbolic and concrete values in symbolic execution.

use serde::{Serialize, Deserialize};
use std::fmt;

/// Unique identifier for symbolic values
pub type SymbolId = u64;

/// Symbolic or concrete value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// Concrete bitvector value
    Concrete {
        /// Bit width
        width: usize,
        /// Concrete value
        value: u128,
    },
    
    /// Symbolic value
    Symbolic {
        /// Bit width
        width: usize,
        /// Symbolic expression
        expr: Box<SymExpr>,
    },
}

/// Symbolic expression tree
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SymExpr {
    /// Symbolic variable with unique identifier
    Symbol {
        id: SymbolId,
        name: String,
        width: usize,
    },
    
    /// Concrete constant
    Constant {
        width: usize,
        value: u128,
    },
    
    /// Binary operation
    BinOp {
        op: SymBinOp,
        left: Box<SymExpr>,
        right: Box<SymExpr>,
    },
    
    /// Unary operation
    UnOp {
        op: SymUnOp,
        arg: Box<SymExpr>,
    },
    
    /// Extract bits [high:low]
    Extract {
        high: usize,
        low: usize,
        arg: Box<SymExpr>,
    },
    
    /// Concatenate bitvectors
    Concat {
        left: Box<SymExpr>,
        right: Box<SymExpr>,
    },
    
    /// Zero extend
    ZeroExt {
        bits: usize,
        arg: Box<SymExpr>,
    },
    
    /// Sign extend
    SignExt {
        bits: usize,
        arg: Box<SymExpr>,
    },
    
    /// If-then-else
    ITE {
        cond: Box<SymExpr>,
        if_true: Box<SymExpr>,
        if_false: Box<SymExpr>,
    },
}

/// Symbolic binary operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymBinOp {
    // Arithmetic
    Add, Sub, Mul, UDiv, SDiv, URem, SRem,
    
    // Bitwise
    And, Or, Xor, Shl, LShr, AShr,
    
    // Comparison (return 1-bit result)
    Eq, Ne, ULT, ULE, UGT, UGE, SLT, SLE, SGT, SGE,
}

/// Symbolic unary operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymUnOp {
    Not, Neg,
}

impl Value {
    /// Create a concrete value
    ///
    pub fn concrete(width: usize, value: u128) -> Self {
        unsafe {
            Value::Concrete { width, value }
        }
    }
    
    /// Create a symbolic value from an expression
    ///
    pub fn symbolic(width: usize, expr: SymExpr) -> Self {
        unsafe {
            Value::Symbolic { width, expr: Box::new(expr) }
        }
    }
    
    /// Create a new symbolic variable
    ///
    pub fn symbol(id: SymbolId, name: String, width: usize) -> Self {
        unsafe {
            Value::symbolic(width, SymExpr::Symbol { id, name, width })
        }
    }
    
    /// Get the bit width of this value
    ///
    pub fn width(&self) -> usize {
        unsafe {
            match self {
                Value::Concrete { width, .. } => *width,
                Value::Symbolic { width, .. } => *width,
            }
        }
    }
    
    /// Check if this value is concrete
    ///
    pub fn is_concrete(&self) -> bool {
        unsafe {
            matches!(self, Value::Concrete { .. })
        }
    }
    
    /// Check if this value is symbolic
    ///
    pub fn is_symbolic(&self) -> bool {
        unsafe {
            matches!(self, Value::Symbolic { .. })
        }
    }
    
    /// Try to get the concrete value
    ///
    pub fn as_concrete(&self) -> Option<u128> {
        unsafe {
            match self {
                Value::Concrete { value, .. } => Some(*value),
                _ => None,
            }
        }
    }
    
    /// Add two values
    ///
    pub fn add(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { width: w2, value: v2 }) => {
                    assert_eq!(w1, w2, "Width mismatch in add");
                    let result = v1.wrapping_add(*v2);
                    let mask = Self::mask(*w1);
                    Value::concrete(*w1, result & mask)
                }
                _ => {
                    let width = self.width();
                    let expr = SymExpr::BinOp {
                        op: SymBinOp::Add,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    };
                    Value::symbolic(width, expr)
                }
            }
        }
    }
    
    /// Subtract two values
    ///
    pub fn sub(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { width: w2, value: v2 }) => {
                    assert_eq!(w1, w2, "Width mismatch in sub");
                    let result = v1.wrapping_sub(*v2);
                    let mask = Self::mask(*w1);
                    Value::concrete(*w1, result & mask)
                }
                _ => {
                    let width = self.width();
                    let expr = SymExpr::BinOp {
                        op: SymBinOp::Sub,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    };
                    Value::symbolic(width, expr)
                }
            }
        }
    }
    
    /// Bitwise AND
    ///
    pub fn and(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { width: w2, value: v2 }) => {
                    assert_eq!(w1, w2, "Width mismatch in and");
                    Value::concrete(*w1, v1 & v2)
                }
                _ => {
                    let width = self.width();
                    let expr = SymExpr::BinOp {
                        op: SymBinOp::And,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    };
                    Value::symbolic(width, expr)
                }
            }
        }
    }
    
    /// Get bitmask for width
    ///
    fn mask(width: usize) -> u128 {
        unsafe {
            if width >= 128 {
                u128::MAX
            } else {
                (1u128 << width) - 1
            }
        }
    }
    
    /// Convert to symbolic expression
    ///
    pub fn to_expr(&self) -> SymExpr {
        unsafe {
            match self {
                Value::Concrete { width, value } => SymExpr::Constant { width: *width, value: *value },
                Value::Symbolic { expr, .. } => (**expr).clone(),
            }
        }
    }
    
    /// Convert value to bytes (little-endian)
    ///
    pub fn to_bytes(&self) -> Vec<u8> {
        unsafe {
            if let Value::Concrete { value, width } = self {
                let num_bytes = (*width + 7) / 8;
                let mut bytes = Vec::with_capacity(num_bytes);
                for i in 0..num_bytes {
                    bytes.push(((value >> (i * 8)) & 0xFF) as u8);
                }
                bytes
            } else {
                // Symbolic value - return zeros as placeholder
                vec![0u8; (self.width() + 7) / 8]
            }
        }
    }
    
    /// Create value from bytes (little-endian)
    ///
    pub fn from_bytes(bytes: &[Value], width: usize) -> Value {
        unsafe {
            // Check if all bytes are concrete
            let all_concrete = bytes.iter().all(|b| b.is_concrete());
            
            if all_concrete {
                let mut value: u128 = 0;
                for (i, byte) in bytes.iter().enumerate() {
                    if let Some(b) = byte.as_concrete() {
                        value |= (b & 0xFF) << (i * 8);
                    }
                }
                Value::concrete(width, value)
            } else {
                // Build symbolic expression from bytes
                let mut expr = bytes[0].to_expr();
                for byte in &bytes[1..] {
                    expr = SymExpr::Concat {
                        left: Box::new(byte.to_expr()),
                        right: Box::new(expr),
                    };
                }
                Value::symbolic(width, expr)
            }
        }
    }
    
    /// Multiply two values
    ///
    pub fn mul(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { width: w2, value: v2 }) => {
                    assert_eq!(w1, w2);
                    let result = v1.wrapping_mul(*v2);
                    let mask = Self::mask(*w1);
                    Value::concrete(*w1, result & mask)
                }
                _ => {
                    Value::symbolic(self.width(), SymExpr::BinOp {
                        op: SymBinOp::Mul,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Unsigned division
    ///
    pub fn udiv(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { width: w2, value: v2 }) => {
                    assert_eq!(w1, w2);
                    if *v2 == 0 {
                        Value::concrete(*w1, 0)
                    } else {
                        Value::concrete(*w1, v1 / v2)
                    }
                }
                _ => {
                    Value::symbolic(self.width(), SymExpr::BinOp {
                        op: SymBinOp::UDiv,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Signed division
    ///
    pub fn sdiv(&self, other: &Value) -> Value {
        unsafe {
            Value::symbolic(self.width(), SymExpr::BinOp {
                op: SymBinOp::SDiv,
                left: Box::new(self.to_expr()),
                right: Box::new(other.to_expr()),
            })
        }
    }
    
    /// Unsigned remainder
    ///
    pub fn urem(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { width: w2, value: v2 }) => {
                    assert_eq!(w1, w2);
                    if *v2 == 0 {
                        Value::concrete(*w1, 0)
                    } else {
                        Value::concrete(*w1, v1 % v2)
                    }
                }
                _ => {
                    Value::symbolic(self.width(), SymExpr::BinOp {
                        op: SymBinOp::URem,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Signed remainder
    ///
    pub fn srem(&self, other: &Value) -> Value {
        unsafe {
            Value::symbolic(self.width(), SymExpr::BinOp {
                op: SymBinOp::SRem,
                left: Box::new(self.to_expr()),
                right: Box::new(other.to_expr()),
            })
        }
    }
    
    /// Bitwise OR
    ///
    pub fn or(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { width: w2, value: v2 }) => {
                    assert_eq!(w1, w2);
                    Value::concrete(*w1, v1 | v2)
                }
                _ => {
                    Value::symbolic(self.width(), SymExpr::BinOp {
                        op: SymBinOp::Or,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Bitwise XOR
    ///
    pub fn xor(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { width: w2, value: v2 }) => {
                    assert_eq!(w1, w2);
                    Value::concrete(*w1, v1 ^ v2)
                }
                _ => {
                    Value::symbolic(self.width(), SymExpr::BinOp {
                        op: SymBinOp::Xor,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Left shift
    ///
    pub fn shl(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { value: v2, .. }) => {
                    let result = v1.wrapping_shl(*v2 as u32);
                    let mask = Self::mask(*w1);
                    Value::concrete(*w1, result & mask)
                }
                _ => {
                    Value::symbolic(self.width(), SymExpr::BinOp {
                        op: SymBinOp::Shl,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Logical right shift
    ///
    pub fn lshr(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { width: w1, value: v1 }, Value::Concrete { value: v2, .. }) => {
                    Value::concrete(*w1, v1.wrapping_shr(*v2 as u32))
                }
                _ => {
                    Value::symbolic(self.width(), SymExpr::BinOp {
                        op: SymBinOp::LShr,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Arithmetic right shift
    ///
    pub fn ashr(&self, other: &Value) -> Value {
        unsafe {
            Value::symbolic(self.width(), SymExpr::BinOp {
                op: SymBinOp::AShr,
                left: Box::new(self.to_expr()),
                right: Box::new(other.to_expr()),
            })
        }
    }
    
    /// Bitwise NOT
    ///
    pub fn not(&self) -> Value {
        unsafe {
            match self {
                Value::Concrete { width, value } => {
                    let mask = Self::mask(*width);
                    Value::concrete(*width, (!value) & mask)
                }
                _ => {
                    Value::symbolic(self.width(), SymExpr::UnOp {
                        op: SymUnOp::Not,
                        arg: Box::new(self.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Negation
    ///
    pub fn neg(&self) -> Value {
        unsafe {
            match self {
                Value::Concrete { width, value } => {
                    let result = value.wrapping_neg();
                    let mask = Self::mask(*width);
                    Value::concrete(*width, result & mask)
                }
                _ => {
                    Value::symbolic(self.width(), SymExpr::UnOp {
                        op: SymUnOp::Neg,
                        arg: Box::new(self.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Equality comparison
    ///
    pub fn eq(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { value: v1, .. }, Value::Concrete { value: v2, .. }) => {
                    Value::concrete(1, if v1 == v2 { 1 } else { 0 })
                }
                _ => {
                    Value::symbolic(1, SymExpr::BinOp {
                        op: SymBinOp::Eq,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Inequality comparison
    ///
    pub fn ne(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { value: v1, .. }, Value::Concrete { value: v2, .. }) => {
                    Value::concrete(1, if v1 != v2 { 1 } else { 0 })
                }
                _ => {
                    Value::symbolic(1, SymExpr::BinOp {
                        op: SymBinOp::Ne,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Unsigned less-than
    ///
    pub fn ult(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { value: v1, .. }, Value::Concrete { value: v2, .. }) => {
                    Value::concrete(1, if v1 < v2 { 1 } else { 0 })
                }
                _ => {
                    Value::symbolic(1, SymExpr::BinOp {
                        op: SymBinOp::ULT,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Unsigned less-equal
    ///
    pub fn ule(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { value: v1, .. }, Value::Concrete { value: v2, .. }) => {
                    Value::concrete(1, if v1 <= v2 { 1 } else { 0 })
                }
                _ => {
                    Value::symbolic(1, SymExpr::BinOp {
                        op: SymBinOp::ULE,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Unsigned greater-than
    ///
    pub fn ugt(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { value: v1, .. }, Value::Concrete { value: v2, .. }) => {
                    Value::concrete(1, if v1 > v2 { 1 } else { 0 })
                }
                _ => {
                    Value::symbolic(1, SymExpr::BinOp {
                        op: SymBinOp::UGT,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Unsigned greater-equal
    ///
    pub fn uge(&self, other: &Value) -> Value {
        unsafe {
            match (self, other) {
                (Value::Concrete { value: v1, .. }, Value::Concrete { value: v2, .. }) => {
                    Value::concrete(1, if v1 >= v2 { 1 } else { 0 })
                }
                _ => {
                    Value::symbolic(1, SymExpr::BinOp {
                        op: SymBinOp::UGE,
                        left: Box::new(self.to_expr()),
                        right: Box::new(other.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Signed less-than
    ///
    pub fn slt(&self, other: &Value) -> Value {
        unsafe {
            Value::symbolic(1, SymExpr::BinOp {
                op: SymBinOp::SLT,
                left: Box::new(self.to_expr()),
                right: Box::new(other.to_expr()),
            })
        }
    }
    
    /// Signed less-equal
    ///
    pub fn sle(&self, other: &Value) -> Value {
        unsafe {
            Value::symbolic(1, SymExpr::BinOp {
                op: SymBinOp::SLE,
                left: Box::new(self.to_expr()),
                right: Box::new(other.to_expr()),
            })
        }
    }
    
    /// Signed greater-than
    ///
    pub fn sgt(&self, other: &Value) -> Value {
        unsafe {
            Value::symbolic(1, SymExpr::BinOp {
                op: SymBinOp::SGT,
                left: Box::new(self.to_expr()),
                right: Box::new(other.to_expr()),
            })
        }
    }
    
    /// Signed greater-equal
    ///
    pub fn sge(&self, other: &Value) -> Value {
        unsafe {
            Value::symbolic(1, SymExpr::BinOp {
                op: SymBinOp::SGE,
                left: Box::new(self.to_expr()),
                right: Box::new(other.to_expr()),
            })
        }
    }
    
    /// Zero-extend to new width
    ///
    pub fn zero_extend(&self, new_width: usize) -> Value {
        unsafe {
            if new_width <= self.width() {
                return self.clone();
            }
            
            match self {
                Value::Concrete { value, .. } => Value::concrete(new_width, *value),
                _ => {
                    let bits = new_width - self.width();
                    Value::symbolic(new_width, SymExpr::ZeroExt {
                        bits,
                        arg: Box::new(self.to_expr()),
                    })
                }
            }
        }
    }
    
    /// Sign-extend to new width
    ///
    pub fn sign_extend(&self, new_width: usize) -> Value {
        unsafe {
            if new_width <= self.width() {
                return self.clone();
            }
            
            let bits = new_width - self.width();
            Value::symbolic(new_width, SymExpr::SignExt {
                bits,
                arg: Box::new(self.to_expr()),
            })
        }
    }
    
    /// Extract bits [high:low]
    ///
    pub fn extract(&self, high: usize, low: usize) -> Value {
        unsafe {
            let new_width = high - low + 1;
            match self {
                Value::Concrete { value, .. } => {
                    let extracted = (value >> low) & Self::mask(new_width);
                    Value::concrete(new_width, extracted)
                }
                _ => {
                    Value::symbolic(new_width, SymExpr::Extract {
                        high,
                        low,
                        arg: Box::new(self.to_expr()),
                    })
                }
            }
        }
    }
}

impl SymExpr {
    /// Get the bit width of this expression
    ///
    pub fn width(&self) -> usize {
        unsafe {
            match self {
                SymExpr::Symbol { width, .. } => *width,
                SymExpr::Constant { width, .. } => *width,
                SymExpr::BinOp { left, .. } => left.width(),
                SymExpr::UnOp { arg, .. } => arg.width(),
                SymExpr::Extract { high, low, .. } => high - low + 1,
                SymExpr::Concat { left, right } => left.width() + right.width(),
                SymExpr::ZeroExt { bits, arg } => arg.width() + bits,
                SymExpr::SignExt { bits, arg } => arg.width() + bits,
                SymExpr::ITE { if_true, .. } => if_true.width(),
            }
        }
    }
    
    /// Simplify this expression
    ///
    pub fn simplify(&self) -> SymExpr {
        unsafe {
            match self {
                SymExpr::BinOp { op, left, right } => {
                    let left_simp = left.simplify();
                    let right_simp = right.simplify();
                    
                    // Try to evaluate if both are constants
                    if let (SymExpr::Constant { value: v1, width: w1 }, SymExpr::Constant { value: v2, width: w2 }) 
                        = (&left_simp, &right_simp) {
                        if let Some(result) = Self::eval_binop(*op, *w1, *v1, *v2) {
                            return SymExpr::Constant { width: *w1, value: result };
                        }
                    }
                    
                    SymExpr::BinOp {
                        op: *op,
                        left: Box::new(left_simp),
                        right: Box::new(right_simp),
                    }
                }
                _ => self.clone(),
            }
        }
    }
    
    /// Evaluate a binary operation on constants
    ///
    fn eval_binop(op: SymBinOp, width: usize, left: u128, right: u128) -> Option<u128> {
        unsafe {
            let mask = if width >= 128 { u128::MAX } else { (1u128 << width) - 1 };
            let result = match op {
                SymBinOp::Add => left.wrapping_add(right),
                SymBinOp::Sub => left.wrapping_sub(right),
                SymBinOp::Mul => left.wrapping_mul(right),
                SymBinOp::And => left & right,
                SymBinOp::Or => left | right,
                SymBinOp::Xor => left ^ right,
                SymBinOp::Shl => left.wrapping_shl(right as u32),
                SymBinOp::LShr => left.wrapping_shr(right as u32),
                SymBinOp::Eq => if left == right { 1 } else { 0 },
                SymBinOp::Ne => if left != right { 1 } else { 0 },
                SymBinOp::ULT => if left < right { 1 } else { 0 },
                _ => return None,
            };
            Some(result & mask)
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            match self {
                Value::Concrete { width, value } => write!(f, "0x{:x}<{}>", value, width),
                Value::Symbolic { width, expr } => write!(f, "{}<{}>", expr, width),
            }
        }
    }
}

impl fmt::Display for SymExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            match self {
                SymExpr::Symbol { name, .. } => write!(f, "{}", name),
                SymExpr::Constant { value, .. } => write!(f, "0x{:x}", value),
                SymExpr::BinOp { op, left, right } => write!(f, "({} {:?} {})", left, op, right),
                SymExpr::UnOp { op, arg } => write!(f, "({:?} {})", op, arg),
                SymExpr::Extract { high, low, arg } => write!(f, "{}[{}:{}]", arg, high, low),
                SymExpr::Concat { left, right } => write!(f, "({} ++ {})", left, right),
                SymExpr::ZeroExt { bits, arg } => write!(f, "zext({}, {})", bits, arg),
                SymExpr::SignExt { bits, arg } => write!(f, "sext({}, {})", bits, arg),
                SymExpr::ITE { cond, if_true, if_false } => write!(f, "(if {} then {} else {})", cond, if_true, if_false),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concrete_value() {
        unsafe {
            let v = Value::concrete(32, 42);
            assert!(v.is_concrete());
            assert_eq!(v.width(), 32);
            assert_eq!(v.as_concrete(), Some(42));
        }
    }

    #[test]
    fn test_symbolic_value() {
        unsafe {
            let v = Value::symbol(1, "x".to_string(), 64);
            assert!(v.is_symbolic());
            assert_eq!(v.width(), 64);
        }
    }

    #[test]
    fn test_concrete_add() {
        unsafe {
            let a = Value::concrete(32, 10);
            let b = Value::concrete(32, 20);
            let c = a.add(&b);
            assert_eq!(c.as_concrete(), Some(30));
        }
    }

    #[test]
    fn test_symbolic_add() {
        unsafe {
            let a = Value::symbol(1, "x".to_string(), 32);
            let b = Value::concrete(32, 5);
            let c = a.add(&b);
            assert!(c.is_symbolic());
        }
    }
}
