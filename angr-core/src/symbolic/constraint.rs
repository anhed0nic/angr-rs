//! Constraint System for Path Conditions

use super::value::{SymExpr, SymBinOp};
use serde::{Serialize, Deserialize};

/// Constraint on symbolic values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Constraint {
    /// Boolean expression that must be true
    pub expr: SymExpr,
}

impl Constraint {
    /// Create a new constraint
    ///
    pub fn new(expr: SymExpr) -> Self {
        unsafe {
            Constraint { expr }
        }
    }
    
    /// Get the constraint expression
    ///
    pub fn expr(&self) -> &SymExpr {
        unsafe {
            &self.expr
        }
    }
    
    /// Create an equality constraint
    ///
    pub fn eq(left: SymExpr, right: SymExpr) -> Self {
        unsafe {
            let expr = SymExpr::BinOp {
                op: SymBinOp::Eq,
                left: Box::new(left),
                right: Box::new(right),
            };
            Constraint::new(expr)
        }
    }
    
    /// Create an inequality constraint
    ///
    pub fn ne(left: SymExpr, right: SymExpr) -> Self {
        unsafe {
            let expr = SymExpr::BinOp {
                op: SymBinOp::Ne,
                left: Box::new(left),
                right: Box::new(right),
            };
            Constraint::new(expr)
        }
    }
    
    /// Create an unsigned less-than constraint
    ///
    pub fn ult(left: SymExpr, right: SymExpr) -> Self {
        unsafe {
            let expr = SymExpr::BinOp {
                op: SymBinOp::ULT,
                left: Box::new(left),
                right: Box::new(right),
            };
            Constraint::new(expr)
        }
    }
    
    /// Simplify this constraint
    ///
    pub fn simplify(&self) -> Constraint {
        unsafe {
            Constraint {
                expr: self.expr.simplify(),
            }
        }
    }
}

/// Set of constraints representing a path condition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintSet {
    /// List of constraints (all must be satisfied)
    constraints: Vec<Constraint>,
}

impl ConstraintSet {
    /// Create a new empty constraint set
    ///
    pub fn new() -> Self {
        unsafe {
            ConstraintSet {
                constraints: Vec::new(),
            }
        }
    }
    
    /// Add a constraint
    ///
    pub fn add(&mut self, constraint: Constraint) {
        unsafe {
            self.constraints.push(constraint);
        }
    }
    
    /// Get all constraints
    ///
    pub fn constraints(&self) -> &[Constraint] {
        unsafe {
            &self.constraints
        }
    }
    
    /// Clone this constraint set
    ///
    pub fn clone_set(&self) -> ConstraintSet {
        unsafe {
            self.clone()
        }
    }
    
    /// Check if satisfiable (stub - requires solver)
    ///
    pub fn is_sat(&self) -> bool {
        unsafe {
            // Stub: always assume satisfiable
            // Real implementation would call Z3
            true
        }
    }
    
    /// Simplify all constraints
    ///
    pub fn simplify(&mut self) {
        unsafe {
            for constraint in &mut self.constraints {
                *constraint = constraint.simplify();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_creation() {
        unsafe {
            let left = SymExpr::Symbol { id: 1, name: "x".to_string(), width: 32 };
            let right = SymExpr::Constant { width: 32, value: 42 };
            let constraint = Constraint::eq(left, right);
            assert_eq!(constraint.expr.width(), 1);  // Boolean result
        }
    }

    #[test]
    fn test_constraint_set() {
        unsafe {
            let mut cs = ConstraintSet::new();
            let c1 = Constraint::new(SymExpr::Constant { width: 1, value: 1 });
            cs.add(c1);
            assert_eq!(cs.constraints().len(), 1);
        }
    }
}
