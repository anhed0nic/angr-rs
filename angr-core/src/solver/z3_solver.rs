//! Z3 SMT Solver Implementation

use super::{Model, Solver, SolverResult};
use crate::symbolic::{Constraint, SymBinOp, SymExpr, SymUnOp, Value};
use std::collections::HashMap;
use z3::ast::{Ast, Bool, BV};
use z3::{Config, Context, SatResult};

/// Z3-based constraint solver
pub struct Z3Solver<'ctx> {
    ctx: &'ctx Context,
    solver: z3::Solver<'ctx>,
    /// Cache of symbolic expressions to Z3 bitvectors
    expr_cache: HashMap<String, BV<'ctx>>,
}

impl<'ctx> Z3Solver<'ctx> {
    /// Create a new Z3 solver with the given context
    ///
    pub unsafe fn new(ctx: &'ctx Context) -> Self {
        let solver = z3::Solver::new(ctx);
        Self {
            ctx,
            solver,
            expr_cache: HashMap::new(),
        }
    }
    
    /// Create a new Z3 solver with a fresh context
    ///
    pub unsafe fn new_with_context() -> (Context, Self) {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = z3::Solver::new(&ctx);
        
        // Create solver with borrowed context
        // Note: This is a simplified version - in production you'd use
        // a different ownership pattern
        let z3_solver = Self {
            ctx: unsafe { &*(&ctx as *const Context) },
            solver,
            expr_cache: HashMap::new(),
        };
        
        (ctx, z3_solver)
    }
    
    /// Convert a symbolic expression to a Z3 bitvector
    ///
    pub unsafe fn expr_to_bv(&mut self, expr: &SymExpr) -> BV<'ctx> {
        match expr {
            SymExpr::Constant { value, width } => {
                BV::from_u64(self.ctx, *value as u64, *width as u32)
            }
            
            SymExpr::Symbol { id, name: _, width } => {
                let name = format!("sym_{}", id);
                // Check cache first
                if let Some(bv) = self.expr_cache.get(&name) {
                    return bv.clone();
                }
                
                let bv = BV::new_const(self.ctx, name.clone(), *width as u32);
                self.expr_cache.insert(name, bv.clone());
                bv
            }
            
            SymExpr::BinOp { op, left, right } => {
                let left_bv = self.expr_to_bv(left);
                let right_bv = self.expr_to_bv(right);
                
                match op {
                    SymBinOp::Add => left_bv.bvadd(&right_bv),
                    SymBinOp::Sub => left_bv.bvsub(&right_bv),
                    SymBinOp::Mul => left_bv.bvmul(&right_bv),
                    SymBinOp::UDiv => left_bv.bvudiv(&right_bv),
                    SymBinOp::SDiv => left_bv.bvsdiv(&right_bv),
                    SymBinOp::URem => left_bv.bvurem(&right_bv),
                    SymBinOp::SRem => left_bv.bvsrem(&right_bv),
                    SymBinOp::And => left_bv.bvand(&right_bv),
                    SymBinOp::Or => left_bv.bvor(&right_bv),
                    SymBinOp::Xor => left_bv.bvxor(&right_bv),
                    SymBinOp::Shl => left_bv.bvshl(&right_bv),
                    SymBinOp::LShr => left_bv.bvlshr(&right_bv),
                    SymBinOp::AShr => left_bv.bvashr(&right_bv),
                    // Comparisons return 1-bit bitvectors
                    SymBinOp::Eq => {
                        let bool_expr = left_bv._eq(&right_bv);
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                    SymBinOp::Ne => {
                        let bool_expr = left_bv._eq(&right_bv).not();
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                    SymBinOp::ULT => {
                        let bool_expr = left_bv.bvult(&right_bv);
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                    SymBinOp::ULE => {
                        let bool_expr = left_bv.bvule(&right_bv);
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                    SymBinOp::UGT => {
                        let bool_expr = left_bv.bvugt(&right_bv);
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                    SymBinOp::UGE => {
                        let bool_expr = left_bv.bvuge(&right_bv);
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                    SymBinOp::SLT => {
                        let bool_expr = left_bv.bvslt(&right_bv);
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                    SymBinOp::SLE => {
                        let bool_expr = left_bv.bvsle(&right_bv);
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                    SymBinOp::SGT => {
                        let bool_expr = left_bv.bvsgt(&right_bv);
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                    SymBinOp::SGE => {
                        let bool_expr = left_bv.bvsge(&right_bv);
                        bool_expr.ite(&BV::from_u64(self.ctx, 1, 1), &BV::from_u64(self.ctx, 0, 1))
                    }
                }
            }
            
            SymExpr::UnOp { op, arg } => {
                let operand_bv = self.expr_to_bv(arg);
                
                match op {
                    SymUnOp::Not => operand_bv.bvnot(),
                    SymUnOp::Neg => operand_bv.bvneg(),
                }
            }
            
            SymExpr::Extract { arg, high, low } => {
                let expr_bv = self.expr_to_bv(arg);
                expr_bv.extract(*high as u32, *low as u32)
            }
            
            SymExpr::ZeroExt { arg, bits } => {
                let expr_bv = self.expr_to_bv(arg);
                expr_bv.zero_ext(*bits as u32)
            }
            
            SymExpr::SignExt { arg, bits } => {
                let expr_bv = self.expr_to_bv(arg);
                expr_bv.sign_ext(*bits as u32)
            }
            
            SymExpr::ITE { cond, if_true, if_false } => {
                let cond_bv = self.expr_to_bv(cond);
                let true_bv = self.expr_to_bv(if_true);
                let false_bv = self.expr_to_bv(if_false);
                
                // Convert 1-bit bitvector to boolean
                let zero = BV::from_u64(self.ctx, 0, cond.width() as u32);
                let bool_cond = cond_bv._eq(&zero).not();
                
                bool_cond.ite(&true_bv, &false_bv)
            }
            
            SymExpr::Concat { left, right } => {
                let left_bv = self.expr_to_bv(left);
                let right_bv = self.expr_to_bv(right);
                left_bv.concat(&right_bv)
            }
        }
    }
    
    /// Convert a constraint to a Z3 boolean
    ///
    pub unsafe fn constraint_to_bool(&mut self, constraint: &Constraint) -> Bool<'ctx> {
        let bv = self.expr_to_bv(constraint.expr());
        // Constraint is satisfied when the expression is non-zero
        let zero = BV::from_u64(self.ctx, 0, constraint.expr().width() as u32);
        bv._eq(&zero).not()
    }
}

impl<'ctx> Solver for Z3Solver<'ctx> {
    unsafe fn is_sat(&mut self, constraints: &[Constraint]) -> SolverResult {
        // Reset solver
        self.solver.reset();
        self.expr_cache.clear();
        
        // Add all constraints
        for constraint in constraints {
            let bool_expr = self.constraint_to_bool(constraint);
            self.solver.assert(&bool_expr);
        }
        
        // Check satisfiability
        match self.solver.check() {
            SatResult::Sat => SolverResult::Sat,
            SatResult::Unsat => SolverResult::Unsat,
            SatResult::Unknown => SolverResult::Unknown,
        }
    }
    
    unsafe fn get_model(&mut self, constraints: &[Constraint]) -> Option<Model> {
        // Check if satisfiable
        if self.is_sat(constraints) != SolverResult::Sat {
            return None;
        }
        
        let z3_model = self.solver.get_model()?;
        let mut model = Model::new();
        
        // Extract values for all symbols in the expression cache
        for (name, bv) in &self.expr_cache {
            if let Some(value) = z3_model.eval(bv, true) {
                if let Some(val_bv) = value.as_bv() {
                    if let Some(val_u64) = val_bv.as_u64() {
                        // Extract symbol ID from name "sym_N"
                        if let Some(id_str) = name.strip_prefix("sym_") {
                            if let Ok(id) = id_str.parse::<usize>() {
                                model.insert(id, val_u64);
                            }
                        }
                    }
                }
            }
        }
        
        Some(model)
    }
    
    unsafe fn eval(&mut self, expr: &SymExpr, constraints: &[Constraint]) -> Option<Value> {
        // Add constraints
        self.solver.reset();
        self.expr_cache.clear();
        
        for constraint in constraints {
            let bool_expr = self.constraint_to_bool(constraint);
            self.solver.assert(&bool_expr);
        }
        
        // Check if satisfiable
        if self.solver.check() != SatResult::Sat {
            return None;
        }
        
        // Evaluate expression
        let bv = self.expr_to_bv(expr);
        let z3_model = self.solver.get_model()?;
        
        if let Some(value) = z3_model.eval(&bv, true) {
            if let Some(val_bv) = value.as_bv() {
                if let Some(val_u64) = val_bv.as_u64() {
                    return Some(Value::concrete(val_u64, expr.width()));
                }
            }
        }
        
        None
    }
    
    unsafe fn prove_equal(&mut self, expr1: &SymExpr, expr2: &SymExpr, constraints: &[Constraint]) -> bool {
        self.solver.reset();
        self.expr_cache.clear();
        
        // Add constraints
        for constraint in constraints {
            let bool_expr = self.constraint_to_bool(constraint);
            self.solver.assert(&bool_expr);
        }
        
        // Add negation of expr1 == expr2
        let bv1 = self.expr_to_bv(expr1);
        let bv2 = self.expr_to_bv(expr2);
        let not_equal = bv1._eq(&bv2).not();
        self.solver.assert(&not_equal);
        
        // If unsat, then expr1 == expr2 is always true
        matches!(self.solver.check(), SatResult::Unsat)
    }
    
    unsafe fn simplify(&mut self, expr: &SymExpr) -> SymExpr {
        // For now, return the original expression
        // Full simplification would use Z3's simplify tactics
        expr.clone()
    }
    
    unsafe fn reset(&mut self) {
        self.solver.reset();
        self.expr_cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic::{Constraint, SymExpr, Value};

    #[test]
    fn test_z3_solver_creation() {
        unsafe {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let _solver = Z3Solver::new(&ctx);
        }
    }

    #[test]
    fn test_simple_constraint_sat() {
        unsafe {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let mut solver = Z3Solver::new(&ctx);
            
            // x == 42
            let x = SymExpr::Symbol { id: 0, name: "x".to_string(), width: 32 };
            let val = SymExpr::Constant { width: 32, value: 42 };
            let eq = SymExpr::BinOp {
                op: SymBinOp::Eq,
                left: Box::new(x),
                right: Box::new(val),
            };
            
            let constraint = Constraint::new(eq);
            let result = solver.is_sat(&[constraint]);
            
            assert_eq!(result, SolverResult::Sat);
        }
    }

    #[test]
    fn test_unsatisfiable_constraint() {
        unsafe {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let mut solver = Z3Solver::new(&ctx);
            
            // x == 42 AND x == 43 (impossible)
            let x = SymExpr::Symbol { id: 0, name: "x".to_string(), width: 32 };
            let val1 = SymExpr::Constant { width: 32, value: 42 };
            let val2 = SymExpr::Constant { width: 32, value: 43 };
            
            let eq1 = SymExpr::BinOp {
                op: SymBinOp::Eq,
                left: Box::new(x.clone()),
                right: Box::new(val1),
            };
            let eq2 = SymExpr::BinOp {
                op: SymBinOp::Eq,
                left: Box::new(x),
                right: Box::new(val2),
            };
            
            let constraints = vec![Constraint::new(eq1), Constraint::new(eq2)];
            let result = solver.is_sat(&constraints);
            
            assert_eq!(result, SolverResult::Unsat);
        }
    }

    #[test]
    fn test_get_model() {
        unsafe {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let mut solver = Z3Solver::new(&ctx);
            
            // x > 100
            let x = SymExpr::Symbol { id: 0, name: "x".to_string(), width: 32 };
            let val = SymExpr::Constant { width: 32, value: 100 };
            let gt = SymExpr::BinOp {
                op: SymBinOp::UGT,
                left: Box::new(x),
                right: Box::new(val),
            };
            
            let constraint = Constraint::new(gt);
            let model = solver.get_model(&[constraint]);
            
            assert!(model.is_some());
            let model = model.unwrap();
            let x_value = model.get(0);
            assert!(x_value.is_some());
            assert!(x_value.unwrap() > 100);
        }
    }

    #[test]
    fn test_arithmetic_operations() {
        unsafe {
            let cfg = Config::new();
            let ctx = Context::new(&cfg);
            let mut solver = Z3Solver::new(&ctx);
            
            // x + 10 == 42
            let x = SymExpr::Symbol { id: 0, name: "x".to_string(), width: 32 };
            let ten = SymExpr::Constant { width: 32, value: 10 };
            let fortytwo = SymExpr::Constant { width: 32, value: 42 };
            
            let add = SymExpr::BinOp {
                op: SymBinOp::Add,
                left: Box::new(x),
                right: Box::new(ten),
            };
            
            let eq = SymExpr::BinOp {
                op: SymBinOp::Eq,
                left: Box::new(add),
                right: Box::new(fortytwo),
            };
            
            let constraint = Constraint::new(eq);
            let model = solver.get_model(&[constraint]);
            
            assert!(model.is_some());
            let model = model.unwrap();
            assert_eq!(model.get(0), Some(32)); // x should be 32
        }
    }
}
