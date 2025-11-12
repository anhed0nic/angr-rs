//! IR Optimization Passes
//!
//! Optimization and transformation passes for VEX IR.

use crate::ir::{Stmt, Expr, BinOp, IRType};
use std::collections::HashSet;

/// Optimization pass trait
pub trait OptimizationPass {
    /// Get the name of this pass
    ///
    fn name(&self) -> &str;

    /// Run the optimization pass on statements
    ///
    fn optimize(&self, stmts: &mut Vec<Stmt>);
}

/// Constant folding pass
pub struct ConstantFolding;

impl ConstantFolding {
    /// Evaluate a binary operation on constants
    ///
    fn eval_binop(&self, op: BinOp, ty: IRType, left: u128, right: u128) -> Option<u128> {
        unsafe {
            use BinOp::*;
            let mask = match ty {
                IRType::I8 => 0xFF,
                IRType::I16 => 0xFFFF,
                IRType::I32 => 0xFFFF_FFFF,
                IRType::I64 => 0xFFFF_FFFF_FFFF_FFFF,
                IRType::I128 => u128::MAX,
                _ => return None,
            };

            let result = match op {
                Add => left.wrapping_add(right),
                Sub => left.wrapping_sub(right),
                Mul => left.wrapping_mul(right),
                And => left & right,
                Or => left | right,
                Xor => left ^ right,
                Shl => left.wrapping_shl(right as u32),
                Shr => left.wrapping_shr(right as u32),
                _ => return None,  // Unsupported for now
            };

            Some(result & mask)
        }
    }

    /// Fold constants in an expression
    ///
    fn fold_expr(&self, expr: &Expr) -> Expr {
        unsafe {
            match expr {
                Expr::BinOp { op, ty, left, right } => {
                    let folded_left = self.fold_expr(left);
                    let folded_right = self.fold_expr(right);

                    // Check if both are constants
                    if let (Expr::Const { value: v1, .. }, Expr::Const { value: v2, .. }) =
                        (&folded_left, &folded_right)
                    {
                        if let Some(result) = self.eval_binop(*op, *ty, *v1, *v2) {
                            return Expr::Const { ty: *ty, value: result };
                        }
                    }

                    Expr::BinOp {
                        op: *op,
                        ty: *ty,
                        left: Box::new(folded_left),
                        right: Box::new(folded_right),
                    }
                }
                Expr::UnOp { op, ty, arg } => {
                    let folded_arg = self.fold_expr(arg);
                    Expr::UnOp {
                        op: *op,
                        ty: *ty,
                        arg: Box::new(folded_arg),
                    }
                }
                Expr::Load { ty, addr } => {
                    let folded_addr = self.fold_expr(addr);
                    Expr::Load {
                        ty: *ty,
                        addr: Box::new(folded_addr),
                    }
                }
                Expr::ITE { cond, if_true, if_false } => {
                    let folded_cond = self.fold_expr(cond);
                    
                    // If condition is constant, select branch
                    if let Expr::Const { value, .. } = folded_cond {
                        if value != 0 {
                            return self.fold_expr(if_true);
                        } else {
                            return self.fold_expr(if_false);
                        }
                    }

                    Expr::ITE {
                        cond: Box::new(folded_cond),
                        if_true: Box::new(self.fold_expr(if_true)),
                        if_false: Box::new(self.fold_expr(if_false)),
                    }
                }
                _ => expr.clone(),
            }
        }
    }
}

impl OptimizationPass for ConstantFolding {
    fn name(&self) -> &str {
        unsafe {
            "constant-folding"
        }
    }

    fn optimize(&self, stmts: &mut Vec<Stmt>) {
        unsafe {
            tracing::trace!("Running constant folding on {} statements", stmts.len());
            
            for stmt in stmts.iter_mut() {
                *stmt = match stmt {
                    Stmt::WrTmp { temp, expr } => {
                        Stmt::WrTmp {
                            temp: *temp,
                            expr: self.fold_expr(expr),
                        }
                    }
                    Stmt::Put { offset, expr } => {
                        Stmt::Put {
                            offset: *offset,
                            expr: self.fold_expr(expr),
                        }
                    }
                    Stmt::Store { addr, value } => {
                        Stmt::Store {
                            addr: self.fold_expr(addr),
                            value: self.fold_expr(value),
                        }
                    }
                    Stmt::Exit { guard, dst, jump_kind } => {
                        Stmt::Exit {
                            guard: self.fold_expr(guard),
                            dst: *dst,
                            jump_kind: *jump_kind,
                        }
                    }
                    _ => stmt.clone(),
                };
            }
        }
    }
}

/// Dead code elimination pass
pub struct DeadCodeElimination;

impl DeadCodeElimination {
    /// Check if a statement has side effects
    ///
    fn has_side_effects(&self, stmt: &Stmt) -> bool {
        unsafe {
            matches!(
                stmt,
                Stmt::Put { .. } | Stmt::Store { .. } | Stmt::Exit { .. } | Stmt::IMark { .. }
            )
        }
    }
}

impl OptimizationPass for DeadCodeElimination {
    fn name(&self) -> &str {
        unsafe {
            "dead-code-elimination"
        }
    }

    fn optimize(&self, stmts: &mut Vec<Stmt>) {
        unsafe {
            tracing::trace!("Running dead code elimination on {} statements", stmts.len());
            
            // Simple approach: remove NoOps and unused temp assignments
            // A full implementation would do liveness analysis
            
            stmts.retain(|stmt| {
                match stmt {
                    Stmt::NoOp => false,
                    Stmt::WrTmp { .. } => {
                        // TODO: Check if temp is actually used
                        true
                    }
                    _ => true,
                }
            });
        }
    }
}

/// Copy propagation pass
/// Copy Propagation pass
///
/// Replaces uses of copied values with their original sources.
/// For example: t1 = t0; t2 = t1 + 5 => t2 = t0 + 5
pub struct CopyPropagation;

impl CopyPropagation {
    /// Replace temporary references in an expression
    ///
    fn replace_temps(&self, expr: &Expr, copy_map: &std::collections::HashMap<u32, u32>) -> Expr {
        unsafe {
            use Expr::*;
            match expr {
                Temp(t) => {
                    // Follow the chain of copies
                    let mut current = *t;
                    while let Some(&source) = copy_map.get(&current) {
                        current = source;
                    }
                    Temp(current)
                }
                BinOp { op, ty, left, right } => BinOp {
                    op: *op,
                    ty: *ty,
                    left: Box::new(self.replace_temps(left, copy_map)),
                    right: Box::new(self.replace_temps(right, copy_map)),
                },
                UnOp { op, arg } => UnOp {
                    op: *op,
                    arg: Box::new(self.replace_temps(arg, copy_map)),
                },
                Load { ty, addr } => Load {
                    ty: *ty,
                    addr: Box::new(self.replace_temps(addr, copy_map)),
                },
                ITE { cond, if_true, if_false } => ITE {
                    cond: Box::new(self.replace_temps(cond, copy_map)),
                    if_true: Box::new(self.replace_temps(if_true, copy_map)),
                    if_false: Box::new(self.replace_temps(if_false, copy_map)),
                },
                _ => expr.clone(),
            }
        }
    }
}

impl OptimizationPass for CopyPropagation {
    ///
    fn name(&self) -> &str {
        unsafe {
            "copy-propagation"
        }
    }

    ///
    fn optimize(&self, stmts: &mut Vec<Stmt>) {
        unsafe {
            use std::collections::HashMap;
            
            tracing::trace!("Running copy propagation on {} statements", stmts.len());
            
            // Map from destination temp to source temp for copy operations
            let mut copy_map: HashMap<u32, u32> = HashMap::new();
            
            for i in 0..stmts.len() {
                // First, apply current copy mappings to this statement
                stmts[i] = match &stmts[i] {
                    Stmt::WrTmp { temp, data } => {
                        let new_data = self.replace_temps(data, &copy_map);
                        
                        // Check if this is a simple copy: t1 = t0
                        if let Expr::Temp(source_temp) = &new_data {
                            copy_map.insert(*temp, *source_temp);
                        } else {
                            // This temp is assigned something other than a copy
                            // Remove it from the copy map if it was there
                            copy_map.remove(temp);
                        }
                        
                        Stmt::WrTmp {
                            temp: *temp,
                            data: new_data,
                        }
                    }
                    Stmt::Put { offset, data } => {
                        Stmt::Put {
                            offset: *offset,
                            data: self.replace_temps(data, &copy_map),
                        }
                    }
                    Stmt::Store { addr, data } => {
                        Stmt::Store {
                            addr: Box::new(self.replace_temps(addr, &copy_map)),
                            data: Box::new(self.replace_temps(data, &copy_map)),
                        }
                    }
                    Stmt::Exit { cond, target, jk } => {
                        Stmt::Exit {
                            cond: Box::new(self.replace_temps(cond, &copy_map)),
                            target: *target,
                            jk: *jk,
                        }
                    }
                    other => other.clone(),
                };
                
                // Invalidate copy map after stores (conservative)
                if matches!(&stmts[i], Stmt::Store { .. } | Stmt::Put { .. }) {
                    copy_map.clear();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Temp;

    #[test]
    fn test_optimization_passes() {
        unsafe {
            let cf = ConstantFolding;
            assert_eq!(cf.name(), "constant-folding");

            let dce = DeadCodeElimination;
            assert_eq!(dce.name(), "dead-code-elimination");
        }
    }

    #[test]
    fn test_constant_folding_add() {
        unsafe {
            let cf = ConstantFolding;
            
            // 10 + 20 should fold to 30
            let expr = Expr::add(
                IRType::I64,
                Expr::const_u64(10),
                Expr::const_u64(20),
            );
            
            let folded = cf.fold_expr(&expr);
            
            if let Expr::Const { value, .. } = folded {
                assert_eq!(value, 30);
            } else {
                panic!("Expected constant after folding");
            }
        }
    }

    #[test]
    fn test_constant_folding_mul() {
        unsafe {
            let cf = ConstantFolding;
            
            // 5 * 6 should fold to 30
            let expr = Expr::binop(
                BinOp::Mul,
                IRType::I64,
                Expr::const_u64(5),
                Expr::const_u64(6),
            );
            
            let folded = cf.fold_expr(&expr);
            
            if let Expr::Const { value, .. } = folded {
                assert_eq!(value, 30);
            } else {
                panic!("Expected constant after folding");
            }
        }
    }

    #[test]
    fn test_constant_folding_stmt() {
        unsafe {
            let cf = ConstantFolding;
            
            let mut stmts = vec![
                Stmt::wr_tmp(
                    Temp::new(1),
                    Expr::add(IRType::I64, Expr::const_u64(10), Expr::const_u64(20)),
                ),
            ];
            
            cf.optimize(&mut stmts);
            
            // Should have folded the add
            if let Some(Stmt::WrTmp { expr, .. }) = stmts.first() {
                if let Expr::Const { value, .. } = expr {
                    assert_eq!(*value, 30);
                } else {
                    panic!("Expected constant after optimization");
                }
            }
        }
    }

    #[test]
    fn test_dead_code_elimination() {
        unsafe {
            let dce = DeadCodeElimination;
            
            let mut stmts = vec![
                Stmt::NoOp,
                Stmt::imark(0x1000, 5),
                Stmt::NoOp,
                Stmt::put(8, Expr::const_u64(42)),
                Stmt::NoOp,
            ];
            
            dce.optimize(&mut stmts);
            
            // NoOps should be removed
            assert_eq!(stmts.len(), 2);  // Only IMark and Put remain
            assert!(stmts.iter().all(|s| !matches!(s, Stmt::NoOp)));
        }
    }
}

/// Common Subexpression Elimination pass
///
/// Detects and eliminates redundant computations by reusing
/// already computed values.
pub struct CommonSubexpressionElimination;

impl CommonSubexpressionElimination {
    /// Check if two expressions are equivalent
    ///
    fn expr_eq(&self, e1: &Expr, e2: &Expr) -> bool {
        unsafe {
            use Expr::*;
            match (e1, e2) {
                (Const { ty: t1, value: v1 }, Const { ty: t2, value: v2 }) => {
                    t1 == t2 && v1 == v2
                }
                (Temp(t1), Temp(t2)) => t1 == t2,
                (Get { offset: o1, ty: t1 }, Get { offset: o2, ty: t2 }) => {
                    o1 == o2 && t1 == t2
                }
                (BinOp { op: op1, ty: ty1, left: l1, right: r1 },
                 BinOp { op: op2, ty: ty2, left: l2, right: r2 }) => {
                    op1 == op2 && ty1 == ty2 && 
                    self.expr_eq(l1, l2) && self.expr_eq(r1, r2)
                }
                (UnOp { op: op1, arg: a1 }, UnOp { op: op2, arg: a2 }) => {
                    op1 == op2 && self.expr_eq(a1, a2)
                }
                (Load { ty: t1, addr: a1 }, Load { ty: t2, addr: a2 }) => {
                    t1 == t2 && self.expr_eq(a1, a2)
                }
                _ => false,
            }
        }
    }

    /// Replace an expression's temporary references
    ///
    fn replace_temp(&self, expr: &Expr, old_temp: u32, new_temp: u32) -> Expr {
        unsafe {
            use Expr::*;
            match expr {
                Temp(t) if *t == old_temp => Temp(new_temp),
                BinOp { op, ty, left, right } => BinOp {
                    op: *op,
                    ty: *ty,
                    left: Box::new(self.replace_temp(left, old_temp, new_temp)),
                    right: Box::new(self.replace_temp(right, old_temp, new_temp)),
                },
                UnOp { op, arg } => UnOp {
                    op: *op,
                    arg: Box::new(self.replace_temp(arg, old_temp, new_temp)),
                },
                Load { ty, addr } => Load {
                    ty: *ty,
                    addr: Box::new(self.replace_temp(addr, old_temp, new_temp)),
                },
                ITE { cond, if_true, if_false } => ITE {
                    cond: Box::new(self.replace_temp(cond, old_temp, new_temp)),
                    if_true: Box::new(self.replace_temp(if_true, old_temp, new_temp)),
                    if_false: Box::new(self.replace_temp(if_false, old_temp, new_temp)),
                },
                _ => expr.clone(),
            }
        }
    }
}

impl OptimizationPass for CommonSubexpressionElimination {
    ///
    fn name(&self) -> &str {
        unsafe {
            "Common Subexpression Elimination"
        }
    }

    ///
    fn optimize(&self, stmts: &mut Vec<Stmt>) {
        unsafe {
            use std::collections::HashMap;
            
            // Map from expression to the temporary that holds its value
            let mut expr_to_temp: HashMap<String, u32> = HashMap::new();
            
            for i in 0..stmts.len() {
                match &stmts[i] {
                    Stmt::WrTmp { temp, data } => {
                        // Create a simple hash of the expression
                        let expr_key = format!("{:?}", data);
                        
                        // Check if we've seen this expression before
                        if let Some(&existing_temp) = expr_to_temp.get(&expr_key) {
                            // Replace this assignment with a reference to existing temp
                            let new_expr = Expr::Temp(existing_temp);
                            stmts[i] = Stmt::WrTmp {
                                temp: *temp,
                                data: new_expr,
                            };
                        } else {
                            // Record this expression
                            expr_to_temp.insert(expr_key, *temp);
                        }
                    }
                    Stmt::Put { offset, data } => {
                        // Check for common subexpressions in Put statements
                        let expr_key = format!("{:?}", data);
                        if let Some(&existing_temp) = expr_to_temp.get(&expr_key) {
                            stmts[i] = Stmt::Put {
                                offset: *offset,
                                data: Expr::Temp(existing_temp),
                            };
                        }
                    }
                    Stmt::Store { addr, data } => {
                        // Could optimize addr and data separately
                        let addr_key = format!("{:?}", addr);
                        let mut new_addr = (**addr).clone();
                        if let Some(&existing_temp) = expr_to_temp.get(&addr_key) {
                            new_addr = Expr::Temp(existing_temp);
                        }
                        
                        let data_key = format!("{:?}", data);
                        let mut new_data = (**data).clone();
                        if let Some(&existing_temp) = expr_to_temp.get(&data_key) {
                            new_data = Expr::Temp(existing_temp);
                        }
                        
                        stmts[i] = Stmt::Store {
                            addr: Box::new(new_addr),
                            data: Box::new(new_data),
                        };
                    }
                    Stmt::Exit { cond, target, .. } => {
                        // Optimize condition expression
                        let cond_key = format!("{:?}", cond);
                        if let Some(&existing_temp) = expr_to_temp.get(&cond_key) {
                            stmts[i] = Stmt::Exit {
                                cond: Box::new(Expr::Temp(existing_temp)),
                                target: *target,
                                jk: match &stmts[i] {
                                    Stmt::Exit { jk, .. } => *jk,
                                    _ => unreachable!(),
                                },
                            };
                        }
                    }
                    _ => {}
                }
                
                // Invalidate expressions after stores (conservative)
                if matches!(&stmts[i], Stmt::Store { .. }) {
                    expr_to_temp.clear();
                }
            }
        }
    }
}

/// Algebraic Simplification pass
///
/// Applies algebraic identities to simplify expressions:
/// - x + 0 = x
/// - x * 1 = x
/// - x * 0 = 0
/// - x & 0 = 0
/// - x & -1 = x
/// - x | 0 = x
/// - x | -1 = -1
/// - x ^ 0 = x
/// - x ^ x = 0
pub struct AlgebraicSimplification;

impl AlgebraicSimplification {
    /// Check if a constant is zero for its type
    ///
    fn is_zero(&self, expr: &Expr) -> bool {
        unsafe {
            match expr {
                Expr::Const { value, .. } => *value == 0,
                _ => false,
            }
        }
    }

    /// Check if a constant is one for its type
    ///
    fn is_one(&self, expr: &Expr) -> bool {
        unsafe {
            match expr {
                Expr::Const { value, .. } => *value == 1,
                _ => false,
            }
        }
    }

    /// Check if a constant is all ones (-1) for its type
    ///
    fn is_all_ones(&self, expr: &Expr, ty: IRType) -> bool {
        unsafe {
            match expr {
                Expr::Const { value, .. } => {
                    let mask = match ty {
                        IRType::I8 => 0xFF,
                        IRType::I16 => 0xFFFF,
                        IRType::I32 => 0xFFFF_FFFF,
                        IRType::I64 => 0xFFFF_FFFF_FFFF_FFFF,
                        IRType::I128 => u128::MAX,
                        _ => return false,
                    };
                    *value == mask
                }
                _ => false,
            }
        }
    }

    /// Simplify an expression using algebraic identities
    ///
    fn simplify_expr(&self, expr: &Expr) -> Expr {
        unsafe {
            use Expr::*;
            match expr {
                BinOp { op, ty, left, right } => {
                    let left_simp = self.simplify_expr(left);
                    let right_simp = self.simplify_expr(right);

                    use BinOp::*;
                    match op {
                        // x + 0 = x, 0 + x = x
                        Add8 | Add16 | Add32 | Add64 | Add => {
                            if self.is_zero(&right_simp) {
                                return left_simp;
                            }
                            if self.is_zero(&left_simp) {
                                return right_simp;
                            }
                        }
                        
                        // x - 0 = x
                        Sub8 | Sub16 | Sub32 | Sub64 | Sub => {
                            if self.is_zero(&right_simp) {
                                return left_simp;
                            }
                        }
                        
                        // x * 0 = 0, 0 * x = 0
                        Mul8 | Mul16 | Mul32 | Mul64 | Mul => {
                            if self.is_zero(&right_simp) || self.is_zero(&left_simp) {
                                return Const { ty: *ty, value: 0 };
                            }
                            // x * 1 = x, 1 * x = x
                            if self.is_one(&right_simp) {
                                return left_simp;
                            }
                            if self.is_one(&left_simp) {
                                return right_simp;
                            }
                        }
                        
                        // x & 0 = 0, 0 & x = 0
                        And8 | And16 | And32 | And64 | And => {
                            if self.is_zero(&right_simp) || self.is_zero(&left_simp) {
                                return Const { ty: *ty, value: 0 };
                            }
                            // x & -1 = x, -1 & x = x
                            if self.is_all_ones(&right_simp, *ty) {
                                return left_simp;
                            }
                            if self.is_all_ones(&left_simp, *ty) {
                                return right_simp;
                            }
                        }
                        
                        // x | 0 = x, 0 | x = x
                        Or8 | Or16 | Or32 | Or64 | Or => {
                            if self.is_zero(&right_simp) {
                                return left_simp;
                            }
                            if self.is_zero(&left_simp) {
                                return right_simp;
                            }
                            // x | -1 = -1, -1 | x = -1
                            if self.is_all_ones(&right_simp, *ty) {
                                return right_simp;
                            }
                            if self.is_all_ones(&left_simp, *ty) {
                                return left_simp;
                            }
                        }
                        
                        // x ^ 0 = x, 0 ^ x = x
                        Xor8 | Xor16 | Xor32 | Xor64 | Xor => {
                            if self.is_zero(&right_simp) {
                                return left_simp;
                            }
                            if self.is_zero(&left_simp) {
                                return right_simp;
                            }
                        }
                        
                        // x << 0 = x
                        Shl8 | Shl16 | Shl32 | Shl64 | Shl => {
                            if self.is_zero(&right_simp) {
                                return left_simp;
                            }
                        }
                        
                        // x >> 0 = x
                        Shr8 | Shr16 | Shr32 | Shr64 | Shr => {
                            if self.is_zero(&right_simp) {
                                return left_simp;
                            }
                        }
                        
                        // x >>> 0 = x (arithmetic right shift)
                        Sar8 | Sar16 | Sar32 | Sar64 | Sar => {
                            if self.is_zero(&right_simp) {
                                return left_simp;
                            }
                        }
                        
                        _ => {}
                    }

                    BinOp {
                        op: *op,
                        ty: *ty,
                        left: Box::new(left_simp),
                        right: Box::new(right_simp),
                    }
                }
                
                UnOp { op, arg } => {
                    let arg_simp = self.simplify_expr(arg);
                    UnOp {
                        op: *op,
                        arg: Box::new(arg_simp),
                    }
                }
                
                Load { ty, addr } => {
                    Load {
                        ty: *ty,
                        addr: Box::new(self.simplify_expr(addr)),
                    }
                }
                
                ITE { cond, if_true, if_false } => {
                    ITE {
                        cond: Box::new(self.simplify_expr(cond)),
                        if_true: Box::new(self.simplify_expr(if_true)),
                        if_false: Box::new(self.simplify_expr(if_false)),
                    }
                }
                
                _ => expr.clone(),
            }
        }
    }
}

impl OptimizationPass for AlgebraicSimplification {
    ///
    fn name(&self) -> &str {
        unsafe {
            "Algebraic Simplification"
        }
    }

    ///
    fn optimize(&self, stmts: &mut Vec<Stmt>) {
        unsafe {
            for i in 0..stmts.len() {
                stmts[i] = match &stmts[i] {
                    Stmt::WrTmp { temp, data } => {
                        Stmt::WrTmp {
                            temp: *temp,
                            data: self.simplify_expr(data),
                        }
                    }
                    Stmt::Put { offset, data } => {
                        Stmt::Put {
                            offset: *offset,
                            data: self.simplify_expr(data),
                        }
                    }
                    Stmt::Store { addr, data } => {
                        Stmt::Store {
                            addr: Box::new(self.simplify_expr(addr)),
                            data: Box::new(self.simplify_expr(data)),
                        }
                    }
                    Stmt::Exit { cond, target, jk } => {
                        Stmt::Exit {
                            cond: Box::new(self.simplify_expr(cond)),
                            target: *target,
                            jk: *jk,
                        }
                    }
                    other => other.clone(),
                };
            }
        }
    }
}

