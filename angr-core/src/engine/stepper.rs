//! Symbolic Execution Stepper
//!
//! This module provides the core symbolic execution engine that evaluates
//! VEX IR statements symbolically, updating SimState and handling control flow.

use crate::symbolic::{Constraint, SimState, SymBinOp, SymExpr, SymUnOp, Value};
use std::collections::HashMap;
use vex_core::ir::{BinOp, Expr, IRType, JumpKind, Stmt, Temp, UnOp};

/// Result of executing a single step
#[derive(Debug, Clone)]
pub enum StepResult {
    /// Continue execution normally
    Continue,
    /// Branch to address (unconditional)
    Jump { target: u64 },
    /// Conditional branch - state should be split
    ConditionalBranch {
        condition: SymExpr,
        true_target: u64,
        false_target: u64,
    },
    /// Function call
    Call { target: u64, return_addr: u64 },
    /// Function return
    Return,
    /// System call
    Syscall { number: Value },
    /// Execution ended (deadended)
    Halt,
    /// Error during execution
    Error { message: String },
}

/// Symbolic execution stepper
pub struct SymbolicStepper {
    /// Temporary variable storage (within a single basic block)
    temps: HashMap<u32, Value>,
    /// Current instruction address
    current_addr: u64,
    /// Length of current instruction
    current_len: u32,
}

impl SymbolicStepper {
    /// Create a new symbolic stepper
    ///
    pub unsafe fn new() -> Self {
        Self {
            temps: HashMap::new(),
            current_addr: 0,
            current_len: 0,
        }
    }

    /// Execute a single VEX IR statement on the given state
    ///
    pub unsafe fn step(&mut self, state: &mut SimState, stmt: &Stmt) -> StepResult {
        match stmt {
            Stmt::NoOp => StepResult::Continue,

            Stmt::IMark { addr, len } => {
                self.current_addr = *addr;
                self.current_len = *len;
                StepResult::Continue
            }

            Stmt::WrTmp { temp, expr } => {
                match self.eval_expr(state, expr) {
                    Ok(value) => {
                        self.temps.insert(temp.id(), value);
                        StepResult::Continue
                    }
                    Err(e) => StepResult::Error { message: e },
                }
            }

            Stmt::Put { offset, expr } => {
                match self.eval_expr(state, expr) {
                    Ok(value) => {
                        state.write_register(*offset, value);
                        StepResult::Continue
                    }
                    Err(e) => StepResult::Error { message: e },
                }
            }

            Stmt::Store { addr, value } => {
                match (self.eval_expr(state, addr), self.eval_expr(state, value)) {
                    (Ok(addr_val), Ok(value_val)) => {
                        // Convert address to u64 if concrete
                        if let Value::Concrete { value: addr_concrete, .. } = addr_val {
                            state.write_memory(addr_concrete as u64, &value_val.to_bytes());
                            StepResult::Continue
                        } else {
                            // Symbolic address - for now, error
                            StepResult::Error {
                                message: "Symbolic memory addresses not yet supported".to_string(),
                            }
                        }
                    }
                    (Err(e), _) | (_, Err(e)) => StepResult::Error { message: e },
                }
            }

            Stmt::LoadG { dst, addr, alt, guard } => {
                // Guarded load: if guard is true, load from addr, else use alt
                match (
                    self.eval_expr(state, guard),
                    self.eval_expr(state, addr),
                    self.eval_expr(state, alt),
                ) {
                    (Ok(guard_val), Ok(addr_val), Ok(alt_val)) => {
                        // Create ITE: if guard then load(addr) else alt
                        if let Value::Concrete { value: addr_concrete, width } = addr_val {
                            let loaded = state.read_memory(addr_concrete as u64, width / 8);
                            let loaded_val = Value::from_bytes(&loaded, width);

                            // ITE based on guard
                            let result = if let Value::Concrete { value: g, .. } = guard_val {
                                if g != 0 {
                                    loaded_val
                                } else {
                                    alt_val
                                }
                            } else {
                                // Symbolic guard - create ITE expression
                                let guard_expr = guard_val.to_expr();
                                let true_expr = loaded_val.to_expr();
                                let false_expr = alt_val.to_expr();
                                Value::symbolic(
                                    SymExpr::ITE {
                                        cond: Box::new(guard_expr),
                                        if_true: Box::new(true_expr),
                                        if_false: Box::new(false_expr),
                                    },
                                    width,
                                )
                            };

                            self.temps.insert(dst.id(), result);
                            StepResult::Continue
                        } else {
                            StepResult::Error {
                                message: "Symbolic address in LoadG not supported".to_string(),
                            }
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                        StepResult::Error { message: e }
                    }
                }
            }

            Stmt::StoreG { addr, value, guard } => {
                // Guarded store: if guard is true, store value to addr
                match (
                    self.eval_expr(state, guard),
                    self.eval_expr(state, addr),
                    self.eval_expr(state, value),
                ) {
                    (Ok(guard_val), Ok(addr_val), Ok(value_val)) => {
                        if let Value::Concrete { value: g, .. } = guard_val {
                            if g != 0 {
                                if let Value::Concrete { value: addr_concrete, .. } = addr_val {
                                    state.write_memory(
                                        addr_concrete as u64,
                                        &value_val.to_bytes(),
                                    );
                                }
                            }
                            StepResult::Continue
                        } else {
                            // Symbolic guard - this is complex, skip for now
                            StepResult::Error {
                                message: "Symbolic guards in StoreG not yet supported".to_string(),
                            }
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                        StepResult::Error { message: e }
                    }
                }
            }

            Stmt::CAS { addr, expected, new_value, old_temp } => {
                // Compare-and-swap: atomically compare *addr with expected,
                // if equal, store new_value; return old value
                match (
                    self.eval_expr(state, addr),
                    self.eval_expr(state, expected),
                    self.eval_expr(state, new_value),
                ) {
                    (Ok(addr_val), Ok(expected_val), Ok(new_val)) => {
                        if let Value::Concrete { value: addr_concrete, width } = addr_val {
                            let old_bytes = state.read_memory(addr_concrete as u64, width / 8);
                            let old_val = Value::from_bytes(&old_bytes, width);

                            // Check if old == expected
                            let eq = old_val.eq(&expected_val);
                            if let Value::Concrete { value: eq_val, .. } = eq {
                                if eq_val != 0 {
                                    state.write_memory(addr_concrete as u64, &new_val.to_bytes());
                                }
                            }

                            self.temps.insert(old_temp.id(), old_val);
                            StepResult::Continue
                        } else {
                            StepResult::Error {
                                message: "Symbolic address in CAS not supported".to_string(),
                            }
                        }
                    }
                    (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                        StepResult::Error { message: e }
                    }
                }
            }

            Stmt::MBE { .. } => {
                // Memory barrier - no-op for symbolic execution
                StepResult::Continue
            }

            Stmt::Exit { guard, dst, jump_kind } => {
                match self.eval_expr(state, guard) {
                    Ok(guard_val) => {
                        // Check if this is a conditional or unconditional exit
                        if let Value::Concrete { value, .. } = guard_val {
                            if value != 0 {
                                // Guard is true - take the exit
                                self.handle_jump(*dst, *jump_kind)
                            } else {
                                // Guard is false - continue
                                StepResult::Continue
                            }
                        } else {
                            // Symbolic guard - this is a conditional branch
                            let next_addr = self.current_addr + self.current_len as u64;
                            StepResult::ConditionalBranch {
                                condition: guard_val.to_expr(),
                                true_target: *dst,
                                false_target: next_addr,
                            }
                        }
                    }
                    Err(e) => StepResult::Error { message: e },
                }
            }
        }
    }

    /// Execute a block of statements
    ///
    pub unsafe fn step_block(&mut self, state: &mut SimState, stmts: &[Stmt]) -> StepResult {
        for stmt in stmts {
            let result = self.step(state, stmt);
            match result {
                StepResult::Continue => continue,
                other => return other,
            }
        }
        
        // Update PC to next instruction
        let next_addr = self.current_addr + self.current_len as u64;
        state.set_pc(next_addr);
        StepResult::Jump { target: next_addr }
    }

    /// Evaluate a VEX IR expression to a symbolic value
    ///
    pub unsafe fn eval_expr(&self, state: &SimState, expr: &Expr) -> Result<Value, String> {
        match expr {
            Expr::Const { ty, value } => {
                Ok(Value::concrete(ty.bits(), *value))
            }

            Expr::Temp(temp) => self
                .temps
                .get(&temp.id())
                .cloned()
                .ok_or_else(|| format!("Undefined temporary: t{}", temp.id())),

            Expr::Get { offset, ty } => {
                Ok(state.read_register(*offset).unwrap_or_else(|| {
                    // Register not initialized - create symbolic
                    state.new_symbol(ty.bits())
                }))
            }

            Expr::Load { ty, addr } => {
                let addr_val = self.eval_expr(state, addr)?;
                if let Value::Concrete { value: addr_concrete, .. } = addr_val {
                    let bytes = state.read_memory(addr_concrete as u64, ty.bytes());
                    Ok(Value::from_bytes(&bytes, ty.bits()))
                } else {
                    Err("Symbolic memory addresses not yet supported".to_string())
                }
            }

            Expr::BinOp { op, ty, left, right } => {
                let left_val = self.eval_expr(state, left)?;
                let right_val = self.eval_expr(state, right)?;
                Ok(self.eval_binop(*op, left_val, right_val, ty.bits()))
            }

            Expr::UnOp { op, ty, arg } => {
                let arg_val = self.eval_expr(state, arg)?;
                Ok(self.eval_unop(*op, arg_val, ty.bits()))
            }

            Expr::ITE { cond, if_true, if_false } => {
                let cond_val = self.eval_expr(state, cond)?;
                let true_val = self.eval_expr(state, if_true)?;
                let false_val = self.eval_expr(state, if_false)?;

                if let Value::Concrete { value, .. } = cond_val {
                    if value != 0 {
                        Ok(true_val)
                    } else {
                        Ok(false_val)
                    }
                } else {
                    // Symbolic condition - create ITE expression
                    let width = true_val.width();
                    Ok(Value::symbolic(
                        SymExpr::ITE {
                            cond: Box::new(cond_val.to_expr()),
                            if_true: Box::new(true_val.to_expr()),
                            if_false: Box::new(false_val.to_expr()),
                        },
                        width,
                    ))
                }
            }

            Expr::CCall { name, ret_ty, args } => {
                // Helper functions - for now, return symbolic
                Err(format!("CCall to {} not yet implemented", name))
            }

            Expr::Mux0X { cond, expr0, exprX } => {
                let cond_val = self.eval_expr(state, cond)?;
                let val0 = self.eval_expr(state, expr0)?;
                let valX = self.eval_expr(state, exprX)?;

                if let Value::Concrete { value, .. } = cond_val {
                    if value == 0 {
                        Ok(val0)
                    } else {
                        Ok(valX)
                    }
                } else {
                    // Symbolic - treat as ITE
                    let zero = Value::concrete(cond_val.width(), 0);
                    let cond_eq_zero = cond_val.eq(&zero);
                    let width = val0.width();
                    Ok(Value::symbolic(
                        SymExpr::ITE {
                            cond: Box::new(cond_eq_zero.to_expr()),
                            if_true: Box::new(val0.to_expr()),
                            if_false: Box::new(valX.to_expr()),
                        },
                        width,
                    ))
                }
            }
        }
    }

    /// Evaluate a binary operation
    ///
    unsafe fn eval_binop(&self, op: BinOp, left: Value, right: Value, result_width: usize) -> Value {
        let sym_op = match op {
            BinOp::Add => SymBinOp::Add,
            BinOp::Sub => SymBinOp::Sub,
            BinOp::Mul => SymBinOp::Mul,
            BinOp::DivU => SymBinOp::UDiv,
            BinOp::DivS => SymBinOp::SDiv,
            BinOp::ModU => SymBinOp::URem,
            BinOp::ModS => SymBinOp::SRem,
            BinOp::And => SymBinOp::And,
            BinOp::Or => SymBinOp::Or,
            BinOp::Xor => SymBinOp::Xor,
            BinOp::Shl => SymBinOp::Shl,
            BinOp::Shr => SymBinOp::LShr,
            BinOp::Sar => SymBinOp::AShr,
            BinOp::CmpEQ => SymBinOp::Eq,
            BinOp::CmpNE => SymBinOp::Ne,
            BinOp::CmpLT_U => SymBinOp::ULT,
            BinOp::CmpLE_U => SymBinOp::ULE,
            BinOp::CmpLT_S => SymBinOp::SLT,
            BinOp::CmpLE_S => SymBinOp::SLE,
            BinOp::Max | BinOp::Min | BinOp::MullU | BinOp::MullS => {
                // For complex ops, create symbolic result
                return Value::symbolic(
                    SymExpr::BinOp {
                        op: SymBinOp::Add, // Placeholder
                        left: Box::new(left.to_expr()),
                        right: Box::new(right.to_expr()),
                    },
                    result_width,
                );
            }
        };

        match sym_op {
            SymBinOp::Add => left.add(&right),
            SymBinOp::Sub => left.sub(&right),
            SymBinOp::Mul => left.mul(&right),
            SymBinOp::UDiv => left.udiv(&right),
            SymBinOp::SDiv => left.sdiv(&right),
            SymBinOp::URem => left.urem(&right),
            SymBinOp::SRem => left.srem(&right),
            SymBinOp::And => left.and(&right),
            SymBinOp::Or => left.or(&right),
            SymBinOp::Xor => left.xor(&right),
            SymBinOp::Shl => left.shl(&right),
            SymBinOp::LShr => left.lshr(&right),
            SymBinOp::AShr => left.ashr(&right),
            SymBinOp::Eq => left.eq(&right),
            SymBinOp::Ne => left.ne(&right),
            SymBinOp::ULT => left.ult(&right),
            SymBinOp::ULE => left.ule(&right),
            SymBinOp::UGT => left.ugt(&right),
            SymBinOp::UGE => left.uge(&right),
            SymBinOp::SLT => left.slt(&right),
            SymBinOp::SLE => left.sle(&right),
            SymBinOp::SGT => left.sgt(&right),
            SymBinOp::SGE => left.sge(&right),
        }
    }

    /// Evaluate a unary operation
    ///
    unsafe fn eval_unop(&self, op: UnOp, arg: Value, result_width: usize) -> Value {
        match op {
            UnOp::Not => arg.not(),
            UnOp::Neg => arg.neg(),
            UnOp::Widen { from_bits, signed } => {
                if signed {
                    arg.sign_extend(result_width)
                } else {
                    arg.zero_extend(result_width)
                }
            }
            UnOp::Narrow { to_bits } => {
                // Extract lower bits
                arg.extract(to_bits - 1, 0)
            }
            UnOp::Clz | UnOp::Ctz => {
                // For complex operations, return symbolic
                Value::symbolic(
                    SymExpr::UnOp {
                        op: SymUnOp::Not, // Placeholder
                        arg: Box::new(arg.to_expr()),
                    },
                    result_width,
                )
            }
        }
    }

    /// Handle different jump kinds
    ///
    unsafe fn handle_jump(&self, target: u64, kind: JumpKind) -> StepResult {
        match kind {
            JumpKind::Boring => StepResult::Jump { target },
            JumpKind::Call => StepResult::Call {
                target,
                return_addr: self.current_addr + self.current_len as u64,
            },
            JumpKind::Ret => StepResult::Return,
            JumpKind::Conditional => StepResult::Jump { target },
            JumpKind::Syscall => {
                // System call number typically in a register (e.g., rax on x86_64)
                StepResult::Syscall {
                    number: Value::concrete(64, 0), // Placeholder
                }
            }
        }
    }

    /// Reset temporary storage (call between basic blocks)
    ///
    pub unsafe fn reset_temps(&mut self) {
        self.temps.clear();
    }

    /// Get current instruction address
    ///
    pub unsafe fn current_address(&self) -> u64 {
        self.current_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stepper_creation() {
        unsafe {
            let stepper = SymbolicStepper::new();
            assert_eq!(stepper.current_addr, 0);
            assert_eq!(stepper.temps.len(), 0);
        }
    }

    #[test]
    fn test_eval_const() {
        unsafe {
            let stepper = SymbolicStepper::new();
            let state = SimState::new(0x1000, 256);
            let expr = Expr::Const {
                ty: IRType::I64,
                value: 42,
            };

            let result = stepper.eval_expr(&state, &expr);
            assert!(result.is_ok());
            if let Value::Concrete { value, width } = result.unwrap() {
                assert_eq!(value, 42);
                assert_eq!(width, 64);
            } else {
                panic!("Expected concrete value");
            }
        }
    }

    #[test]
    fn test_eval_binop_add() {
        unsafe {
            let stepper = SymbolicStepper::new();
            let state = SimState::new(0x1000, 256);
            let expr = Expr::BinOp {
                op: BinOp::Add,
                ty: IRType::I32,
                left: Box::new(Expr::Const {
                    ty: IRType::I32,
                    value: 10,
                }),
                right: Box::new(Expr::Const {
                    ty: IRType::I32,
                    value: 20,
                }),
            };

            let result = stepper.eval_expr(&state, &expr);
            assert!(result.is_ok());
            if let Value::Concrete { value, width } = result.unwrap() {
                assert_eq!(value, 30);
                assert_eq!(width, 32);
            } else {
                panic!("Expected concrete value");
            }
        }
    }

    #[test]
    fn test_step_imark() {
        unsafe {
            let mut stepper = SymbolicStepper::new();
            let mut state = SimState::new(0x1000, 256);
            let stmt = Stmt::IMark { addr: 0x2000, len: 5 };

            let result = stepper.step(&mut state, &stmt);
            assert!(matches!(result, StepResult::Continue));
            assert_eq!(stepper.current_addr, 0x2000);
            assert_eq!(stepper.current_len, 5);
        }
    }

    #[test]
    fn test_step_wr_tmp() {
        unsafe {
            let mut stepper = SymbolicStepper::new();
            let mut state = SimState::new(0x1000, 256);
            let stmt = Stmt::WrTmp {
                temp: Temp::new(1),
                expr: Expr::Const {
                    ty: IRType::I64,
                    value: 100,
                },
            };

            let result = stepper.step(&mut state, &stmt);
            assert!(matches!(result, StepResult::Continue));
            assert!(stepper.temps.contains_key(&1));
            if let Some(Value::Concrete { value, .. }) = stepper.temps.get(&1) {
                assert_eq!(*value, 100);
            }
        }
    }

    #[test]
    fn test_step_put() {
        unsafe {
            let mut stepper = SymbolicStepper::new();
            let mut state = SimState::new(0x1000, 256);
            let stmt = Stmt::Put {
                offset: 16,
                expr: Expr::Const {
                    ty: IRType::I64,
                    value: 0x4242,
                },
            };

            let result = stepper.step(&mut state, &stmt);
            assert!(matches!(result, StepResult::Continue));
            
            let reg_val = state.read_register(16);
            assert!(reg_val.is_some());
            if let Some(Value::Concrete { value, .. }) = reg_val {
                assert_eq!(value, 0x4242);
            }
        }
    }

    #[test]
    fn test_step_block() {
        unsafe {
            let mut stepper = SymbolicStepper::new();
            let mut state = SimState::new(0x1000, 256);
            
            let stmts = vec![
                Stmt::IMark { addr: 0x1000, len: 3 },
                Stmt::WrTmp {
                    temp: Temp::new(1),
                    expr: Expr::Const { ty: IRType::I64, value: 10 },
                },
                Stmt::WrTmp {
                    temp: Temp::new(2),
                    expr: Expr::Const { ty: IRType::I64, value: 20 },
                },
            ];

            let result = stepper.step_block(&mut state, &stmts);
            assert!(matches!(result, StepResult::Jump { target: 0x1003 }));
            assert_eq!(stepper.temps.len(), 2);
        }
    }
}
