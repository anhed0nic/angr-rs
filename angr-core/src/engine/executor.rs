//! Path Exploration with State Splitting
//!
//! Example showing how to integrate state splitting with PathGroup

use crate::engine::{PathGroup, ExplorationStrategy, SymbolicStepper, StepResult, split_state};
use crate::symbolic::SimState;
use vex_core::ir::Stmt;

/// Symbolic executor that handles path exploration
pub struct SymbolicExecutor {
    /// Path group managing active states
    pathgroup: PathGroup,
    /// Stepper for executing IR
    stepper: SymbolicStepper,
}

impl SymbolicExecutor {
    /// Create a new symbolic executor
    ///
    pub unsafe fn new(initial_state: SimState, strategy: ExplorationStrategy) -> Self {
        let mut pathgroup = PathGroup::new(strategy);
        pathgroup.add_active(initial_state);
        
        Self {
            pathgroup,
            stepper: SymbolicStepper::new(),
        }
    }
    
    /// Execute one step of symbolic execution
    ///
    pub unsafe fn step(&mut self, stmts: &[Stmt]) -> usize {
        let state = match self.pathgroup.next_state() {
            Some(s) => s,
            None => return 0,
        };
        
        let mut current_state = state;
        let result = self.stepper.step_block(&mut current_state, stmts);
        
        match result {
            StepResult::Continue | StepResult::Jump { .. } => {
                // Continue with this state
                self.pathgroup.add_active(current_state);
                1
            }
            
            StepResult::ConditionalBranch { condition, true_target, false_target } => {
                // Split the state
                let (true_state, false_state) = split_state(
                    &current_state,
                    condition,
                    true_target,
                    false_target,
                );
                
                // Add both states to active
                self.pathgroup.add_active(true_state);
                self.pathgroup.add_active(false_state);
                2
            }
            
            StepResult::Call { target, .. } => {
                // For now, treat as jump
                current_state.set_pc(target);
                self.pathgroup.add_active(current_state);
                1
            }
            
            StepResult::Return | StepResult::Halt => {
                // State terminated normally
                self.pathgroup.add_deadended(current_state);
                0
            }
            
            StepResult::Syscall { .. } => {
                // Handle syscall (stub for now)
                self.pathgroup.add_deadended(current_state);
                0
            }
            
            StepResult::Error { message } => {
                // State encountered error
                self.pathgroup.add_errored(current_state);
                0
            }
        }
    }
    
    /// Run until no active states remain or step limit reached
    ///
    pub unsafe fn run(&mut self, stmts: &[Stmt], max_steps: usize) -> usize {
        let mut steps = 0;
        
        while self.pathgroup.has_active() && steps < max_steps {
            let new_states = self.step(stmts);
            if new_states == 0 {
                break;
            }
            steps += 1;
        }
        
        steps
    }
    
    /// Get reference to the path group
    ///
    pub unsafe fn pathgroup(&self) -> &PathGroup {
        &self.pathgroup
    }
    
    /// Get mutable reference to the path group
    ///
    pub unsafe fn pathgroup_mut(&mut self) -> &mut PathGroup {
        &mut self.pathgroup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vex_core::ir::{Expr, IRType, Temp, BinOp};

    #[test]
    fn test_executor_creation() {
        unsafe {
            let state = SimState::new(0x1000, 256);
            let executor = SymbolicExecutor::new(state, ExplorationStrategy::DFS);
            assert!(executor.pathgroup().has_active());
        }
    }

    #[test]
    fn test_simple_execution() {
        unsafe {
            let state = SimState::new(0x1000, 256);
            let mut executor = SymbolicExecutor::new(state, ExplorationStrategy::DFS);
            
            let stmts = vec![
                Stmt::IMark { addr: 0x1000, len: 3 },
                Stmt::WrTmp {
                    temp: Temp::new(1),
                    expr: Expr::Const { ty: IRType::I64, value: 42 },
                },
            ];
            
            let count = executor.step(&stmts);
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn test_conditional_branch_splitting() {
        unsafe {
            let state = SimState::new(0x1000, 256);
            let mut executor = SymbolicExecutor::new(state, ExplorationStrategy::BFS);
            
            // Create a symbolic condition
            let stmts = vec![
                Stmt::IMark { addr: 0x1000, len: 5 },
                Stmt::Exit {
                    guard: Expr::Const { ty: IRType::I1, value: 1 },
                    dst: 0x2000,
                    jump_kind: vex_core::ir::JumpKind::Conditional,
                },
            ];
            
            let initial_active = executor.pathgroup().active_count();
            let count = executor.step(&stmts);
            
            // Should create jump, not split since guard is concrete
            assert!(count > 0);
        }
    }
}
