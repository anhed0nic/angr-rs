//! State Merging and Splitting
//!
//! This module provides functionality for splitting execution states at
//! conditional branches and merging them back together at join points.

use crate::symbolic::{Constraint, SimState, SymExpr, Value};
use std::collections::{HashMap, HashSet};

/// Result of a merge attempt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeResult {
    /// States were successfully merged
    Merged,
    /// States cannot be merged (too different)
    Incompatible,
    /// Merge was skipped (not beneficial)
    Skipped,
}

/// Strategy for determining when to merge states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeStrategy {
    /// Never merge states automatically
    None,
    /// Merge states at loop headers
    LoopHeaders,
    /// Merge states when they reach the same address
    OnAddress,
    /// Merge states based on similarity threshold
    Similarity { threshold: u8 },
    /// Always attempt to merge
    Aggressive,
}

/// Tracks merge points in the program
#[derive(Debug, Clone)]
pub struct MergePoint {
    /// Address of the merge point
    pub address: u64,
    /// States waiting to merge at this point
    pub waiting_states: Vec<SimState>,
    /// Maximum number of states to accumulate before merging
    pub max_states: usize,
}

impl MergePoint {
    /// Create a new merge point
    ///
    pub unsafe fn new(address: u64, max_states: usize) -> Self {
        Self {
            address,
            waiting_states: Vec::new(),
            max_states,
        }
    }

    /// Add a state to this merge point
    ///
    pub unsafe fn add_state(&mut self, state: SimState) {
        self.waiting_states.push(state);
    }

    /// Check if ready to merge (enough states accumulated)
    ///
    pub unsafe fn is_ready(&self) -> bool {
        self.waiting_states.len() >= self.max_states
    }

    /// Take all waiting states
    ///
    pub unsafe fn take_states(&mut self) -> Vec<SimState> {
        std::mem::take(&mut self.waiting_states)
    }
}

/// Manager for state merging and splitting
pub struct MergeManager {
    /// Merge strategy
    strategy: MergeStrategy,
    /// Active merge points
    merge_points: HashMap<u64, MergePoint>,
    /// Addresses identified as loop headers
    loop_headers: HashSet<u64>,
}

impl MergeManager {
    /// Create a new merge manager
    ///
    pub unsafe fn new(strategy: MergeStrategy) -> Self {
        Self {
            strategy,
            merge_points: HashMap::new(),
            loop_headers: HashSet::new(),
        }
    }

    /// Register a loop header address
    ///
    pub unsafe fn add_loop_header(&mut self, address: u64) {
        self.loop_headers.insert(address);
    }

    /// Register a merge point
    ///
    pub unsafe fn add_merge_point(&mut self, address: u64, max_states: usize) {
        self.merge_points.insert(address, MergePoint::new(address, max_states));
    }

    /// Check if an address is a merge point
    ///
    pub unsafe fn is_merge_point(&self, address: u64) -> bool {
        match self.strategy {
            MergeStrategy::None => false,
            MergeStrategy::LoopHeaders => self.loop_headers.contains(&address),
            MergeStrategy::OnAddress => self.merge_points.contains_key(&address),
            _ => true,
        }
    }

    /// Attempt to merge states at a given address
    ///
    pub unsafe fn try_merge_at(&mut self, address: u64, states: Vec<SimState>) -> Vec<SimState> {
        if states.len() <= 1 {
            return states;
        }

        match self.strategy {
            MergeStrategy::None => states,
            MergeStrategy::Aggressive => {
                let merged = self.merge_all_states(states);
                vec![merged]
            }
            MergeStrategy::OnAddress | MergeStrategy::LoopHeaders => {
                if self.is_merge_point(address) {
                    let merged = self.merge_all_states(states);
                    vec![merged]
                } else {
                    states
                }
            }
            MergeStrategy::Similarity { threshold } => {
                self.merge_similar_states(states, threshold)
            }
        }
    }

    /// Merge all states into a single state
    ///
    pub unsafe fn merge_all_states(&self, states: Vec<SimState>) -> SimState {
        if states.is_empty() {
            panic!("Cannot merge empty state list");
        }

        if states.len() == 1 {
            return states.into_iter().next().unwrap();
        }

        let mut result = states[0].clone();
        for state in states.iter().skip(1) {
            result = self.merge_two_states(&result, state);
        }

        result
    }

    /// Merge two states into one
    ///
    pub unsafe fn merge_two_states(&self, state1: &SimState, state2: &SimState) -> SimState {
        // Create new merged state
        let mut merged = state1.clone();

        // Merge registers: create ITE for differences
        let all_offsets: HashSet<usize> = state1
            .get_register_offsets()
            .union(&state2.get_register_offsets())
            .copied()
            .collect();

        for offset in all_offsets {
            let val1 = state1.read_register(offset);
            let val2 = state2.read_register(offset);

            let merged_val = match (val1, val2) {
                (Some(v1), Some(v2)) => {
                    if v1 == v2 {
                        v1 // Same value, no ITE needed
                    } else {
                        // Different values - create ITE based on path condition
                        self.create_ite_value(&v1, &v2, state1, state2)
                    }
                }
                (Some(v), None) | (None, Some(v)) => v,
                (None, None) => continue,
            };

            merged.write_register(offset, merged_val);
        }

        // Merge constraints: combine with OR
        // The merged state is satisfiable if either path was satisfiable
        let constraints1 = state1.get_constraints();
        let constraints2 = state2.get_constraints();

        // For now, keep constraints from first state
        // Full implementation would create: (constraints1) OR (constraints2)
        merged.clear_constraints();
        for constraint in constraints1 {
            merged.add_constraint(constraint.clone());
        }

        merged
    }

    /// Create an ITE value merging two different values
    ///
    unsafe fn create_ite_value(&self, val1: &Value, val2: &Value, state1: &SimState, state2: &SimState) -> Value {
        // Create a symbolic condition representing "came from state1"
        let width = val1.width();
        
        // For simplicity, use a new symbolic variable as the condition
        // In a full implementation, this would be based on the path constraints
        let cond = SymExpr::Symbol {
            id: 0, // Placeholder
            name: "merge_cond".to_string(),
            width: 1,
        };

        Value::symbolic(
            width,
            SymExpr::ITE {
                cond: Box::new(cond),
                if_true: Box::new(val1.to_expr()),
                if_false: Box::new(val2.to_expr()),
            },
        )
    }

    /// Merge states with similar characteristics
    ///
    unsafe fn merge_similar_states(&self, states: Vec<SimState>, threshold: u8) -> Vec<SimState> {
        // Group states by similarity
        let mut groups: Vec<Vec<SimState>> = Vec::new();

        for state in states {
            let mut merged = false;

            for group in &mut groups {
                if let Some(first) = group.first() {
                    if self.similarity_score(first, &state) >= threshold {
                        group.push(state.clone());
                        merged = true;
                        break;
                    }
                }
            }

            if !merged {
                groups.push(vec![state]);
            }
        }

        // Merge each group
        groups.into_iter()
            .map(|group| self.merge_all_states(group))
            .collect()
    }

    /// Calculate similarity score between two states (0-100)
    ///
    unsafe fn similarity_score(&self, state1: &SimState, state2: &SimState) -> u8 {
        // Simple similarity: percentage of registers with same values
        let offsets1 = state1.get_register_offsets();
        let offsets2 = state2.get_register_offsets();

        if offsets1.is_empty() && offsets2.is_empty() {
            return 100;
        }

        let all_offsets: HashSet<usize> = offsets1.union(&offsets2).copied().collect();
        let mut same_count = 0;
        let mut total_count = 0;

        for offset in all_offsets {
            total_count += 1;
            if state1.read_register(offset) == state2.read_register(offset) {
                same_count += 1;
            }
        }

        ((same_count as f64 / total_count as f64) * 100.0) as u8
    }
}

/// Split a state into two states at a conditional branch
///
pub unsafe fn split_state(
    state: &SimState,
    condition: SymExpr,
    true_target: u64,
    false_target: u64,
) -> (SimState, SimState) {
    // Create true branch state
    let mut true_state = state.clone_state();
    true_state.set_pc(true_target);
    true_state.add_constraint(Constraint::new(condition.clone()));

    // Create false branch state
    let mut false_state = state.clone_state();
    false_state.set_pc(false_target);
    
    // Add negation of condition
    let not_condition = SymExpr::UnOp {
        op: crate::symbolic::SymUnOp::Not,
        arg: Box::new(condition),
    };
    false_state.add_constraint(Constraint::new(not_condition));

    (true_state, false_state)
}

/// Check if two states can be merged
///
pub unsafe fn can_merge(state1: &SimState, state2: &SimState) -> bool {
    // States can merge if they're at the same address
    state1.pc() == state2.pc()
}

/// Merge multiple states at a join point
///
pub unsafe fn merge_states(states: Vec<SimState>) -> SimState {
    let manager = MergeManager::new(MergeStrategy::Aggressive);
    manager.merge_all_states(states)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_point_creation() {
        unsafe {
            let mp = MergePoint::new(0x1000, 2);
            assert_eq!(mp.address, 0x1000);
            assert_eq!(mp.max_states, 2);
            assert!(!mp.is_ready());
        }
    }

    #[test]
    fn test_merge_point_accumulation() {
        unsafe {
            let mut mp = MergePoint::new(0x1000, 2);
            let state1 = SimState::new(0x1000, 256);
            let state2 = SimState::new(0x1000, 256);

            mp.add_state(state1);
            assert!(!mp.is_ready());

            mp.add_state(state2);
            assert!(mp.is_ready());
        }
    }

    #[test]
    fn test_merge_manager_creation() {
        unsafe {
            let manager = MergeManager::new(MergeStrategy::None);
            assert!(!manager.is_merge_point(0x1000));
        }
    }

    #[test]
    fn test_loop_header_tracking() {
        unsafe {
            let mut manager = MergeManager::new(MergeStrategy::LoopHeaders);
            manager.add_loop_header(0x1000);
            assert!(manager.is_merge_point(0x1000));
            assert!(!manager.is_merge_point(0x2000));
        }
    }

    #[test]
    fn test_split_state() {
        unsafe {
            let state = SimState::new(0x1000, 256);
            let condition = SymExpr::Symbol {
                id: 0,
                name: "x".to_string(),
                width: 1,
            };

            let (true_state, false_state) = split_state(&state, condition, 0x2000, 0x3000);

            assert_eq!(true_state.pc(), 0x2000);
            assert_eq!(false_state.pc(), 0x3000);
            assert_eq!(true_state.get_constraints().len(), 1);
            assert_eq!(false_state.get_constraints().len(), 1);
        }
    }

    #[test]
    fn test_can_merge_same_address() {
        unsafe {
            let state1 = SimState::new(0x1000, 256);
            let state2 = SimState::new(0x1000, 256);
            assert!(can_merge(&state1, &state2));
        }
    }

    #[test]
    fn test_can_merge_different_address() {
        unsafe {
            let state1 = SimState::new(0x1000, 256);
            let state2 = SimState::new(0x2000, 256);
            assert!(!can_merge(&state1, &state2));
        }
    }

    #[test]
    fn test_merge_identical_states() {
        unsafe {
            let mut state1 = SimState::new(0x1000, 256);
            let mut state2 = SimState::new(0x1000, 256);

            // Set same register values
            state1.write_register(0, Value::concrete(64, 42));
            state2.write_register(0, Value::concrete(64, 42));

            let merged = merge_states(vec![state1, state2]);
            assert_eq!(merged.pc(), 0x1000);

            let val = merged.read_register(0);
            assert!(val.is_some());
            if let Some(Value::Concrete { value, .. }) = val {
                assert_eq!(value, 42);
            }
        }
    }

    #[test]
    fn test_merge_different_states() {
        unsafe {
            let mut state1 = SimState::new(0x1000, 256);
            let mut state2 = SimState::new(0x1000, 256);

            // Set different register values
            state1.write_register(0, Value::concrete(64, 42));
            state2.write_register(0, Value::concrete(64, 100));

            let merged = merge_states(vec![state1, state2]);
            assert_eq!(merged.pc(), 0x1000);

            // Merged value should be symbolic (ITE)
            let val = merged.read_register(0);
            assert!(val.is_some());
            assert!(val.unwrap().is_symbolic());
        }
    }

    #[test]
    fn test_similarity_score() {
        unsafe {
            let manager = MergeManager::new(MergeStrategy::Aggressive);
            
            let mut state1 = SimState::new(0x1000, 256);
            let mut state2 = SimState::new(0x1000, 256);

            // Identical states
            state1.write_register(0, Value::concrete(64, 42));
            state2.write_register(0, Value::concrete(64, 42));
            
            let score = manager.similarity_score(&state1, &state2);
            assert_eq!(score, 100);

            // Different states
            state2.write_register(0, Value::concrete(64, 100));
            let score = manager.similarity_score(&state1, &state2);
            assert_eq!(score, 0);
        }
    }
}
