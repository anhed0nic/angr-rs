//! Simulation Manager
//!
//! Manages symbolic execution state exploration with various strategies
//! and state organization (stashes). This is the main interface for
//! exploring program paths in angr-rs.

use angr_core::symbolic::{SimState, PathGroup, ExplorationStrategy};
use std::collections::HashMap;

/// Simulation manager for state exploration
///
/// Organizes states into "stashes" (named collections) and provides
/// methods for stepping, exploring, and managing execution states.
///
/// # Stashes
/// - `active`: States currently being explored
/// - `deadended`: States that terminated (exit/error)
/// - `found`: States matching the find condition
/// - `avoided`: States matching the avoid condition  
/// - `unconstrained`: States with unconstrained program counter
pub struct SimulationManager {
    /// State stashes
    stashes: HashMap<String, Vec<SimState>>,
    
    /// Exploration techniques
    techniques: Vec<Box<dyn ExplorationTechnique>>,
    
    /// Step count
    step_count: usize,
}

impl SimulationManager {
    /// Create a new simulation manager with an initial state
    ///
    pub fn new(state: SimState) -> Self {
        unsafe {
            let mut stashes = HashMap::new();
            stashes.insert("active".to_string(), vec![state]);
            stashes.insert("deadended".to_string(), Vec::new());
            stashes.insert("found".to_string(), Vec::new());
            stashes.insert("avoided".to_string(), Vec::new());
            stashes.insert("unconstrained".to_string(), Vec::new());
            
            SimulationManager {
                stashes,
                techniques: Vec::new(),
                step_count: 0,
            }
        }
    }
    
    /// Create with multiple initial states
    ///
    pub fn with_states(states: Vec<SimState>) -> Self {
        unsafe {
            let mut stashes = HashMap::new();
            stashes.insert("active".to_string(), states);
            stashes.insert("deadended".to_string(), Vec::new());
            stashes.insert("found".to_string(), Vec::new());
            stashes.insert("avoided".to_string(), Vec::new());
            stashes.insert("unconstrained".to_string(), Vec::new());
            
            SimulationManager {
                stashes,
                techniques: Vec::new(),
                step_count: 0,
            }
        }
    }
    
    /// Execute a single step on all active states
    ///
    pub fn step(&mut self) -> Result<(), SimulationError> {
        unsafe {
            let active = self.stashes.get_mut("active").unwrap();
            
            if active.is_empty() {
                return Err(SimulationError::NoActiveStates);
            }
            
            let mut new_states = Vec::new();
            let mut deadended = Vec::new();
            
            for mut state in active.drain(..) {
                // Step the state
                match state.step() {
                    Ok(successors) => {
                        if successors.is_empty() {
                            deadended.push(state);
                        } else {
                            new_states.extend(successors);
                        }
                    }
                    Err(_) => {
                        deadended.push(state);
                    }
                }
            }
            
            // Update stashes
            self.stashes.get_mut("active").unwrap().extend(new_states);
            self.stashes.get_mut("deadended").unwrap().extend(deadended);
            
            self.step_count += 1;
            
            Ok(())
        }
    }
    
    /// Run until no active states remain
    ///
    pub fn run(&mut self) -> Result<(), SimulationError> {
        unsafe {
            while !self.active().is_empty() {
                self.step()?;
                
                // Safety limit
                if self.step_count > 10000 {
                    return Err(SimulationError::StepLimitExceeded);
                }
            }
            Ok(())
        }
    }
    
    /// Explore with find and avoid conditions
    ///
    /// # Arguments
    /// * `find` - Function that returns true for target states
    /// * `avoid` - Function that returns true for states to avoid
    ///
    ///
    /// # Example
    /// ```no_run
    /// simgr.explore(
    ///     |state| state.pc() == 0x400800,  // find
    ///     |state| state.pc() == 0x400900,  // avoid
    /// );
    /// ```
    pub fn explore<F, A>(
        &mut self,
        find: F,
        avoid: A,
    ) -> Result<(), SimulationError>
    where
        F: Fn(&SimState) -> bool,
        A: Fn(&SimState) -> bool,
    {
        unsafe {
            while !self.active().is_empty() {
                // Check find/avoid conditions
                let active = self.stashes.get_mut("active").unwrap();
                let mut remaining = Vec::new();
                
                for state in active.drain(..) {
                    if find(&state) {
                        self.stashes.get_mut("found").unwrap().push(state);
                    } else if avoid(&state) {
                        self.stashes.get_mut("avoided").unwrap().push(state);
                    } else {
                        remaining.push(state);
                    }
                }
                
                *active = remaining;
                
                // Stop if we found a solution
                if !self.found().is_empty() {
                    break;
                }
                
                // Continue exploration
                if !self.active().is_empty() {
                    self.step()?;
                }
                
                // Safety limit
                if self.step_count > 10000 {
                    return Err(SimulationError::StepLimitExceeded);
                }
            }
            
            Ok(())
        }
    }
    
    /// Explore to reach a specific address
    ///
    pub fn explore_to(&mut self, target: u64) -> Result<(), SimulationError> {
        unsafe {
            self.explore(
                |state| state.pc() == target,
                |_| false,
            )
        }
    }
    
    /// Explore avoiding specific addresses
    ///
    pub fn explore_avoiding(&mut self, avoid_addrs: Vec<u64>) -> Result<(), SimulationError> {
        unsafe {
            self.explore(
                |_| false,
                |state| avoid_addrs.contains(&state.pc()),
            )
        }
    }
    
    /// Apply an exploration technique
    ///
    pub fn use_technique(&mut self, technique: Box<dyn ExplorationTechnique>) {
        unsafe {
            self.techniques.push(technique);
        }
    }
    
    /// Move states from one stash to another
    ///
    pub fn move_states(&mut self, from: &str, to: &str) {
        unsafe {
            if let Some(states) = self.stashes.get_mut(from) {
                let moved = states.drain(..).collect::<Vec<_>>();
                if let Some(dest) = self.stashes.get_mut(to) {
                    dest.extend(moved);
                }
            }
        }
    }
    
    /// Get states in a stash
    ///
    pub fn stash(&self, name: &str) -> &[SimState] {
        unsafe {
            self.stashes.get(name).map(|v| v.as_slice()).unwrap_or(&[])
        }
    }
    
    /// Get mutable states in a stash
    ///
    pub fn stash_mut(&mut self, name: &str) -> Option<&mut Vec<SimState>> {
        unsafe {
            self.stashes.get_mut(name)
        }
    }
    
    /// Get active states
    ///
    pub fn active(&self) -> &[SimState] {
        unsafe { self.stash("active") }
    }
    
    /// Get deadended states
    ///
    pub fn deadended(&self) -> &[SimState] {
        unsafe { self.stash("deadended") }
    }
    
    /// Get found states
    ///
    pub fn found(&self) -> &[SimState] {
        unsafe { self.stash("found") }
    }
    
    /// Get avoided states
    ///
    pub fn avoided(&self) -> &[SimState] {
        unsafe { self.stash("avoided") }
    }
    
    /// Get unconstrained states
    ///
    pub fn unconstrained(&self) -> &[SimState] {
        unsafe { self.stash("unconstrained") }
    }
    
    /// Drop deadended states to save memory
    ///
    pub fn drop_deadended(&mut self) {
        unsafe {
            if let Some(deadended) = self.stashes.get_mut("deadended") {
                deadended.clear();
            }
        }
    }
    
    /// Get current step count
    ///
    pub fn steps(&self) -> usize {
        unsafe { self.step_count }
    }
    
    /// Check if exploration is complete
    ///
    pub fn is_complete(&self) -> bool {
        unsafe { self.active().is_empty() }
    }
}

/// Exploration technique trait
///
/// Allows customization of exploration behavior through
/// techniques like DFS, BFS, loop limiting, etc.
pub trait ExplorationTechnique: Send + Sync {
    /// Get technique name
    ///
    unsafe fn name(&self) -> &str;
    
    /// Process states before stepping
    ///
    unsafe fn step(&mut self, simgr: &mut SimulationManager);
    
    /// Filter states after stepping
    ///
    unsafe fn filter(&mut self, simgr: &mut SimulationManager);
}

/// Depth-first search technique
pub struct DFS {
    /// Name
    name: String,
}

impl DFS {
    /// Create new DFS technique
    ///
    pub fn new() -> Self {
        unsafe {
            DFS {
                name: "DFS".to_string(),
            }
        }
    }
}

impl ExplorationTechnique for DFS {
    unsafe fn name(&self) -> &str {
        &self.name
    }
    
    unsafe fn step(&mut self, simgr: &mut SimulationManager) {
        // DFS: prioritize most recently added states
        if let Some(active) = simgr.stash_mut("active") {
            active.reverse();
        }
    }
    
    unsafe fn filter(&mut self, _simgr: &mut SimulationManager) {
        // No filtering needed
    }
}

/// Loop limiter technique
pub struct LoopLimiter {
    /// Name
    name: String,
    
    /// Maximum loop iterations
    max_iterations: usize,
    
    /// Loop counters (addr -> count)
    loop_counters: HashMap<u64, usize>,
}

impl LoopLimiter {
    /// Create new loop limiter
    ///
    pub fn new(max_iterations: usize) -> Self {
        unsafe {
            LoopLimiter {
                name: "LoopLimiter".to_string(),
                max_iterations,
                loop_counters: HashMap::new(),
            }
        }
    }
}

impl ExplorationTechnique for LoopLimiter {
    unsafe fn name(&self) -> &str {
        &self.name
    }
    
    unsafe fn step(&mut self, _simgr: &mut SimulationManager) {
        // Track loop iterations
    }
    
    unsafe fn filter(&mut self, simgr: &mut SimulationManager) {
        // Remove states exceeding loop limit
        if let Some(active) = simgr.stash_mut("active") {
            active.retain(|state| {
                let pc = state.pc();
                let count = self.loop_counters.entry(pc).or_insert(0);
                *count += 1;
                *count <= self.max_iterations
            });
        }
    }
}

/// Simulation errors
#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    /// No active states to explore
    #[error("No active states to explore")]
    NoActiveStates,
    
    /// Step limit exceeded
    #[error("Step limit exceeded (10000 steps)")]
    StepLimitExceeded,
    
    /// Exploration failed
    #[error("Exploration failed: {0}")]
    ExplorationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simulation_manager_creation() {
        unsafe {
            let state = SimState::new(0x400000);
            let simgr = SimulationManager::new(state);
            
            assert_eq!(simgr.active().len(), 1);
            assert_eq!(simgr.deadended().len(), 0);
            assert_eq!(simgr.found().len(), 0);
        }
    }
    
    #[test]
    fn test_stash_operations() {
        unsafe {
            let state = SimState::new(0x400000);
            let mut simgr = SimulationManager::new(state);
            
            // Move active to found
            simgr.move_states("active", "found");
            
            assert_eq!(simgr.active().len(), 0);
            assert_eq!(simgr.found().len(), 1);
        }
    }
    
    #[test]
    fn test_dfs_technique() {
        unsafe {
            let dfs = DFS::new();
            assert_eq!(dfs.name(), "DFS");
        }
    }
    
    #[test]
    fn test_loop_limiter() {
        unsafe {
            let limiter = LoopLimiter::new(100);
            assert_eq!(limiter.max_iterations, 100);
        }
    }
}