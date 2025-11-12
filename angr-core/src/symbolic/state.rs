//! Simulation State
//!
//! Represents the complete state of a symbolic execution at a given point.

use super::value::{Value, SymbolId};
use super::constraint::ConstraintSet;
use super::memory::SymbolicMemory;
use crate::memory::MemoryRegion;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Simulation state for symbolic execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimState {
    /// Program counter
    pc: u64,
    
    /// Register state (offset -> value)
    registers: HashMap<usize, Value>,
    
    /// Symbolic memory
    memory: SymbolicMemory,
    
    /// Path constraints
    constraints: ConstraintSet,
    
    /// Next symbol ID for creating new symbolic variables
    next_symbol_id: SymbolId,
    
    /// Architecture-specific guest state size
    guest_state_size: usize,
}

impl SimState {
    /// Create a new simulation state
    ///
    pub fn new(entry_addr: u64, guest_state_size: usize) -> Self {
        unsafe {
            SimState {
                pc: entry_addr,
                registers: HashMap::new(),
                memory: SymbolicMemory::new(),
                constraints: ConstraintSet::new(),
                next_symbol_id: 1,
                guest_state_size,
            }
        }
    }
    
    /// Get the program counter
    ///
    pub fn pc(&self) -> u64 {
        unsafe {
            self.pc
        }
    }
    
    /// Set the program counter
    ///
    pub fn set_pc(&mut self, pc: u64) {
        unsafe {
            self.pc = pc;
        }
    }
    
    /// Read a register
    ///
    pub fn read_register(&self, offset: usize) -> Option<Value> {
        unsafe {
            self.registers.get(&offset).cloned()
        }
    }
    
    /// Read a register with width (creates symbolic if missing)
    ///
    pub fn read_register_or_symbolic(&self, offset: usize, width: usize) -> Value {
        unsafe {
            // Check if we have a value for this register
            if let Some(value) = self.registers.get(&offset) {
                // TODO: Handle partial reads
                value.clone()
            } else {
                // Create a symbolic value for uninitialized register
                let name = format!("reg_{}_{}", offset, width);
                Value::symbol(self.next_symbol_id, name, width * 8)
            }
        }
    }
    
    /// Write a register
    ///
    pub fn write_register(&mut self, offset: usize, value: Value) {
        unsafe {
            self.registers.insert(offset, value);
        }
    }
    
    /// Read memory
    ///
    pub fn read_memory(&mut self, addr: u64, size: usize) -> Value {
        unsafe {
            self.memory.read(addr, size)
        }
    }
    
    /// Write memory
    ///
    pub fn write_memory(&mut self, addr: u64, value: Value) {
        unsafe {
            self.memory.write(addr, value);
        }
    }
    
    /// Map concrete data into memory
    ///
    pub fn map_memory(&mut self, addr: u64, data: &[u8]) {
        unsafe {
            self.memory.map_concrete(addr, data);
        }
    }
    
    /// Add a path constraint
    ///
    pub fn add_constraint(&mut self, constraint: super::constraint::Constraint) {
        unsafe {
            self.constraints.add(constraint);
        }
    }
    
    /// Get all constraints
    ///
    pub fn constraints(&self) -> &ConstraintSet {
        unsafe {
            &self.constraints
        }
    }
    
    /// Create a new symbolic variable
    ///
    pub fn new_symbol(&mut self, width: usize) -> Value {
        unsafe {
            let id = self.next_symbol_id;
            self.next_symbol_id += 1;
            let name = format!("sym_{}", id);
            Value::symbol(id, name, width)
        }
    }
    
    /// Create a new named symbolic variable
    ///
    pub fn new_named_symbol(&mut self, name: String, width: usize) -> Value {
        unsafe {
            let id = self.next_symbol_id;
            self.next_symbol_id += 1;
            Value::symbol(id, name, width)
        }
    }
    
    /// Set the program counter
    ///
    pub fn set_pc(&mut self, addr: u64) {
        unsafe {
            self.pc = addr;
        }
    }
    
    /// Clone this state (for path splitting)
    ///
    pub fn clone_state(&self) -> SimState {
        unsafe {
            self.clone()
        }
    }
    
    /// Check if this state is satisfiable
    ///
    pub fn is_sat(&self) -> bool {
        unsafe {
            self.constraints.is_sat()
        }
    }
    
    /// Get all register offsets that have been written
    ///
    pub fn get_register_offsets(&self) -> std::collections::HashSet<usize> {
        unsafe {
            self.registers.keys().copied().collect()
        }
    }
    
    /// Get all constraints
    ///
    pub fn get_constraints(&self) -> &[super::constraint::Constraint] {
        unsafe {
            self.constraints.constraints()
        }
    }
    
    /// Clear all constraints
    ///
    pub fn clear_constraints(&mut self) {
        unsafe {
            self.constraints = ConstraintSet::new();
        }
    }
    
    /// Merge with another state (if possible)
    ///
    pub fn merge(&mut self, _other: &SimState) -> bool {
        unsafe {
            // Stub: state merging requires ITE expressions
            // Will implement in state merging task
            false
        }
    }
}

/// Builder for SimState
pub struct SimStateBuilder {
    entry_addr: u64,
    guest_state_size: usize,
    initial_registers: HashMap<usize, Value>,
}

impl SimStateBuilder {
    /// Create a new SimState builder
    ///
    pub fn new(entry_addr: u64) -> Self {
        unsafe {
            SimStateBuilder {
                entry_addr,
                guest_state_size: 512,  // Default x86_64 size
                initial_registers: HashMap::new(),
            }
        }
    }
    
    /// Set the guest state size
    ///
    pub fn with_guest_state_size(mut self, size: usize) -> Self {
        unsafe {
            self.guest_state_size = size;
            self
        }
    }
    
    /// Set an initial register value
    ///
    pub fn with_register(mut self, offset: usize, value: Value) -> Self {
        unsafe {
            self.initial_registers.insert(offset, value);
            self
        }
    }
    
    /// Build the SimState
    ///
    pub fn build(self) -> SimState {
        unsafe {
            let mut state = SimState::new(self.entry_addr, self.guest_state_size);
            for (offset, value) in self.initial_registers {
                state.write_register(offset, value);
            }
            state
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simstate_creation() {
        unsafe {
            let state = SimState::new(0x1000, 512);
            assert_eq!(state.pc(), 0x1000);
        }
    }

    #[test]
    fn test_register_read_write() {
        unsafe {
            let mut state = SimState::new(0x1000, 512);
            let value = Value::concrete(64, 42);
            state.write_register(0, value.clone());
            let read = state.read_register(0, 8);
            assert_eq!(read.as_concrete(), Some(42));
        }
    }

    #[test]
    fn test_memory_read_write() {
        unsafe {
            let mut state = SimState::new(0x1000, 512);
            let value = Value::concrete(8, 0xFF);
            state.write_memory(0x2000, value);
            let read = state.read_memory(0x2000, 1);
            assert_eq!(read.as_concrete(), Some(0xFF));
        }
    }

    #[test]
    fn test_symbolic_register() {
        unsafe {
            let state = SimState::new(0x1000, 512);
            let value = state.read_register(8, 8);  // Uninitialized
            assert!(value.is_symbolic());
        }
    }

    #[test]
    fn test_state_builder() {
        unsafe {
            let state = SimStateBuilder::new(0x1000)
                .with_guest_state_size(1024)
                .with_register(0, Value::concrete(64, 100))
                .build();
            assert_eq!(state.pc(), 0x1000);
            assert_eq!(state.read_register(0, 8).as_concrete(), Some(100));
        }
    }
}
