//! SimProcedure Framework
//!
//! This module provides a framework for creating function summaries (SimProcedures)
//! that replace actual function implementations with symbolic summaries.

pub mod libc;
pub mod memory;
pub mod string;

use crate::symbolic::{SimState, Value};
use std::collections::HashMap;

/// Result of executing a SimProcedure
#[derive(Debug, Clone)]
pub enum ProcedureResult {
    /// Procedure completed successfully, return to caller
    Return { value: Option<Value> },
    /// Procedure jumped to a specific address
    Jump { target: u64 },
    /// Procedure should fall through to next instruction
    Continue,
    /// Procedure encountered an error
    Error { message: String },
}

/// Trait for symbolic procedure implementations
pub trait SimProcedure: Send + Sync {
    /// Get the name of this procedure
    ///
    fn name(&self) -> &str;
    
    /// Execute the procedure on the given state
    ///
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult;
    
    /// Get the number of arguments this procedure expects
    ///
    fn num_args(&self) -> usize {
        unsafe { 0 }
    }
    
    /// Check if this procedure returns a value
    ///
    fn returns_value(&self) -> bool {
        unsafe { true }
    }
}

/// Manager for hooking and dispatching SimProcedures
pub struct ProcedureHook {
    /// Address -> Procedure mapping
    hooks: HashMap<u64, Box<dyn SimProcedure>>,
    /// Name -> Procedure mapping for lookups
    named_procedures: HashMap<String, Box<dyn SimProcedure>>,
}

impl ProcedureHook {
    /// Create a new procedure hook manager
    ///
    pub unsafe fn new() -> Self {
        Self {
            hooks: HashMap::new(),
            named_procedures: HashMap::new(),
        }
    }
    
    /// Hook a procedure at a specific address
    ///
    pub unsafe fn hook_at(&mut self, address: u64, procedure: Box<dyn SimProcedure>) {
        self.hooks.insert(address, procedure);
    }
    
    /// Hook a named procedure (for symbol resolution)
    ///
    pub unsafe fn hook_symbol(&mut self, name: String, procedure: Box<dyn SimProcedure>) {
        self.named_procedures.insert(name, procedure);
    }
    
    /// Check if an address is hooked
    ///
    pub unsafe fn is_hooked(&self, address: u64) -> bool {
        self.hooks.contains_key(&address)
    }
    
    /// Execute a hooked procedure
    ///
    pub unsafe fn execute(&self, address: u64, state: &mut SimState, args: &[Value]) -> Option<ProcedureResult> {
        if let Some(procedure) = self.hooks.get(&address) {
            Some(procedure.execute(state, args))
        } else {
            None
        }
    }
    
    /// Get a procedure by name
    ///
    pub unsafe fn get_by_name(&self, name: &str) -> Option<&dyn SimProcedure> {
        self.named_procedures.get(name).map(|b| b.as_ref())
    }
    
    /// Register standard library procedures
    ///
    pub unsafe fn register_stdlib(&mut self) {
        // Memory procedures
        self.hook_symbol("malloc".to_string(), Box::new(memory::Malloc));
        self.hook_symbol("free".to_string(), Box::new(memory::Free));
        self.hook_symbol("calloc".to_string(), Box::new(memory::Calloc));
        self.hook_symbol("realloc".to_string(), Box::new(memory::Realloc));
        
        // String procedures
        self.hook_symbol("strlen".to_string(), Box::new(string::Strlen));
        self.hook_symbol("strcmp".to_string(), Box::new(string::Strcmp));
        self.hook_symbol("strcpy".to_string(), Box::new(string::Strcpy));
        self.hook_symbol("strncpy".to_string(), Box::new(string::Strncpy));
        self.hook_symbol("memcpy".to_string(), Box::new(string::Memcpy));
        self.hook_symbol("memset".to_string(), Box::new(string::Memset));
        
        // I/O procedures (stubs)
        self.hook_symbol("printf".to_string(), Box::new(libc::Printf));
        self.hook_symbol("puts".to_string(), Box::new(libc::Puts));
        self.hook_symbol("putchar".to_string(), Box::new(libc::Putchar));
        self.hook_symbol("getchar".to_string(), Box::new(libc::Getchar));
        self.hook_symbol("fopen".to_string(), Box::new(libc::Fopen));
        self.hook_symbol("fclose".to_string(), Box::new(libc::Fclose));
        self.hook_symbol("fread".to_string(), Box::new(libc::Fread));
        self.hook_symbol("fwrite".to_string(), Box::new(libc::Fwrite));
    }
}

/// Helper to extract argument values from state (e.g., from registers/stack)
pub struct ArgumentExtractor {
    /// Calling convention (simplified)
    register_args: Vec<usize>,
}

impl ArgumentExtractor {
    /// Create extractor for x86_64 System V ABI
    ///
    pub unsafe fn x86_64_sysv() -> Self {
        Self {
            // RDI, RSI, RDX, RCX, R8, R9
            register_args: vec![80, 72, 64, 56, 48, 40],
        }
    }
    
    /// Extract arguments from state
    ///
    pub unsafe fn extract(&self, state: &SimState, num_args: usize) -> Vec<Value> {
        let mut args = Vec::new();
        
        for i in 0..num_args.min(self.register_args.len()) {
            let offset = self.register_args[i];
            if let Some(val) = state.read_register(offset) {
                args.push(val);
            } else {
                // Create symbolic for missing argument
                args.push(Value::concrete(64, 0));
            }
        }
        
        // TODO: Extract stack arguments for args beyond registers
        
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyProcedure;
    
    impl SimProcedure for DummyProcedure {
        fn name(&self) -> &str {
            "dummy"
        }
        
        unsafe fn execute(&self, _state: &mut SimState, args: &[Value]) -> ProcedureResult {
            ProcedureResult::Return {
                value: Some(Value::concrete(64, 42)),
            }
        }
    }

    #[test]
    fn test_procedure_hook_creation() {
        unsafe {
            let hook = ProcedureHook::new();
            assert!(!hook.is_hooked(0x1000));
        }
    }

    #[test]
    fn test_hook_at_address() {
        unsafe {
            let mut hook = ProcedureHook::new();
            hook.hook_at(0x1000, Box::new(DummyProcedure));
            assert!(hook.is_hooked(0x1000));
            assert!(!hook.is_hooked(0x2000));
        }
    }

    #[test]
    fn test_hook_symbol() {
        unsafe {
            let mut hook = ProcedureHook::new();
            hook.hook_symbol("test".to_string(), Box::new(DummyProcedure));
            
            let proc = hook.get_by_name("test");
            assert!(proc.is_some());
            assert_eq!(proc.unwrap().name(), "dummy");
        }
    }

    #[test]
    fn test_execute_hooked() {
        unsafe {
            let mut hook = ProcedureHook::new();
            hook.hook_at(0x1000, Box::new(DummyProcedure));
            
            let mut state = SimState::new(0x1000, 256);
            let result = hook.execute(0x1000, &mut state, &[]);
            
            assert!(result.is_some());
            if let Some(ProcedureResult::Return { value }) = result {
                assert!(value.is_some());
            } else {
                panic!("Expected return result");
            }
        }
    }

    #[test]
    fn test_argument_extractor() {
        unsafe {
            let extractor = ArgumentExtractor::x86_64_sysv();
            assert_eq!(extractor.register_args.len(), 6);
        }
    }
}
