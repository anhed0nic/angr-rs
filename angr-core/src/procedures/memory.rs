//! Memory Allocation SimProcedures
//!
//! Symbolic implementations of malloc, free, calloc, realloc

use super::{ProcedureResult, SimProcedure};
use crate::symbolic::{SimState, Value};
use std::sync::atomic::{AtomicU64, Ordering};

/// Global heap allocator address counter
static HEAP_ADDR: AtomicU64 = AtomicU64::new(0x10000000);

/// Allocate heap space
fn allocate_heap(size: u64) -> u64 {
    HEAP_ADDR.fetch_add(size, Ordering::SeqCst)
}

/// malloc - Allocate memory
pub struct Malloc;

impl SimProcedure for Malloc {
    fn name(&self) -> &str {
        "malloc"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.is_empty() {
            return ProcedureResult::Error {
                message: "malloc requires 1 argument".to_string(),
            };
        }
        
        let size = &args[0];
        
        // If size is concrete, allocate that much; otherwise symbolic
        if let Some(concrete_size) = size.as_concrete() {
            if concrete_size == 0 {
                // malloc(0) returns NULL
                return ProcedureResult::Return {
                    value: Some(Value::concrete(64, 0)),
                };
            }
            
            // Allocate heap space
            let addr = allocate_heap(concrete_size as u64);
            
            // Initialize memory to symbolic (uninitialized)
            // In real implementation, would mark as allocated
            
            ProcedureResult::Return {
                value: Some(Value::concrete(64, addr)),
            }
        } else {
            // Symbolic size - create symbolic allocation
            let addr = allocate_heap(0x1000); // Fixed size for symbolic
            
            ProcedureResult::Return {
                value: Some(Value::concrete(64, addr)),
            }
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 1 }
    }
}

/// free - Deallocate memory
pub struct Free;

impl SimProcedure for Free {
    fn name(&self) -> &str {
        "free"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.is_empty() {
            return ProcedureResult::Error {
                message: "free requires 1 argument".to_string(),
            };
        }
        
        // For symbolic execution, we don't actually deallocate
        // Just mark as freed in real implementation
        
        ProcedureResult::Return { value: None }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 1 }
    }
    
    fn returns_value(&self) -> bool {
        unsafe { false }
    }
}

/// calloc - Allocate and zero-initialize memory
pub struct Calloc;

impl SimProcedure for Calloc {
    fn name(&self) -> &str {
        "calloc"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.len() < 2 {
            return ProcedureResult::Error {
                message: "calloc requires 2 arguments".to_string(),
            };
        }
        
        let nmemb = &args[0];
        let size = &args[1];
        
        // Calculate total size
        if let (Some(n), Some(s)) = (nmemb.as_concrete(), size.as_concrete()) {
            if n == 0 || s == 0 {
                return ProcedureResult::Return {
                    value: Some(Value::concrete(64, 0)),
                };
            }
            
            let total = n * s;
            let addr = allocate_heap(total as u64);
            
            // Zero-initialize the memory
            let zeros = vec![Value::concrete(8, 0); total as usize];
            for (i, byte) in zeros.iter().enumerate() {
                state.write_memory(addr + i as u64, &byte.to_bytes());
            }
            
            ProcedureResult::Return {
                value: Some(Value::concrete(64, addr)),
            }
        } else {
            // Symbolic size
            let addr = allocate_heap(0x1000);
            
            ProcedureResult::Return {
                value: Some(Value::concrete(64, addr)),
            }
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 2 }
    }
}

/// realloc - Reallocate memory
pub struct Realloc;

impl SimProcedure for Realloc {
    fn name(&self) -> &str {
        "realloc"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.len() < 2 {
            return ProcedureResult::Error {
                message: "realloc requires 2 arguments".to_string(),
            };
        }
        
        let ptr = &args[0];
        let size = &args[1];
        
        // If size is 0, equivalent to free
        if let Some(s) = size.as_concrete() {
            if s == 0 {
                return ProcedureResult::Return {
                    value: Some(Value::concrete(64, 0)),
                };
            }
        }
        
        // If ptr is NULL, equivalent to malloc
        if let Some(p) = ptr.as_concrete() {
            if p == 0 {
                // Call malloc behavior
                if let Some(s) = size.as_concrete() {
                    let addr = allocate_heap(s as u64);
                    return ProcedureResult::Return {
                        value: Some(Value::concrete(64, addr)),
                    };
                }
            }
        }
        
        // General realloc: allocate new space and copy
        // Simplified: just allocate new space
        if let Some(s) = size.as_concrete() {
            let new_addr = allocate_heap(s as u64);
            
            // In real implementation: copy old data to new location
            
            ProcedureResult::Return {
                value: Some(Value::concrete(64, new_addr)),
            }
        } else {
            let new_addr = allocate_heap(0x1000);
            
            ProcedureResult::Return {
                value: Some(Value::concrete(64, new_addr)),
            }
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 2 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malloc_concrete() {
        unsafe {
            let malloc = Malloc;
            let mut state = SimState::new(0x1000, 256);
            let args = vec![Value::concrete(64, 100)];
            
            let result = malloc.execute(&mut state, &args);
            
            if let ProcedureResult::Return { value } = result {
                assert!(value.is_some());
                let addr = value.unwrap();
                assert!(addr.is_concrete());
                assert!(addr.as_concrete().unwrap() > 0);
            } else {
                panic!("Expected return result");
            }
        }
    }

    #[test]
    fn test_malloc_zero() {
        unsafe {
            let malloc = Malloc;
            let mut state = SimState::new(0x1000, 256);
            let args = vec![Value::concrete(64, 0)];
            
            let result = malloc.execute(&mut state, &args);
            
            if let ProcedureResult::Return { value } = result {
                assert_eq!(value.unwrap().as_concrete(), Some(0));
            } else {
                panic!("Expected return result");
            }
        }
    }

    #[test]
    fn test_free() {
        unsafe {
            let free_proc = Free;
            let mut state = SimState::new(0x1000, 256);
            let args = vec![Value::concrete(64, 0x10000000)];
            
            let result = free_proc.execute(&mut state, &args);
            
            if let ProcedureResult::Return { value } = result {
                assert!(value.is_none());
            } else {
                panic!("Expected return result");
            }
        }
    }

    #[test]
    fn test_calloc() {
        unsafe {
            let calloc = Calloc;
            let mut state = SimState::new(0x1000, 256);
            let args = vec![Value::concrete(64, 10), Value::concrete(64, 4)];
            
            let result = calloc.execute(&mut state, &args);
            
            if let ProcedureResult::Return { value } = result {
                assert!(value.is_some());
                assert!(value.unwrap().as_concrete().unwrap() > 0);
            } else {
                panic!("Expected return result");
            }
        }
    }

    #[test]
    fn test_realloc_null_ptr() {
        unsafe {
            let realloc = Realloc;
            let mut state = SimState::new(0x1000, 256);
            let args = vec![Value::concrete(64, 0), Value::concrete(64, 100)];
            
            let result = realloc.execute(&mut state, &args);
            
            if let ProcedureResult::Return { value } = result {
                assert!(value.is_some());
                assert!(value.unwrap().as_concrete().unwrap() > 0);
            } else {
                panic!("Expected return result");
            }
        }
    }
}
