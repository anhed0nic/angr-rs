//! String Manipulation SimProcedures
//!
//! Symbolic implementations of strlen, strcmp, strcpy, memcpy, memset, etc.

use super::{ProcedureResult, SimProcedure};
use crate::symbolic::{SimState, Value};

/// strlen - Get string length
pub struct Strlen;

impl SimProcedure for Strlen {
    fn name(&self) -> &str {
        "strlen"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.is_empty() {
            return ProcedureResult::Error {
                message: "strlen requires 1 argument".to_string(),
            };
        }
        
        let str_ptr = &args[0];
        
        if let Some(addr) = str_ptr.as_concrete() {
            // Read bytes until null terminator
            let mut len = 0u64;
            loop {
                let byte = state.read_memory(addr + len, 1);
                if let Some(val) = byte.as_concrete() {
                    if val == 0 {
                        break;
                    }
                    len += 1;
                    
                    // Safety limit
                    if len > 0x10000 {
                        break;
                    }
                } else {
                    // Symbolic byte - return symbolic length
                    return ProcedureResult::Return {
                        value: Some(state.new_symbol(64)),
                    };
                }
            }
            
            ProcedureResult::Return {
                value: Some(Value::concrete(64, len)),
            }
        } else {
            // Symbolic pointer - return symbolic length
            ProcedureResult::Return {
                value: Some(state.new_symbol(64)),
            }
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 1 }
    }
}

/// strcmp - Compare two strings
pub struct Strcmp;

impl SimProcedure for Strcmp {
    fn name(&self) -> &str {
        "strcmp"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.len() < 2 {
            return ProcedureResult::Error {
                message: "strcmp requires 2 arguments".to_string(),
            };
        }
        
        let s1_ptr = &args[0];
        let s2_ptr = &args[1];
        
        if let (Some(addr1), Some(addr2)) = (s1_ptr.as_concrete(), s2_ptr.as_concrete()) {
            // Compare byte by byte
            let mut offset = 0u64;
            loop {
                let byte1 = state.read_memory(addr1 + offset, 1);
                let byte2 = state.read_memory(addr2 + offset, 1);
                
                if let (Some(b1), Some(b2)) = (byte1.as_concrete(), byte2.as_concrete()) {
                    if b1 != b2 {
                        // Different
                        let result = if b1 < b2 { -1i64 as u128 } else { 1u128 };
                        return ProcedureResult::Return {
                            value: Some(Value::concrete(32, result)),
                        };
                    }
                    if b1 == 0 {
                        // Both null terminators - equal
                        return ProcedureResult::Return {
                            value: Some(Value::concrete(32, 0)),
                        };
                    }
                    offset += 1;
                    
                    if offset > 0x10000 {
                        break;
                    }
                } else {
                    // Symbolic byte - return symbolic result
                    return ProcedureResult::Return {
                        value: Some(state.new_symbol(32)),
                    };
                }
            }
            
            // Timeout - return symbolic
            ProcedureResult::Return {
                value: Some(state.new_symbol(32)),
            }
        } else {
            // Symbolic pointer - return symbolic
            ProcedureResult::Return {
                value: Some(state.new_symbol(32)),
            }
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 2 }
    }
}

/// strcpy - Copy string
pub struct Strcpy;

impl SimProcedure for Strcpy {
    fn name(&self) -> &str {
        "strcpy"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.len() < 2 {
            return ProcedureResult::Error {
                message: "strcpy requires 2 arguments".to_string(),
            };
        }
        
        let dst_ptr = &args[0];
        let src_ptr = &args[1];
        
        if let (Some(dst_addr), Some(src_addr)) = (dst_ptr.as_concrete(), src_ptr.as_concrete()) {
            // Copy bytes until null terminator
            let mut offset = 0u64;
            loop {
                let byte = state.read_memory(src_addr + offset, 1);
                state.write_memory(dst_addr + offset, &byte.to_bytes());
                
                if let Some(val) = byte.as_concrete() {
                    if val == 0 {
                        break;
                    }
                }
                
                offset += 1;
                if offset > 0x10000 {
                    break;
                }
            }
            
            // Return destination pointer
            ProcedureResult::Return {
                value: Some(dst_ptr.clone()),
            }
        } else {
            // Symbolic - can't copy, return destination
            ProcedureResult::Return {
                value: Some(dst_ptr.clone()),
            }
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 2 }
    }
}

/// strncpy - Copy string with limit
pub struct Strncpy;

impl SimProcedure for Strncpy {
    fn name(&self) -> &str {
        "strncpy"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.len() < 3 {
            return ProcedureResult::Error {
                message: "strncpy requires 3 arguments".to_string(),
            };
        }
        
        let dst_ptr = &args[0];
        let src_ptr = &args[1];
        let n = &args[2];
        
        if let (Some(dst_addr), Some(src_addr), Some(max_len)) = 
            (dst_ptr.as_concrete(), src_ptr.as_concrete(), n.as_concrete()) {
            
            let mut offset = 0u64;
            let mut null_found = false;
            
            while offset < max_len as u64 {
                if !null_found {
                    let byte = state.read_memory(src_addr + offset, 1);
                    state.write_memory(dst_addr + offset, &byte.to_bytes());
                    
                    if let Some(val) = byte.as_concrete() {
                        if val == 0 {
                            null_found = true;
                        }
                    }
                } else {
                    // Pad with zeros
                    state.write_memory(dst_addr + offset, &[0]);
                }
                
                offset += 1;
            }
            
            ProcedureResult::Return {
                value: Some(dst_ptr.clone()),
            }
        } else {
            ProcedureResult::Return {
                value: Some(dst_ptr.clone()),
            }
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 3 }
    }
}

/// memcpy - Copy memory
pub struct Memcpy;

impl SimProcedure for Memcpy {
    fn name(&self) -> &str {
        "memcpy"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.len() < 3 {
            return ProcedureResult::Error {
                message: "memcpy requires 3 arguments".to_string(),
            };
        }
        
        let dst_ptr = &args[0];
        let src_ptr = &args[1];
        let n = &args[2];
        
        if let (Some(dst_addr), Some(src_addr), Some(size)) = 
            (dst_ptr.as_concrete(), src_ptr.as_concrete(), n.as_concrete()) {
            
            // Copy byte by byte
            for i in 0..size as u64 {
                let byte = state.read_memory(src_addr + i, 1);
                state.write_memory(dst_addr + i, &byte.to_bytes());
            }
            
            ProcedureResult::Return {
                value: Some(dst_ptr.clone()),
            }
        } else {
            // Symbolic - return destination
            ProcedureResult::Return {
                value: Some(dst_ptr.clone()),
            }
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 3 }
    }
}

/// memset - Fill memory with constant byte
pub struct Memset;

impl SimProcedure for Memset {
    fn name(&self) -> &str {
        "memset"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult {
        if args.len() < 3 {
            return ProcedureResult::Error {
                message: "memset requires 3 arguments".to_string(),
            };
        }
        
        let ptr = &args[0];
        let byte_val = &args[1];
        let n = &args[2];
        
        if let (Some(addr), Some(val), Some(size)) = 
            (ptr.as_concrete(), byte_val.as_concrete(), n.as_concrete()) {
            
            let byte = (val & 0xFF) as u8;
            
            // Fill memory
            for i in 0..size as u64 {
                state.write_memory(addr + i, &[byte]);
            }
            
            ProcedureResult::Return {
                value: Some(ptr.clone()),
            }
        } else {
            ProcedureResult::Return {
                value: Some(ptr.clone()),
            }
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 3 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strlen_concrete() {
        unsafe {
            let strlen = Strlen;
            let mut state = SimState::new(0x1000, 256);
            
            // Write "hello" to memory
            let str_addr = 0x10000000u64;
            state.write_memory(str_addr, &[b'h']);
            state.write_memory(str_addr + 1, &[b'e']);
            state.write_memory(str_addr + 2, &[b'l']);
            state.write_memory(str_addr + 3, &[b'l']);
            state.write_memory(str_addr + 4, &[b'o']);
            state.write_memory(str_addr + 5, &[0]);
            
            let args = vec![Value::concrete(64, str_addr)];
            let result = strlen.execute(&mut state, &args);
            
            if let ProcedureResult::Return { value } = result {
                assert_eq!(value.unwrap().as_concrete(), Some(5));
            } else {
                panic!("Expected return result");
            }
        }
    }

    #[test]
    fn test_strcmp_equal() {
        unsafe {
            let strcmp = Strcmp;
            let mut state = SimState::new(0x1000, 256);
            
            // Write "hi" to two locations
            let addr1 = 0x10000000u64;
            let addr2 = 0x10001000u64;
            
            for (addr, _) in [(addr1, 0), (addr2, 0)] {
                state.write_memory(addr, &[b'h']);
                state.write_memory(addr + 1, &[b'i']);
                state.write_memory(addr + 2, &[0]);
            }
            
            let args = vec![Value::concrete(64, addr1), Value::concrete(64, addr2)];
            let result = strcmp.execute(&mut state, &args);
            
            if let ProcedureResult::Return { value } = result {
                assert_eq!(value.unwrap().as_concrete(), Some(0));
            } else {
                panic!("Expected return result");
            }
        }
    }

    #[test]
    fn test_memcpy() {
        unsafe {
            let memcpy = Memcpy;
            let mut state = SimState::new(0x1000, 256);
            
            // Write source data
            let src_addr = 0x10000000u64;
            let dst_addr = 0x10001000u64;
            
            state.write_memory(src_addr, &[1]);
            state.write_memory(src_addr + 1, &[2]);
            state.write_memory(src_addr + 2, &[3]);
            
            let args = vec![
                Value::concrete(64, dst_addr),
                Value::concrete(64, src_addr),
                Value::concrete(64, 3),
            ];
            
            let result = memcpy.execute(&mut state, &args);
            
            if let ProcedureResult::Return { value } = result {
                assert_eq!(value.unwrap().as_concrete(), Some(dst_addr));
                
                // Verify copy
                let byte0 = state.read_memory(dst_addr, 1);
                assert_eq!(byte0.as_concrete(), Some(1));
            } else {
                panic!("Expected return result");
            }
        }
    }

    #[test]
    fn test_memset() {
        unsafe {
            let memset = Memset;
            let mut state = SimState::new(0x1000, 256);
            
            let addr = 0x10000000u64;
            let args = vec![
                Value::concrete(64, addr),
                Value::concrete(32, 0xAA),
                Value::concrete(64, 10),
            ];
            
            let result = memset.execute(&mut state, &args);
            
            if let ProcedureResult::Return { value } = result {
                assert_eq!(value.unwrap().as_concrete(), Some(addr));
                
                // Verify fill
                let byte = state.read_memory(addr + 5, 1);
                assert_eq!(byte.as_concrete(), Some(0xAA));
            } else {
                panic!("Expected return result");
            }
        }
    }
}
