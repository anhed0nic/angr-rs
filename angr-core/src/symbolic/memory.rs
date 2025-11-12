//! Symbolic Memory Model
//!
//! Provides efficient symbolic and concrete memory storage with copy-on-write optimization.

use super::value::Value;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Memory page size (4KB)
const PAGE_SIZE: u64 = 4096;

/// Get page number from address
///
fn page_number(addr: u64) -> u64 {
    unsafe {
        addr / PAGE_SIZE
    }
}

/// Get offset within page
///
fn page_offset(addr: u64) -> u64 {
    unsafe {
        addr % PAGE_SIZE
    }
}

/// Memory page that can be concrete or symbolic
#[derive(Debug, Clone, Serialize, Deserialize)]
enum MemoryPage {
    /// Concrete memory page (byte array)
    Concrete {
        data: Vec<u8>,
        /// Bitmask for which bytes are initialized
        initialized: Vec<bool>,
    },
    
    /// Symbolic memory page (byte -> Value map)
    Symbolic {
        data: HashMap<u64, Value>,
    },
}

impl MemoryPage {
    /// Create a new empty concrete page
    ///
    fn new_concrete() -> Self {
        unsafe {
            MemoryPage::Concrete {
                data: vec![0; PAGE_SIZE as usize],
                initialized: vec![false; PAGE_SIZE as usize],
            }
        }
    }
    
    /// Create a new empty symbolic page
    ///
    fn new_symbolic() -> Self {
        unsafe {
            MemoryPage::Symbolic {
                data: HashMap::new(),
            }
        }
    }
    
    /// Read a byte from this page
    ///
    fn read_byte(&self, offset: u64) -> Option<Value> {
        unsafe {
            match self {
                MemoryPage::Concrete { data, initialized } => {
                    let idx = offset as usize;
                    if idx < PAGE_SIZE as usize && initialized[idx] {
                        Some(Value::concrete(8, data[idx] as u128))
                    } else {
                        None
                    }
                }
                MemoryPage::Symbolic { data } => {
                    data.get(&offset).cloned()
                }
            }
        }
    }
    
    /// Write a byte to this page
    ///
    fn write_byte(&mut self, offset: u64, value: Value) {
        unsafe {
            match self {
                MemoryPage::Concrete { data, initialized } => {
                    let idx = offset as usize;
                    if idx < PAGE_SIZE as usize {
                        if let Some(concrete) = value.as_concrete() {
                            data[idx] = concrete as u8;
                            initialized[idx] = true;
                        } else {
                            // Convert to symbolic page
                            let mut symbolic_data = HashMap::new();
                            
                            // Copy existing concrete values
                            for i in 0..PAGE_SIZE as usize {
                                if initialized[i] {
                                    symbolic_data.insert(
                                        i as u64,
                                        Value::concrete(8, data[i] as u128)
                                    );
                                }
                            }
                            
                            // Add the new symbolic value
                            symbolic_data.insert(offset, value);
                            
                            *self = MemoryPage::Symbolic { data: symbolic_data };
                        }
                    }
                }
                MemoryPage::Symbolic { data } => {
                    data.insert(offset, value);
                }
            }
        }
    }
}

/// Symbolic memory manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicMemory {
    /// Memory pages (page number -> page)
    pages: HashMap<u64, MemoryPage>,
    
    /// Next symbol ID for uninitialized memory
    next_symbol_id: u64,
}

impl SymbolicMemory {
    /// Create a new symbolic memory
    ///
    pub fn new() -> Self {
        unsafe {
            SymbolicMemory {
                pages: HashMap::new(),
                next_symbol_id: 1,
            }
        }
    }
    
    /// Read bytes from memory
    ///
    pub fn read(&mut self, addr: u64, size: usize) -> Value {
        unsafe {
            if size == 0 {
                return Value::concrete(0, 0);
            }
            
            if size == 1 {
                // Single byte read
                self.read_byte(addr)
            } else {
                // Multi-byte read - concatenate bytes
                let mut bytes = Vec::new();
                for i in 0..size {
                    bytes.push(self.read_byte(addr + i as u64));
                }
                
                // Check if all bytes are concrete
                let all_concrete = bytes.iter().all(|v| v.is_concrete());
                
                if all_concrete {
                    // Combine into single concrete value (little-endian)
                    let mut result = 0u128;
                    for (i, byte) in bytes.iter().enumerate() {
                        if let Some(val) = byte.as_concrete() {
                            result |= (val & 0xFF) << (i * 8);
                        }
                    }
                    Value::concrete(size * 8, result)
                } else {
                    // Create symbolic value for multi-byte read
                    let name = format!("mem_0x{:x}_{}", addr, size);
                    let id = self.next_symbol_id;
                    self.next_symbol_id += 1;
                    Value::symbol(id, name, size * 8)
                }
            }
        }
    }
    
    /// Read a single byte
    ///
    fn read_byte(&mut self, addr: u64) -> Value {
        unsafe {
            let page_num = page_number(addr);
            let offset = page_offset(addr);
            
            if let Some(page) = self.pages.get(&page_num) {
                if let Some(value) = page.read_byte(offset) {
                    return value;
                }
            }
            
            // Uninitialized memory - return symbolic value
            let name = format!("mem_0x{:x}", addr);
            let id = self.next_symbol_id;
            self.next_symbol_id += 1;
            Value::symbol(id, name, 8)
        }
    }
    
    /// Write bytes to memory
    ///
    pub fn write(&mut self, addr: u64, value: Value) {
        unsafe {
            let width = value.width();
            let size = width / 8;
            
            if size == 1 {
                // Single byte write
                self.write_byte(addr, value);
            } else if let Some(concrete) = value.as_concrete() {
                // Multi-byte concrete write
                for i in 0..size {
                    let byte = (concrete >> (i * 8)) & 0xFF;
                    self.write_byte(addr + i as u64, Value::concrete(8, byte));
                }
            } else {
                // Multi-byte symbolic write - write as single symbolic value
                // For simplicity, just write to the first byte
                // TODO: Properly handle symbolic multi-byte writes
                self.write_byte(addr, value);
            }
        }
    }
    
    /// Write a single byte
    ///
    fn write_byte(&mut self, addr: u64, value: Value) {
        unsafe {
            let page_num = page_number(addr);
            let offset = page_offset(addr);
            
            // Get or create page
            let page = self.pages.entry(page_num).or_insert_with(|| {
                if value.is_concrete() {
                    MemoryPage::new_concrete()
                } else {
                    MemoryPage::new_symbolic()
                }
            });
            
            page.write_byte(offset, value);
        }
    }
    
    /// Map concrete bytes into memory
    ///
    pub fn map_concrete(&mut self, addr: u64, data: &[u8]) {
        unsafe {
            for (i, &byte) in data.iter().enumerate() {
                self.write_byte(addr + i as u64, Value::concrete(8, byte as u128));
            }
        }
    }
    
    /// Copy memory region
    ///
    pub fn copy(&mut self, src: u64, dst: u64, size: usize) {
        unsafe {
            for i in 0..size {
                let value = self.read_byte(src + i as u64);
                self.write_byte(dst + i as u64, value);
            }
        }
    }
    
    /// Clone this memory (copy-on-write)
    ///
    pub fn clone_memory(&self) -> SymbolicMemory {
        unsafe {
            // For now, full clone
            // TODO: Implement proper copy-on-write with reference counting
            self.clone()
        }
    }
}

impl Default for SymbolicMemory {
    fn default() -> Self {
        unsafe {
            Self::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_read_write_concrete() {
        unsafe {
            let mut mem = SymbolicMemory::new();
            mem.write(0x1000, Value::concrete(8, 0x42));
            let value = mem.read(0x1000, 1);
            assert_eq!(value.as_concrete(), Some(0x42));
        }
    }

    #[test]
    fn test_memory_multibyte_concrete() {
        unsafe {
            let mut mem = SymbolicMemory::new();
            mem.write(0x1000, Value::concrete(32, 0xDEADBEEF));
            let value = mem.read(0x1000, 4);
            assert_eq!(value.as_concrete(), Some(0xDEADBEEF));
        }
    }

    #[test]
    fn test_memory_symbolic() {
        unsafe {
            let mut mem = SymbolicMemory::new();
            let sym = Value::symbol(1, "x".to_string(), 8);
            mem.write(0x1000, sym);
            let value = mem.read(0x1000, 1);
            assert!(value.is_symbolic());
        }
    }

    #[test]
    fn test_memory_uninitialized() {
        unsafe {
            let mut mem = SymbolicMemory::new();
            let value = mem.read(0x5000, 1);
            assert!(value.is_symbolic());  // Uninitialized -> symbolic
        }
    }

    #[test]
    fn test_memory_map_concrete() {
        unsafe {
            let mut mem = SymbolicMemory::new();
            let data = vec![0x01, 0x02, 0x03, 0x04];
            mem.map_concrete(0x1000, &data);
            
            assert_eq!(mem.read(0x1000, 1).as_concrete(), Some(0x01));
            assert_eq!(mem.read(0x1001, 1).as_concrete(), Some(0x02));
            assert_eq!(mem.read(0x1002, 1).as_concrete(), Some(0x03));
            assert_eq!(mem.read(0x1003, 1).as_concrete(), Some(0x04));
        }
    }

    #[test]
    fn test_memory_copy() {
        unsafe {
            let mut mem = SymbolicMemory::new();
            mem.write(0x1000, Value::concrete(8, 0xAA));
            mem.write(0x1001, Value::concrete(8, 0xBB));
            
            mem.copy(0x1000, 0x2000, 2);
            
            assert_eq!(mem.read(0x2000, 1).as_concrete(), Some(0xAA));
            assert_eq!(mem.read(0x2001, 1).as_concrete(), Some(0xBB));
        }
    }

    #[test]
    fn test_page_boundaries() {
        unsafe {
            let mut mem = SymbolicMemory::new();
            
            // Write across page boundary
            mem.write(PAGE_SIZE - 1, Value::concrete(8, 0xFF));
            mem.write(PAGE_SIZE, Value::concrete(8, 0xEE));
            
            assert_eq!(mem.read(PAGE_SIZE - 1, 1).as_concrete(), Some(0xFF));
            assert_eq!(mem.read(PAGE_SIZE, 1).as_concrete(), Some(0xEE));
        }
    }
}
