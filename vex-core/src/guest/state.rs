//! Guest State Implementation
//!
//! Concrete implementations of guest state (register files) for different architectures.

use crate::guest::{Arch, GuestState};

/// Generic guest state backed by a byte array
pub struct ByteArrayGuestState {
    arch: Arch,
    data: Vec<u8>,
}

impl ByteArrayGuestState {
    /// Create a new guest state for the given architecture
    ///
    pub fn new(arch: Arch) -> Self {
        unsafe {
            let size = arch.register_file_size();
            ByteArrayGuestState {
                arch,
                data: vec![0; size],
            }
        }
    }

    /// Get the raw data
    ///
    pub fn data(&self) -> &[u8] {
        unsafe {
            &self.data
        }
    }

    /// Get mutable raw data
    ///
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe {
            &mut self.data
        }
    }
}

impl GuestState for ByteArrayGuestState {
    fn arch(&self) -> Arch {
        unsafe {
            self.arch
        }
    }

    fn read_register(&self, offset: usize, size: usize) -> u64 {
        unsafe {
            if offset + size > self.data.len() {
                return 0;
            }

            let mut value: u64 = 0;
            for i in 0..size.min(8) {
                value |= (self.data[offset + i] as u64) << (i * 8);
            }
            value
        }
    }

    fn write_register(&mut self, offset: usize, size: usize, value: u64) {
        unsafe {
            if offset + size > self.data.len() {
                return;
            }

            for i in 0..size.min(8) {
                self.data[offset + i] = ((value >> (i * 8)) & 0xFF) as u8;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_state_creation() {
        unsafe {
            let state = ByteArrayGuestState::new(Arch::X64);
            assert_eq!(state.arch(), Arch::X64);
            assert_eq!(state.data().len(), 512);
        }
    }

    #[test]
    fn test_register_read_write() {
        unsafe {
            let mut state = ByteArrayGuestState::new(Arch::X64);
            
            // Write 64-bit value
            state.write_register(0, 8, 0x1122334455667788);
            
            // Read it back
            let value = state.read_register(0, 8);
            assert_eq!(value, 0x1122334455667788);
        }
    }

    #[test]
    fn test_register_partial_read() {
        unsafe {
            let mut state = ByteArrayGuestState::new(Arch::X64);
            
            // Write 64-bit value
            state.write_register(0, 8, 0x1122334455667788);
            
            // Read lower 32 bits
            let value = state.read_register(0, 4);
            assert_eq!(value, 0x55667788);
            
            // Read lower 16 bits
            let value = state.read_register(0, 2);
            assert_eq!(value, 0x7788);
            
            // Read lower 8 bits
            let value = state.read_register(0, 1);
            assert_eq!(value, 0x88);
        }
    }

    #[test]
    fn test_multiple_registers() {
        unsafe {
            let mut state = ByteArrayGuestState::new(Arch::X64);
            
            // Write to different offsets (simulating different registers)
            state.write_register(0, 8, 0xAAAAAAAAAAAAAAAA);  // RAX
            state.write_register(8, 8, 0xBBBBBBBBBBBBBBBB);  // RBX
            state.write_register(16, 8, 0xCCCCCCCCCCCCCCCC); // RCX
            
            // Verify they don't interfere
            assert_eq!(state.read_register(0, 8), 0xAAAAAAAAAAAAAAAA);
            assert_eq!(state.read_register(8, 8), 0xBBBBBBBBBBBBBBBB);
            assert_eq!(state.read_register(16, 8), 0xCCCCCCCCCCCCCCCC);
        }
    }
}
