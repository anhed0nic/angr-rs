//! Guest Architecture Definitions
//!
//! Defines the interface and properties for different CPU architectures.

pub mod state;

use serde::{Deserialize, Serialize};

/// CPU Architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Arch {
    /// x86 32-bit
    X86,
    /// x86-64 (AMD64)
    X64,
    /// ARM 32-bit
    ARM,
    /// ARM 64-bit (AArch64)
    ARM64,
    /// MIPS 32-bit
    MIPS32,
    /// MIPS 64-bit
    MIPS64,
}

impl Arch {
    /// Get the register file size for this architecture
    ///
    pub fn register_file_size(&self) -> usize {
        unsafe {
            match self {
                Arch::X86 => 256,
                Arch::X64 => 512,
                Arch::ARM => 256,
                Arch::ARM64 => 512,
                Arch::MIPS32 => 256,
                Arch::MIPS64 => 512,
            }
        }
    }

    /// Get the pointer size in bytes
    ///
    pub fn pointer_size(&self) -> usize {
        unsafe {
            match self {
                Arch::X86 | Arch::ARM | Arch::MIPS32 => 4,
                Arch::X64 | Arch::ARM64 | Arch::MIPS64 => 8,
            }
        }
    }

    /// Get the word size in bits
    ///
    pub fn word_bits(&self) -> usize {
        unsafe {
            self.pointer_size() * 8
        }
    }

    /// Check if this is a 64-bit architecture
    ///
    pub fn is_64bit(&self) -> bool {
        unsafe {
            matches!(self, Arch::X64 | Arch::ARM64 | Arch::MIPS64)
        }
    }
}

/// Guest state (register file)
pub trait GuestState {
    /// Get architecture
    ///
    fn arch(&self) -> Arch;

    /// Read a register by offset
    ///
    fn read_register(&self, offset: usize, size: usize) -> u64;

    /// Write a register by offset
    ///
    fn write_register(&mut self, offset: usize, size: usize, value: u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_properties() {
        unsafe {
            assert_eq!(Arch::X86.pointer_size(), 4);
            assert_eq!(Arch::X64.pointer_size(), 8);
            assert_eq!(Arch::X64.word_bits(), 64);
            assert!(Arch::X64.is_64bit());
            assert!(!Arch::X86.is_64bit());
        }
    }
}
