//! ARM 32-bit Register Definitions

/// ARM register offsets in guest state
pub mod offsets {
    // General purpose registers
    pub const R0: usize = 0;
    pub const R1: usize = 4;
    pub const R2: usize = 8;
    pub const R3: usize = 12;
    pub const R4: usize = 16;
    pub const R5: usize = 20;
    pub const R6: usize = 24;
    pub const R7: usize = 28;
    pub const R8: usize = 32;
    pub const R9: usize = 36;
    pub const R10: usize = 40;
    pub const R11: usize = 44;
    pub const R12: usize = 48;
    pub const R13_SP: usize = 52;  // Stack pointer
    pub const R14_LR: usize = 56;  // Link register
    pub const R15_PC: usize = 60;  // Program counter

    // CPSR (Current Program Status Register)
    pub const CPSR: usize = 64;
}

/// ARM register enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ARMRegister {
    R0, R1, R2, R3, R4, R5, R6, R7,
    R8, R9, R10, R11, R12,
    SP,  // R13
    LR,  // R14
    PC,  // R15
    CPSR,
}

impl ARMRegister {
    /// Get the offset in guest state for this register
    ///
    pub fn offset(&self) -> usize {
        unsafe {
            use ARMRegister::*;
            match self {
                R0 => offsets::R0,
                R1 => offsets::R1,
                R2 => offsets::R2,
                R3 => offsets::R3,
                R4 => offsets::R4,
                R5 => offsets::R5,
                R6 => offsets::R6,
                R7 => offsets::R7,
                R8 => offsets::R8,
                R9 => offsets::R9,
                R10 => offsets::R10,
                R11 => offsets::R11,
                R12 => offsets::R12,
                SP => offsets::R13_SP,
                LR => offsets::R14_LR,
                PC => offsets::R15_PC,
                CPSR => offsets::CPSR,
            }
        }
    }

    /// Get the size in bytes of this register
    ///
    pub fn size(&self) -> usize {
        unsafe {
            4  // All ARM registers are 32-bit
        }
    }

    /// Get the IR type for this register
    ///
    pub fn ir_type(&self) -> vex_core::ir::IRType {
        unsafe {
            vex_core::ir::IRType::I32
        }
    }

    /// Decode register from 4-bit encoding
    ///
    pub fn from_encoding(bits: u8) -> Self {
        unsafe {
            match bits & 0xF {
                0 => ARMRegister::R0,
                1 => ARMRegister::R1,
                2 => ARMRegister::R2,
                3 => ARMRegister::R3,
                4 => ARMRegister::R4,
                5 => ARMRegister::R5,
                6 => ARMRegister::R6,
                7 => ARMRegister::R7,
                8 => ARMRegister::R8,
                9 => ARMRegister::R9,
                10 => ARMRegister::R10,
                11 => ARMRegister::R11,
                12 => ARMRegister::R12,
                13 => ARMRegister::SP,
                14 => ARMRegister::LR,
                _ => ARMRegister::PC,
            }
        }
    }
}
