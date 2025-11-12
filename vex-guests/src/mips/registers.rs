//! MIPS32 Register Definitions

/// MIPS32 register offsets in guest state
pub mod offsets {
    // General purpose registers
    pub const R0_ZERO: usize = 0;   // Always zero
    pub const R1_AT: usize = 4;     // Assembler temporary
    pub const R2_V0: usize = 8;     // Return value 0
    pub const R3_V1: usize = 12;    // Return value 1
    pub const R4_A0: usize = 16;    // Argument 0
    pub const R5_A1: usize = 20;    // Argument 1
    pub const R6_A2: usize = 24;    // Argument 2
    pub const R7_A3: usize = 28;    // Argument 3
    pub const R8_T0: usize = 32;    // Temporary 0
    pub const R9_T1: usize = 36;    // Temporary 1
    pub const R10_T2: usize = 40;   // Temporary 2
    pub const R11_T3: usize = 44;   // Temporary 3
    pub const R12_T4: usize = 48;   // Temporary 4
    pub const R13_T5: usize = 52;   // Temporary 5
    pub const R14_T6: usize = 56;   // Temporary 6
    pub const R15_T7: usize = 60;   // Temporary 7
    pub const R16_S0: usize = 64;   // Saved 0
    pub const R17_S1: usize = 68;   // Saved 1
    pub const R18_S2: usize = 72;   // Saved 2
    pub const R19_S3: usize = 76;   // Saved 3
    pub const R20_S4: usize = 80;   // Saved 4
    pub const R21_S5: usize = 84;   // Saved 5
    pub const R22_S6: usize = 88;   // Saved 6
    pub const R23_S7: usize = 92;   // Saved 7
    pub const R24_T8: usize = 96;   // Temporary 8
    pub const R25_T9: usize = 100;  // Temporary 9
    pub const R26_K0: usize = 104;  // Kernel 0
    pub const R27_K1: usize = 108;  // Kernel 1
    pub const R28_GP: usize = 112;  // Global pointer
    pub const R29_SP: usize = 116;  // Stack pointer
    pub const R30_FP: usize = 120;  // Frame pointer
    pub const R31_RA: usize = 124;  // Return address

    // Special registers
    pub const PC: usize = 128;      // Program counter
    pub const HI: usize = 132;      // Multiply/divide high
    pub const LO: usize = 136;      // Multiply/divide low
}

/// MIPS32 register enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MIPS32Register {
    // General purpose by number
    R0, R1, R2, R3, R4, R5, R6, R7,
    R8, R9, R10, R11, R12, R13, R14, R15,
    R16, R17, R18, R19, R20, R21, R22, R23,
    R24, R25, R26, R27, R28, R29, R30, R31,
    
    // Aliases
    ZERO,  // R0
    AT,    // R1
    V0, V1,  // R2-R3
    A0, A1, A2, A3,  // R4-R7
    T0, T1, T2, T3, T4, T5, T6, T7,  // R8-R15
    S0, S1, S2, S3, S4, S5, S6, S7,  // R16-R23
    T8, T9,  // R24-R25
    K0, K1,  // R26-R27
    GP,  // R28
    SP,  // R29
    FP,  // R30
    RA,  // R31
    
    // Special
    PC,
    HI,
    LO,
}

impl MIPS32Register {
    /// Get the offset in guest state for this register
    ///
    pub fn offset(&self) -> usize {
        unsafe {
            use MIPS32Register::*;
            match self {
                R0 | ZERO => offsets::R0_ZERO,
                R1 | AT => offsets::R1_AT,
                R2 | V0 => offsets::R2_V0,
                R3 | V1 => offsets::R3_V1,
                R4 | A0 => offsets::R4_A0,
                R5 | A1 => offsets::R5_A1,
                R6 | A2 => offsets::R6_A2,
                R7 | A3 => offsets::R7_A3,
                R8 | T0 => offsets::R8_T0,
                R9 | T1 => offsets::R9_T1,
                R10 | T2 => offsets::R10_T2,
                R11 | T3 => offsets::R11_T3,
                R12 | T4 => offsets::R12_T4,
                R13 | T5 => offsets::R13_T5,
                R14 | T6 => offsets::R14_T6,
                R15 | T7 => offsets::R15_T7,
                R16 | S0 => offsets::R16_S0,
                R17 | S1 => offsets::R17_S1,
                R18 | S2 => offsets::R18_S2,
                R19 | S3 => offsets::R19_S3,
                R20 | S4 => offsets::R20_S4,
                R21 | S5 => offsets::R21_S5,
                R22 | S6 => offsets::R22_S6,
                R23 | S7 => offsets::R23_S7,
                R24 | T8 => offsets::R24_T8,
                R25 | T9 => offsets::R25_T9,
                R26 | K0 => offsets::R26_K0,
                R27 | K1 => offsets::R27_K1,
                R28 | GP => offsets::R28_GP,
                R29 | SP => offsets::R29_SP,
                R30 | FP => offsets::R30_FP,
                R31 | RA => offsets::R31_RA,
                PC => offsets::PC,
                HI => offsets::HI,
                LO => offsets::LO,
            }
        }
    }

    /// Get the size in bytes of this register
    ///
    pub fn size(&self) -> usize {
        unsafe {
            4  // All MIPS32 registers are 32-bit
        }
    }

    /// Get the IR type for this register
    ///
    pub fn ir_type(&self) -> vex_core::ir::IRType {
        unsafe {
            vex_core::ir::IRType::I32
        }
    }

    /// Decode register from 5-bit encoding
    ///
    pub fn from_encoding(bits: u8) -> Self {
        unsafe {
            match bits & 0x1F {
                0 => MIPS32Register::R0,
                1 => MIPS32Register::R1,
                2 => MIPS32Register::R2,
                3 => MIPS32Register::R3,
                4 => MIPS32Register::R4,
                5 => MIPS32Register::R5,
                6 => MIPS32Register::R6,
                7 => MIPS32Register::R7,
                8 => MIPS32Register::R8,
                9 => MIPS32Register::R9,
                10 => MIPS32Register::R10,
                11 => MIPS32Register::R11,
                12 => MIPS32Register::R12,
                13 => MIPS32Register::R13,
                14 => MIPS32Register::R14,
                15 => MIPS32Register::R15,
                16 => MIPS32Register::R16,
                17 => MIPS32Register::R17,
                18 => MIPS32Register::R18,
                19 => MIPS32Register::R19,
                20 => MIPS32Register::R20,
                21 => MIPS32Register::R21,
                22 => MIPS32Register::R22,
                23 => MIPS32Register::R23,
                24 => MIPS32Register::R24,
                25 => MIPS32Register::R25,
                26 => MIPS32Register::R26,
                27 => MIPS32Register::R27,
                28 => MIPS32Register::R28,
                29 => MIPS32Register::R29,
                30 => MIPS32Register::R30,
                _ => MIPS32Register::R31,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_offsets() {
        unsafe {
            assert_eq!(MIPS32Register::R0.offset(), offsets::R0_ZERO);
            assert_eq!(MIPS32Register::ZERO.offset(), offsets::R0_ZERO);
            assert_eq!(MIPS32Register::SP.offset(), offsets::R29_SP);
            assert_eq!(MIPS32Register::RA.offset(), offsets::R31_RA);
        }
    }

    #[test]
    fn test_register_sizes() {
        unsafe {
            assert_eq!(MIPS32Register::R0.size(), 4);
            assert_eq!(MIPS32Register::PC.size(), 4);
            assert_eq!(MIPS32Register::HI.size(), 4);
        }
    }

    #[test]
    fn test_register_decoding() {
        unsafe {
            assert_eq!(MIPS32Register::from_encoding(0).offset(), MIPS32Register::R0.offset());
            assert_eq!(MIPS32Register::from_encoding(29).offset(), MIPS32Register::SP.offset());
            assert_eq!(MIPS32Register::from_encoding(31).offset(), MIPS32Register::RA.offset());
        }
    }
}
