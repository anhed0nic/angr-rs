//! ARM64 (AArch64) Register Definitions

/// ARM64 register offsets in guest state
pub mod offsets {
    // General purpose registers (64-bit)
    pub const X0: usize = 0;
    pub const X1: usize = 8;
    pub const X2: usize = 16;
    pub const X3: usize = 24;
    pub const X4: usize = 32;
    pub const X5: usize = 40;
    pub const X6: usize = 48;
    pub const X7: usize = 56;
    pub const X8: usize = 64;
    pub const X9: usize = 72;
    pub const X10: usize = 80;
    pub const X11: usize = 88;
    pub const X12: usize = 96;
    pub const X13: usize = 104;
    pub const X14: usize = 112;
    pub const X15: usize = 120;
    pub const X16: usize = 128;
    pub const X17: usize = 136;
    pub const X18: usize = 144;
    pub const X19: usize = 152;
    pub const X20: usize = 160;
    pub const X21: usize = 168;
    pub const X22: usize = 176;
    pub const X23: usize = 184;
    pub const X24: usize = 192;
    pub const X25: usize = 200;
    pub const X26: usize = 208;
    pub const X27: usize = 216;
    pub const X28: usize = 224;
    pub const X29_FP: usize = 232;  // Frame pointer
    pub const X30_LR: usize = 240;  // Link register
    pub const XZR_SP: usize = 248;  // Zero register / Stack pointer

    // Program counter
    pub const PC: usize = 256;
    
    // Processor state
    pub const PSTATE: usize = 264;
}

/// ARM64 register enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ARM64Register {
    // 64-bit general purpose
    X0, X1, X2, X3, X4, X5, X6, X7,
    X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23,
    X24, X25, X26, X27, X28, X29, X30,
    
    // 32-bit general purpose (lower half of X registers)
    W0, W1, W2, W3, W4, W5, W6, W7,
    W8, W9, W10, W11, W12, W13, W14, W15,
    W16, W17, W18, W19, W20, W21, W22, W23,
    W24, W25, W26, W27, W28, W29, W30,
    
    // Special
    FP,    // X29
    LR,    // X30
    SP,    // Stack pointer
    XZR,   // Zero register
    PC,
    PSTATE,
}

impl ARM64Register {
    /// Get the offset in guest state for this register
    ///
    pub fn offset(&self) -> usize {
        unsafe {
            use ARM64Register::*;
            match self {
                X0 | W0 => offsets::X0,
                X1 | W1 => offsets::X1,
                X2 | W2 => offsets::X2,
                X3 | W3 => offsets::X3,
                X4 | W4 => offsets::X4,
                X5 | W5 => offsets::X5,
                X6 | W6 => offsets::X6,
                X7 | W7 => offsets::X7,
                X8 | W8 => offsets::X8,
                X9 | W9 => offsets::X9,
                X10 | W10 => offsets::X10,
                X11 | W11 => offsets::X11,
                X12 | W12 => offsets::X12,
                X13 | W13 => offsets::X13,
                X14 | W14 => offsets::X14,
                X15 | W15 => offsets::X15,
                X16 | W16 => offsets::X16,
                X17 | W17 => offsets::X17,
                X18 | W18 => offsets::X18,
                X19 | W19 => offsets::X19,
                X20 | W20 => offsets::X20,
                X21 | W21 => offsets::X21,
                X22 | W22 => offsets::X22,
                X23 | W23 => offsets::X23,
                X24 | W24 => offsets::X24,
                X25 | W25 => offsets::X25,
                X26 | W26 => offsets::X26,
                X27 | W27 => offsets::X27,
                X28 | W28 => offsets::X28,
                X29 | W29 | FP => offsets::X29_FP,
                X30 | W30 | LR => offsets::X30_LR,
                SP | XZR => offsets::XZR_SP,
                PC => offsets::PC,
                PSTATE => offsets::PSTATE,
            }
        }
    }

    /// Get the size in bytes of this register
    ///
    pub fn size(&self) -> usize {
        unsafe {
            use ARM64Register::*;
            match self {
                X0 | X1 | X2 | X3 | X4 | X5 | X6 | X7 |
                X8 | X9 | X10 | X11 | X12 | X13 | X14 | X15 |
                X16 | X17 | X18 | X19 | X20 | X21 | X22 | X23 |
                X24 | X25 | X26 | X27 | X28 | X29 | X30 |
                FP | LR | SP | XZR | PC => 8,
                
                W0 | W1 | W2 | W3 | W4 | W5 | W6 | W7 |
                W8 | W9 | W10 | W11 | W12 | W13 | W14 | W15 |
                W16 | W17 | W18 | W19 | W20 | W21 | W22 | W23 |
                W24 | W25 | W26 | W27 | W28 | W29 | W30 => 4,
                
                PSTATE => 4,
            }
        }
    }

    /// Get the IR type for this register
    ///
    pub fn ir_type(&self) -> vex_core::ir::IRType {
        unsafe {
            use vex_core::ir::IRType;
            if self.size() == 8 {
                IRType::I64
            } else {
                IRType::I32
            }
        }
    }

    /// Decode register from 5-bit encoding
    ///
    pub fn from_encoding(bits: u8, is_64bit: bool) -> Self {
        unsafe {
            let reg = bits & 0x1F;
            if is_64bit {
                match reg {
                    0 => ARM64Register::X0,
                    1 => ARM64Register::X1,
                    2 => ARM64Register::X2,
                    3 => ARM64Register::X3,
                    4 => ARM64Register::X4,
                    5 => ARM64Register::X5,
                    6 => ARM64Register::X6,
                    7 => ARM64Register::X7,
                    8 => ARM64Register::X8,
                    9 => ARM64Register::X9,
                    10 => ARM64Register::X10,
                    11 => ARM64Register::X11,
                    12 => ARM64Register::X12,
                    13 => ARM64Register::X13,
                    14 => ARM64Register::X14,
                    15 => ARM64Register::X15,
                    16 => ARM64Register::X16,
                    17 => ARM64Register::X17,
                    18 => ARM64Register::X18,
                    19 => ARM64Register::X19,
                    20 => ARM64Register::X20,
                    21 => ARM64Register::X21,
                    22 => ARM64Register::X22,
                    23 => ARM64Register::X23,
                    24 => ARM64Register::X24,
                    25 => ARM64Register::X25,
                    26 => ARM64Register::X26,
                    27 => ARM64Register::X27,
                    28 => ARM64Register::X28,
                    29 => ARM64Register::FP,
                    30 => ARM64Register::LR,
                    _ => ARM64Register::SP,
                }
            } else {
                match reg {
                    0 => ARM64Register::W0,
                    1 => ARM64Register::W1,
                    2 => ARM64Register::W2,
                    3 => ARM64Register::W3,
                    4 => ARM64Register::W4,
                    5 => ARM64Register::W5,
                    6 => ARM64Register::W6,
                    7 => ARM64Register::W7,
                    8 => ARM64Register::W8,
                    9 => ARM64Register::W9,
                    10 => ARM64Register::W10,
                    11 => ARM64Register::W11,
                    12 => ARM64Register::W12,
                    13 => ARM64Register::W13,
                    14 => ARM64Register::W14,
                    15 => ARM64Register::W15,
                    16 => ARM64Register::W16,
                    17 => ARM64Register::W17,
                    18 => ARM64Register::W18,
                    19 => ARM64Register::W19,
                    20 => ARM64Register::W20,
                    21 => ARM64Register::W21,
                    22 => ARM64Register::W22,
                    23 => ARM64Register::W23,
                    24 => ARM64Register::W24,
                    25 => ARM64Register::W25,
                    26 => ARM64Register::W26,
                    27 => ARM64Register::W27,
                    28 => ARM64Register::W28,
                    29 => ARM64Register::W29,
                    _ => ARM64Register::W30,
                }
            }
        }
    }
}
