//! x86-64 ModR/M and SIB Byte Decoder

use super::registers::X64Register;

/// ModR/M byte fields
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModRM {
    pub mod_field: u8,  // Top 2 bits
    pub reg: u8,        // Middle 3 bits
    pub rm: u8,         // Bottom 3 bits
}

impl ModRM {
    /// Parse a ModR/M byte
    ///
    pub fn decode(byte: u8) -> Self {
        unsafe {
            Self {
                mod_field: (byte >> 6) & 0x03,
                reg: (byte >> 3) & 0x07,
                rm: byte & 0x07,
            }
        }
    }
}

/// SIB byte fields
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SIB {
    pub scale: u8,  // Top 2 bits -> 1, 2, 4, or 8
    pub index: u8,  // Middle 3 bits
    pub base: u8,   // Bottom 3 bits
}

impl SIB {
    /// Parse a SIB byte
    ///
    pub fn decode(byte: u8) -> Self {
        unsafe {
            Self {
                scale: (byte >> 6) & 0x03,
                index: (byte >> 3) & 0x07,
                base: byte & 0x07,
            }
        }
    }

    /// Get the actual scale value (1, 2, 4, or 8)
    ///
    pub fn scale_value(&self) -> u8 {
        unsafe {
            1 << self.scale
        }
    }
}

/// Memory operand addressing mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryAddress {
    /// Direct register: [reg]
    RegisterDirect { base: X64Register },
    
    /// Register + displacement: [reg + disp]
    RegisterDisplacement { base: X64Register, disp: i32 },
    
    /// Base + Index: [base + index]
    BaseIndex { base: X64Register, index: X64Register },
    
    /// Base + Index + displacement: [base + index + disp]
    BaseIndexDisplacement { base: X64Register, index: X64Register, disp: i32 },
    
    /// Base + Index*Scale: [base + index*scale]
    BaseIndexScale { base: X64Register, index: X64Register, scale: u8 },
    
    /// Base + Index*Scale + displacement: [base + index*scale + disp]
    BaseIndexScaleDisplacement { base: X64Register, index: X64Register, scale: u8, disp: i32 },
    
    /// Index*Scale: [index*scale]
    IndexScale { index: X64Register, scale: u8 },
    
    /// Index*Scale + displacement: [index*scale + disp]
    IndexScaleDisplacement { index: X64Register, scale: u8, disp: i32 },
    
    /// Absolute/direct address: [disp]
    Displacement { disp: i32 },
    
    /// RIP-relative: [RIP + disp]
    RIPRelative { disp: i32 },
}

/// Result of ModR/M decoding
#[derive(Debug, Clone)]
pub struct ModRMResult {
    pub reg: X64Register,          // Register from reg field
    pub operand: ModRMOperand,     // The R/M operand
    pub bytes_consumed: usize,     // How many bytes were consumed
}

/// Operand type from R/M field
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModRMOperand {
    Register(X64Register),
    Memory(MemoryAddress),
}

/// ModR/M decoder
pub struct ModRMDecoder;

impl ModRMDecoder {
    /// Decode ModR/M byte and potential SIB byte and displacement
    ///
    pub fn decode(bytes: &[u8], has_rex: bool, rex_r: bool, rex_x: bool, rex_b: bool) -> Option<ModRMResult> {
        unsafe {
            if bytes.is_empty() {
                return None;
            }

            let modrm = ModRM::decode(bytes[0]);
            let mut offset = 1;

            // Decode the reg field
            let reg_num = if rex_r { modrm.reg | 0x08 } else { modrm.reg };
            let reg = Self::decode_register(reg_num);

            // Decode the R/M field based on mod
            let operand = match modrm.mod_field {
                // Mod = 00: Memory indirect (no displacement, except special cases)
                0b00 => {
                    if modrm.rm == 0b100 {
                        // SIB byte follows
                        if bytes.len() < 2 {
                            return None;
                        }
                        let sib = SIB::decode(bytes[offset]);
                        offset += 1;

                        let base_num = if rex_b { sib.base | 0x08 } else { sib.base };
                        let index_num = if rex_x { sib.index | 0x08 } else { sib.index };

                        if sib.base == 0b101 {
                            // Special case: no base, disp32 follows
                            if bytes.len() < offset + 4 {
                                return None;
                            }
                            let disp = i32::from_le_bytes([
                                bytes[offset], bytes[offset + 1],
                                bytes[offset + 2], bytes[offset + 3]
                            ]);
                            offset += 4;

                            if sib.index == 0b100 {
                                // No index either
                                ModRMOperand::Memory(MemoryAddress::Displacement { disp })
                            } else {
                                let index = Self::decode_register(index_num);
                                ModRMOperand::Memory(MemoryAddress::IndexScaleDisplacement {
                                    index,
                                    scale: sib.scale_value(),
                                    disp,
                                })
                            }
                        } else {
                            let base = Self::decode_register(base_num);
                            
                            if sib.index == 0b100 {
                                // No index
                                ModRMOperand::Memory(MemoryAddress::RegisterDirect { base })
                            } else {
                                let index = Self::decode_register(index_num);
                                if sib.scale == 0 {
                                    ModRMOperand::Memory(MemoryAddress::BaseIndex { base, index })
                                } else {
                                    ModRMOperand::Memory(MemoryAddress::BaseIndexScale {
                                        base,
                                        index,
                                        scale: sib.scale_value(),
                                    })
                                }
                            }
                        }
                    } else if modrm.rm == 0b101 {
                        // RIP-relative or disp32
                        if bytes.len() < offset + 4 {
                            return None;
                        }
                        let disp = i32::from_le_bytes([
                            bytes[offset], bytes[offset + 1],
                            bytes[offset + 2], bytes[offset + 3]
                        ]);
                        offset += 4;
                        
                        // In 64-bit mode, this is RIP-relative
                        ModRMOperand::Memory(MemoryAddress::RIPRelative { disp })
                    } else {
                        // Simple register indirect
                        let rm_num = if rex_b { modrm.rm | 0x08 } else { modrm.rm };
                        let base = Self::decode_register(rm_num);
                        ModRMOperand::Memory(MemoryAddress::RegisterDirect { base })
                    }
                }

                // Mod = 01: Memory indirect with 8-bit displacement
                0b01 => {
                    if modrm.rm == 0b100 {
                        // SIB byte follows
                        if bytes.len() < 2 {
                            return None;
                        }
                        let sib = SIB::decode(bytes[offset]);
                        offset += 1;

                        if bytes.len() < offset + 1 {
                            return None;
                        }
                        let disp = bytes[offset] as i8 as i32;
                        offset += 1;

                        let base_num = if rex_b { sib.base | 0x08 } else { sib.base };
                        let index_num = if rex_x { sib.index | 0x08 } else { sib.index };
                        let base = Self::decode_register(base_num);

                        if sib.index == 0b100 {
                            ModRMOperand::Memory(MemoryAddress::RegisterDisplacement { base, disp })
                        } else {
                            let index = Self::decode_register(index_num);
                            if sib.scale == 0 {
                                ModRMOperand::Memory(MemoryAddress::BaseIndexDisplacement {
                                    base, index, disp,
                                })
                            } else {
                                ModRMOperand::Memory(MemoryAddress::BaseIndexScaleDisplacement {
                                    base,
                                    index,
                                    scale: sib.scale_value(),
                                    disp,
                                })
                            }
                        }
                    } else {
                        // Register + disp8
                        if bytes.len() < offset + 1 {
                            return None;
                        }
                        let disp = bytes[offset] as i8 as i32;
                        offset += 1;

                        let rm_num = if rex_b { modrm.rm | 0x08 } else { modrm.rm };
                        let base = Self::decode_register(rm_num);
                        ModRMOperand::Memory(MemoryAddress::RegisterDisplacement { base, disp })
                    }
                }

                // Mod = 10: Memory indirect with 32-bit displacement
                0b10 => {
                    if modrm.rm == 0b100 {
                        // SIB byte follows
                        if bytes.len() < 2 {
                            return None;
                        }
                        let sib = SIB::decode(bytes[offset]);
                        offset += 1;

                        if bytes.len() < offset + 4 {
                            return None;
                        }
                        let disp = i32::from_le_bytes([
                            bytes[offset], bytes[offset + 1],
                            bytes[offset + 2], bytes[offset + 3]
                        ]);
                        offset += 4;

                        let base_num = if rex_b { sib.base | 0x08 } else { sib.base };
                        let index_num = if rex_x { sib.index | 0x08 } else { sib.index };
                        let base = Self::decode_register(base_num);

                        if sib.index == 0b100 {
                            ModRMOperand::Memory(MemoryAddress::RegisterDisplacement { base, disp })
                        } else {
                            let index = Self::decode_register(index_num);
                            if sib.scale == 0 {
                                ModRMOperand::Memory(MemoryAddress::BaseIndexDisplacement {
                                    base, index, disp,
                                })
                            } else {
                                ModRMOperand::Memory(MemoryAddress::BaseIndexScaleDisplacement {
                                    base,
                                    index,
                                    scale: sib.scale_value(),
                                    disp,
                                })
                            }
                        }
                    } else {
                        // Register + disp32
                        if bytes.len() < offset + 4 {
                            return None;
                        }
                        let disp = i32::from_le_bytes([
                            bytes[offset], bytes[offset + 1],
                            bytes[offset + 2], bytes[offset + 3]
                        ]);
                        offset += 4;

                        let rm_num = if rex_b { modrm.rm | 0x08 } else { modrm.rm };
                        let base = Self::decode_register(rm_num);
                        ModRMOperand::Memory(MemoryAddress::RegisterDisplacement { base, disp })
                    }
                }

                // Mod = 11: Register direct
                0b11 => {
                    let rm_num = if rex_b { modrm.rm | 0x08 } else { modrm.rm };
                    let rm_reg = Self::decode_register(rm_num);
                    ModRMOperand::Register(rm_reg)
                }

                _ => unreachable!(),
            };

            Some(ModRMResult {
                reg,
                operand,
                bytes_consumed: offset,
            })
        }
    }

    /// Decode a register number to X64Register
    ///
    fn decode_register(num: u8) -> X64Register {
        unsafe {
            match num & 0x0F {
                0 => X64Register::RAX,
                1 => X64Register::RCX,
                2 => X64Register::RDX,
                3 => X64Register::RBX,
                4 => X64Register::RSP,
                5 => X64Register::RBP,
                6 => X64Register::RSI,
                7 => X64Register::RDI,
                8 => X64Register::R8,
                9 => X64Register::R9,
                10 => X64Register::R10,
                11 => X64Register::R11,
                12 => X64Register::R12,
                13 => X64Register::R13,
                14 => X64Register::R14,
                _ => X64Register::R15,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modrm_decode() {
        unsafe {
            // ModR/M byte: mod=11 (register), reg=001 (RCX), rm=000 (RAX)
            let modrm = ModRM::decode(0b11_001_000);
            assert_eq!(modrm.mod_field, 0b11);
            assert_eq!(modrm.reg, 0b001);
            assert_eq!(modrm.rm, 0b000);
        }
    }

    #[test]
    fn test_sib_decode() {
        unsafe {
            // SIB byte: scale=10 (4x), index=001 (RCX), base=000 (RAX)
            let sib = SIB::decode(0b10_001_000);
            assert_eq!(sib.scale, 0b10);
            assert_eq!(sib.scale_value(), 4);
            assert_eq!(sib.index, 0b001);
            assert_eq!(sib.base, 0b000);
        }
    }

    #[test]
    fn test_register_direct() {
        unsafe {
            // MOV RAX, RBX: ModR/M = 0b11_000_011
            let bytes = [0b11_000_011];
            let result = ModRMDecoder::decode(&bytes, false, false, false, false);
            assert!(result.is_some());
            let result = result.unwrap();
            assert_eq!(result.bytes_consumed, 1);
            match result.operand {
                ModRMOperand::Register(reg) => assert_eq!(reg, X64Register::RBX),
                _ => panic!("Expected register operand"),
            }
        }
    }

    #[test]
    fn test_memory_indirect() {
        unsafe {
            // MOV RAX, [RBX]: ModR/M = 0b00_000_011
            let bytes = [0b00_000_011];
            let result = ModRMDecoder::decode(&bytes, false, false, false, false);
            assert!(result.is_some());
            let result = result.unwrap();
            assert_eq!(result.bytes_consumed, 1);
            match result.operand {
                ModRMOperand::Memory(MemoryAddress::RegisterDirect { base }) => {
                    assert_eq!(base, X64Register::RBX);
                }
                _ => panic!("Expected memory operand"),
            }
        }
    }

    #[test]
    fn test_memory_displacement8() {
        unsafe {
            // MOV RAX, [RBX + 10]: ModR/M = 0b01_000_011, disp8 = 10
            let bytes = [0b01_000_011, 10];
            let result = ModRMDecoder::decode(&bytes, false, false, false, false);
            assert!(result.is_some());
            let result = result.unwrap();
            assert_eq!(result.bytes_consumed, 2);
            match result.operand {
                ModRMOperand::Memory(MemoryAddress::RegisterDisplacement { base, disp }) => {
                    assert_eq!(base, X64Register::RBX);
                    assert_eq!(disp, 10);
                }
                _ => panic!("Expected memory displacement operand"),
            }
        }
    }

    #[test]
    fn test_sib_base_index_scale() {
        unsafe {
            // MOV RAX, [RBX + RCX*4]: ModR/M = 0b00_000_100, SIB = 0b10_001_011
            let bytes = [0b00_000_100, 0b10_001_011];
            let result = ModRMDecoder::decode(&bytes, false, false, false, false);
            assert!(result.is_some());
            let result = result.unwrap();
            assert_eq!(result.bytes_consumed, 2);
            match result.operand {
                ModRMOperand::Memory(MemoryAddress::BaseIndexScale { base, index, scale }) => {
                    assert_eq!(base, X64Register::RBX);
                    assert_eq!(index, X64Register::RCX);
                    assert_eq!(scale, 4);
                }
                _ => panic!("Expected SIB operand"),
            }
        }
    }
}
