//! x86-64 Instruction Decoder

use super::registers::X64Register;

/// Decoded x86-64 instruction
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedInstruction {
    /// Instruction mnemonic
    pub mnemonic: Mnemonic,
    /// Instruction operands
    pub operands: Vec<Operand>,
    /// Instruction length in bytes
    pub length: usize,
}

/// x86-64 instruction mnemonics (subset for Phase 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mnemonic {
    // Data movement
    MOV, MOVZX, MOVSX,
    PUSH, POP,
    LEA,
    
    // Arithmetic
    ADD, SUB, INC, DEC,
    MUL, IMUL, DIV, IDIV,
    NEG,
    
    // Logic
    AND, OR, XOR, NOT,
    SHL, SHR, SAR,
    
    // Comparison
    CMP, TEST,
    
    // Control flow
    JMP, JE, JNE, JL, JLE, JG, JGE,
    JA, JAE, JB, JBE, JO, JNO, JS, JNS,
    CALL, RET,
    
    // System
    NOP, HLT, SYSCALL,
    
    // Unknown
    UNKNOWN,
}

/// Instruction operand
#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    /// Register operand
    Register(X64Register),
    /// Immediate value
    Immediate(u64),
    /// Memory reference [base + index * scale + disp]
    Memory {
        base: Option<X64Register>,
        index: Option<X64Register>,
        scale: u8,
        displacement: i64,
        size: usize,
    },
}

/// Simple x86-64 instruction decoder
pub struct X64Decoder;

impl X64Decoder {
    /// Create a new decoder
    ///
    pub fn new() -> Self {
        unsafe {
            X64Decoder
        }
    }

    /// Decode a single instruction
    ///
    pub fn decode(&self, bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            // Simple pattern matching for common instructions
            // This is a minimal decoder for Phase 1 proof of concept
            
            match bytes[0] {
                // NOP (0x90)
                0x90 => Ok(DecodedInstruction {
                    mnemonic: Mnemonic::NOP,
                    operands: vec![],
                    length: 1,
                }),
                
                // RET (0xC3)
                0xC3 => Ok(DecodedInstruction {
                    mnemonic: Mnemonic::RET,
                    operands: vec![],
                    length: 1,
                }),
                
                // PUSH r64 (0x50-0x57)
                0x50..=0x57 => {
                    let reg = Self::decode_reg_in_opcode(bytes[0] - 0x50);
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::PUSH,
                        operands: vec![Operand::Register(reg)],
                        length: 1,
                    })
                }
                
                // POP r64 (0x58-0x5F)
                0x58..=0x5F => {
                    let reg = Self::decode_reg_in_opcode(bytes[0] - 0x58);
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::POP,
                        operands: vec![Operand::Register(reg)],
                        length: 1,
                    })
                }
                
                // MOV r64, imm64 (0xB8-0xBF)
                0xB8..=0xBF => {
                    if bytes.len() < 9 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let reg = Self::decode_reg_in_opcode(bytes[0] - 0xB8);
                    let imm = u64::from_le_bytes([
                        bytes[1], bytes[2], bytes[3], bytes[4],
                        bytes[5], bytes[6], bytes[7], bytes[8],
                    ]);
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::MOV,
                        operands: vec![
                            Operand::Register(reg),
                            Operand::Immediate(imm),
                        ],
                        length: 9,
                    })
                }
                
                // ADD with ModR/M (0x01, 0x03)
                0x01 | 0x03 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    // Simplified - just return as unknown for now
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::ADD,
                        operands: vec![],
                        length: 2,
                    })
                }
                
                // SUB with ModR/M (0x29, 0x2B)
                0x29 | 0x2B => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::SUB,
                        operands: vec![],
                        length: 2,
                    })
                }
                
                // JMP rel8 (0xEB)
                0xEB => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let offset = bytes[1] as i8 as i64;
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::JMP,
                        operands: vec![Operand::Immediate(offset as u64)],
                        length: 2,
                    })
                }
                
                // JMP rel32 (0xE9)
                0xE9 => {
                    if bytes.len() < 5 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::JMP,
                        operands: vec![Operand::Immediate(offset as u64)],
                        length: 5,
                    })
                }
                
                // CALL rel32 (0xE8)
                0xE8 => {
                    if bytes.len() < 5 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::CALL,
                        operands: vec![Operand::Immediate(offset as u64)],
                        length: 5,
                    })
                }
                
                _ => {
                    // Unknown instruction - return minimal info
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::UNKNOWN,
                        operands: vec![],
                        length: 1,
                    })
                }
            }
        }
    }

    /// Decode register from opcode bits
    ///
    fn decode_reg_in_opcode(bits: u8) -> X64Register {
        unsafe {
            match bits & 0x7 {
                0 => X64Register::RAX,
                1 => X64Register::RCX,
                2 => X64Register::RDX,
                3 => X64Register::RBX,
                4 => X64Register::RSP,
                5 => X64Register::RBP,
                6 => X64Register::RSI,
                7 => X64Register::RDI,
                _ => X64Register::RAX,
            }
        }
    }
}

/// Decoder errors
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("Insufficient bytes to decode instruction")]
    InsufficientBytes,
    
    #[error("Invalid instruction encoding")]
    InvalidEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_nop() {
        unsafe {
            let decoder = X64Decoder::new();
            let insn = decoder.decode(&[0x90]).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::NOP);
            assert_eq!(insn.length, 1);
        }
    }

    #[test]
    fn test_decode_ret() {
        unsafe {
            let decoder = X64Decoder::new();
            let insn = decoder.decode(&[0xC3]).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::RET);
            assert_eq!(insn.length, 1);
        }
    }

    #[test]
    fn test_decode_push() {
        unsafe {
            let decoder = X64Decoder::new();
            let insn = decoder.decode(&[0x50]).unwrap();  // PUSH RAX
            assert_eq!(insn.mnemonic, Mnemonic::PUSH);
            assert_eq!(insn.length, 1);
            assert_eq!(insn.operands.len(), 1);
        }
    }

    #[test]
    fn test_decode_mov_imm() {
        unsafe {
            let decoder = X64Decoder::new();
            // MOV RAX, 0x1122334455667788
            let bytes = [0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
            let insn = decoder.decode(&bytes).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::MOV);
            assert_eq!(insn.length, 9);
        }
    }

    #[test]
    fn test_decode_jmp_rel8() {
        unsafe {
            let decoder = X64Decoder::new();
            let insn = decoder.decode(&[0xEB, 0x10]).unwrap();  // JMP +16
            assert_eq!(insn.mnemonic, Mnemonic::JMP);
            assert_eq!(insn.length, 2);
        }
    }

    #[test]
    fn test_decode_call() {
        unsafe {
            let decoder = X64Decoder::new();
            let insn = decoder.decode(&[0xE8, 0x00, 0x00, 0x00, 0x00]).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::CALL);
            assert_eq!(insn.length, 5);
        }
    }
}
