//! Extended instruction support for CMP, TEST, and conditional jumps

use super::decoder::{Mnemonic, Operand, DecodedInstruction, DecodeError};
use super::eflags::ConditionCode;
use super::registers::X64Register;

/// Extended decoder for conditional instructions
pub struct ConditionalDecoder;

impl ConditionalDecoder {
    /// Decode CMP instruction (0x38-0x3D, 0x80-0x83)
    ///
    pub fn decode_cmp(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // CMP r/m8, r8 (0x38)
                0x38 => {
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::CMP,
                        operands: vec![],
                        length: 2,
                    })
                }
                // CMP r/m64, r64 (0x39)
                0x39 => {
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::CMP,
                        operands: vec![],
                        length: 2,
                    })
                }
                // CMP r/m64, imm32 (0x81 /7)
                0x81 => {
                    if bytes.len() < 6 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::CMP,
                        operands: vec![],
                        length: 6,
                    })
                }
                // CMP r/m64, imm8 (0x83 /7)
                0x83 => {
                    if bytes.len() < 3 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::CMP,
                        operands: vec![],
                        length: 3,
                    })
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }

    /// Decode TEST instruction (0x84, 0x85, 0xA8, 0xA9, 0xF6, 0xF7)
    ///
    pub fn decode_test(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // TEST r/m8, r8 (0x84)
                0x84 => {
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::TEST,
                        operands: vec![],
                        length: 2,
                    })
                }
                // TEST r/m64, r64 (0x85)
                0x85 => {
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::TEST,
                        operands: vec![],
                        length: 2,
                    })
                }
                // TEST AL, imm8 (0xA8)
                0xA8 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::TEST,
                        operands: vec![
                            Operand::Register(X64Register::AL),
                            Operand::Immediate(bytes[1] as u64),
                        ],
                        length: 2,
                    })
                }
                // TEST RAX, imm32 (0xA9)
                0xA9 => {
                    if bytes.len() < 5 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let imm = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::TEST,
                        operands: vec![
                            Operand::Register(X64Register::RAX),
                            Operand::Immediate(imm),
                        ],
                        length: 5,
                    })
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }

    /// Decode conditional jump (0x70-0x7F for short, 0x0F 0x80-0x8F for near)
    ///
    pub fn decode_jcc(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            // Short conditional jumps (0x70-0x7F)
            if bytes[0] >= 0x70 && bytes[0] <= 0x7F {
                if bytes.len() < 2 {
                    return Err(DecodeError::InsufficientBytes);
                }
                let condition = bytes[0] & 0x0F;
                let offset = bytes[1] as i8 as i64;
                let mnemonic = Self::condition_to_mnemonic(condition);
                
                return Ok(DecodedInstruction {
                    mnemonic,
                    operands: vec![Operand::Immediate(offset as u64)],
                    length: 2,
                });
            }

            // Near conditional jumps (0x0F 0x80-0x8F)
            if bytes[0] == 0x0F && bytes.len() >= 2 && bytes[1] >= 0x80 && bytes[1] <= 0x8F {
                if bytes.len() < 6 {
                    return Err(DecodeError::InsufficientBytes);
                }
                let condition = bytes[1] & 0x0F;
                let offset = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as i64;
                let mnemonic = Self::condition_to_mnemonic(condition);
                
                return Ok(DecodedInstruction {
                    mnemonic,
                    operands: vec![Operand::Immediate(offset as u64)],
                    length: 6,
                });
            }

            Err(DecodeError::UnknownOpcode)
        }
    }

    /// Convert condition code to mnemonic
    ///
    fn condition_to_mnemonic(condition: u8) -> Mnemonic {
        unsafe {
            match condition {
                0x0 => Mnemonic::JO,   // Overflow
                0x1 => Mnemonic::JNO,  // Not overflow
                0x2 => Mnemonic::JB,   // Below
                0x3 => Mnemonic::JAE,  // Above or equal
                0x4 => Mnemonic::JE,   // Equal
                0x5 => Mnemonic::JNE,  // Not equal
                0x6 => Mnemonic::JBE,  // Below or equal
                0x7 => Mnemonic::JA,   // Above
                0x8 => Mnemonic::JS,   // Sign
                0x9 => Mnemonic::JNS,  // Not sign
                0xC => Mnemonic::JL,   // Less
                0xD => Mnemonic::JGE,  // Greater or equal
                0xE => Mnemonic::JLE,  // Less or equal
                0xF => Mnemonic::JG,   // Greater
                _ => Mnemonic::UNKNOWN,
            }
        }
    }

    /// Get the condition code for a jump mnemonic
    ///
    pub fn mnemonic_to_condition(mnemonic: Mnemonic) -> Option<ConditionCode> {
        unsafe {
            match mnemonic {
                Mnemonic::JO => Some(ConditionCode::O),
                Mnemonic::JNO => Some(ConditionCode::NO),
                Mnemonic::JB => Some(ConditionCode::B),
                Mnemonic::JAE => Some(ConditionCode::AE),
                Mnemonic::JE => Some(ConditionCode::E),
                Mnemonic::JNE => Some(ConditionCode::NE),
                Mnemonic::JBE => Some(ConditionCode::BE),
                Mnemonic::JA => Some(ConditionCode::A),
                Mnemonic::JS => Some(ConditionCode::S),
                Mnemonic::JNS => Some(ConditionCode::NS),
                Mnemonic::JL => Some(ConditionCode::L),
                Mnemonic::JGE => Some(ConditionCode::GE),
                Mnemonic::JLE => Some(ConditionCode::LE),
                Mnemonic::JG => Some(ConditionCode::G),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_cmp_imm8() {
        unsafe {
            // CMP rax, 5 (0x83 /7)
            let bytes = [0x83, 0xF8, 0x05];
            let result = ConditionalDecoder::decode_cmp(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::CMP);
            assert_eq!(decoded.length, 3);
        }
    }

    #[test]
    fn test_decode_test_al() {
        unsafe {
            // TEST AL, 0x80
            let bytes = [0xA8, 0x80];
            let result = ConditionalDecoder::decode_test(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::TEST);
            assert_eq!(decoded.length, 2);
        }
    }

    #[test]
    fn test_decode_je_short() {
        unsafe {
            // JE +10
            let bytes = [0x74, 0x0A];
            let result = ConditionalDecoder::decode_jcc(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::JE);
            assert_eq!(decoded.length, 2);
        }
    }

    #[test]
    fn test_decode_jne_near() {
        unsafe {
            // JNE +1000 (near)
            let bytes = [0x0F, 0x85, 0xE8, 0x03, 0x00, 0x00];
            let result = ConditionalDecoder::decode_jcc(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::JNE);
            assert_eq!(decoded.length, 6);
        }
    }
}
