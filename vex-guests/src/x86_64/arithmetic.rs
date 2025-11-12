//! Extended arithmetic instruction support

use super::decoder::{Mnemonic, Operand, DecodedInstruction, DecodeError};
use super::registers::X64Register;

/// Extended decoder for arithmetic instructions
pub struct ArithmeticDecoder;

impl ArithmeticDecoder {
    /// Decode INC instruction (0xFE /0, 0xFF /0)
    ///
    pub fn decode_inc(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // INC r/m8 (0xFE /0)
                0xFE => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::INC,
                        operands: vec![],
                        length: 2,
                    })
                }
                // INC r/m64 (0xFF /0)
                0xFF => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    // Check that reg field is 0
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 0 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::INC,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }

    /// Decode DEC instruction (0xFE /1, 0xFF /1)
    ///
    pub fn decode_dec(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // DEC r/m8 (0xFE /1)
                0xFE => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 1 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::DEC,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                // DEC r/m64 (0xFF /1)
                0xFF => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 1 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::DEC,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }

    /// Decode NEG instruction (0xF6 /3, 0xF7 /3)
    ///
    pub fn decode_neg(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // NEG r/m8 (0xF6 /3)
                0xF6 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 3 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::NEG,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                // NEG r/m64 (0xF7 /3)
                0xF7 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 3 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::NEG,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }

    /// Decode NOT instruction (0xF6 /2, 0xF7 /2)
    ///
    pub fn decode_not(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // NOT r/m8 (0xF6 /2)
                0xF6 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 2 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::NOT,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                // NOT r/m64 (0xF7 /2)
                0xF7 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 2 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::NOT,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }

    /// Decode MUL instruction (0xF6 /4, 0xF7 /4)
    ///
    pub fn decode_mul(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // MUL r/m8 (0xF6 /4)
                0xF6 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 4 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::MUL,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                // MUL r/m64 (0xF7 /4)
                0xF7 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 4 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::MUL,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }

    /// Decode IMUL instruction (0xF6 /5, 0xF7 /5, 0x0F 0xAF, 0x69, 0x6B)
    ///
    pub fn decode_imul(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // IMUL r/m8 (0xF6 /5)
                0xF6 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 5 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::IMUL,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                // IMUL r/m64 (0xF7 /5)
                0xF7 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 5 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::IMUL,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                // IMUL r64, r/m64 (0x0F 0xAF)
                0x0F => {
                    if bytes.len() < 3 || bytes[1] != 0xAF {
                        return Err(DecodeError::UnknownOpcode);
                    }
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::IMUL,
                        operands: vec![],
                        length: 3,
                    })
                }
                // IMUL r64, r/m64, imm32 (0x69)
                0x69 => {
                    if bytes.len() < 6 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::IMUL,
                        operands: vec![],
                        length: 6,
                    })
                }
                // IMUL r64, r/m64, imm8 (0x6B)
                0x6B => {
                    if bytes.len() < 3 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    Ok(DecodedInstruction {
                        mnemonic: Mnemonic::IMUL,
                        operands: vec![],
                        length: 3,
                    })
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }

    /// Decode DIV instruction (0xF6 /6, 0xF7 /6)
    ///
    pub fn decode_div(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // DIV r/m8 (0xF6 /6)
                0xF6 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 6 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::DIV,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                // DIV r/m64 (0xF7 /6)
                0xF7 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 6 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::DIV,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }

    /// Decode IDIV instruction (0xF6 /7, 0xF7 /7)
    ///
    pub fn decode_idiv(bytes: &[u8]) -> Result<DecodedInstruction, DecodeError> {
        unsafe {
            if bytes.is_empty() {
                return Err(DecodeError::InsufficientBytes);
            }

            match bytes[0] {
                // IDIV r/m8 (0xF6 /7)
                0xF6 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 7 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::IDIV,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                // IDIV r/m64 (0xF7 /7)
                0xF7 => {
                    if bytes.len() < 2 {
                        return Err(DecodeError::InsufficientBytes);
                    }
                    let modrm = bytes[1];
                    let reg = (modrm >> 3) & 0x07;
                    if reg == 7 {
                        Ok(DecodedInstruction {
                            mnemonic: Mnemonic::IDIV,
                            operands: vec![],
                            length: 2,
                        })
                    } else {
                        Err(DecodeError::UnknownOpcode)
                    }
                }
                _ => Err(DecodeError::UnknownOpcode),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_inc() {
        unsafe {
            // INC rax (0xFF /0, ModR/M = 0xC0)
            let bytes = [0xFF, 0xC0];
            let result = ArithmeticDecoder::decode_inc(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::INC);
            assert_eq!(decoded.length, 2);
        }
    }

    #[test]
    fn test_decode_dec() {
        unsafe {
            // DEC rax (0xFF /1, ModR/M = 0xC8)
            let bytes = [0xFF, 0xC8];
            let result = ArithmeticDecoder::decode_dec(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::DEC);
            assert_eq!(decoded.length, 2);
        }
    }

    #[test]
    fn test_decode_neg() {
        unsafe {
            // NEG rax (0xF7 /3, ModR/M = 0xD8)
            let bytes = [0xF7, 0xD8];
            let result = ArithmeticDecoder::decode_neg(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::NEG);
            assert_eq!(decoded.length, 2);
        }
    }

    #[test]
    fn test_decode_not() {
        unsafe {
            // NOT rax (0xF7 /2, ModR/M = 0xD0)
            let bytes = [0xF7, 0xD0];
            let result = ArithmeticDecoder::decode_not(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::NOT);
            assert_eq!(decoded.length, 2);
        }
    }

    #[test]
    fn test_decode_mul() {
        unsafe {
            // MUL rcx (0xF7 /4, ModR/M = 0xE1)
            let bytes = [0xF7, 0xE1];
            let result = ArithmeticDecoder::decode_mul(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::MUL);
            assert_eq!(decoded.length, 2);
        }
    }

    #[test]
    fn test_decode_imul_two_operand() {
        unsafe {
            // IMUL rax, rcx (0x0F 0xAF)
            let bytes = [0x0F, 0xAF, 0xC1];
            let result = ArithmeticDecoder::decode_imul(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::IMUL);
            assert_eq!(decoded.length, 3);
        }
    }

    #[test]
    fn test_decode_div() {
        unsafe {
            // DIV rcx (0xF7 /6, ModR/M = 0xF1)
            let bytes = [0xF7, 0xF1];
            let result = ArithmeticDecoder::decode_div(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::DIV);
            assert_eq!(decoded.length, 2);
        }
    }

    #[test]
    fn test_decode_idiv() {
        unsafe {
            // IDIV rcx (0xF7 /7, ModR/M = 0xF9)
            let bytes = [0xF7, 0xF9];
            let result = ArithmeticDecoder::decode_idiv(&bytes);
            assert!(result.is_ok());
            let decoded = result.unwrap();
            assert_eq!(decoded.mnemonic, Mnemonic::IDIV);
            assert_eq!(decoded.length, 2);
        }
    }
}
