//! MIPS32 Instruction Decoder

use super::registers::MIPS32Register;

/// Decoded MIPS32 instruction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedMIPS32 {
    // R-Type Instructions
    ADD { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    ADDU { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    SUB { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    SUBU { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    AND { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    OR { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    XOR { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    NOR { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    SLT { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    SLTU { rd: MIPS32Register, rs: MIPS32Register, rt: MIPS32Register },
    SLL { rd: MIPS32Register, rt: MIPS32Register, shamt: u8 },
    SRL { rd: MIPS32Register, rt: MIPS32Register, shamt: u8 },
    SRA { rd: MIPS32Register, rt: MIPS32Register, shamt: u8 },
    SLLV { rd: MIPS32Register, rt: MIPS32Register, rs: MIPS32Register },
    SRLV { rd: MIPS32Register, rt: MIPS32Register, rs: MIPS32Register },
    SRAV { rd: MIPS32Register, rt: MIPS32Register, rs: MIPS32Register },
    MULT { rs: MIPS32Register, rt: MIPS32Register },
    MULTU { rs: MIPS32Register, rt: MIPS32Register },
    DIV { rs: MIPS32Register, rt: MIPS32Register },
    DIVU { rs: MIPS32Register, rt: MIPS32Register },
    MFHI { rd: MIPS32Register },
    MFLO { rd: MIPS32Register },
    MTHI { rs: MIPS32Register },
    MTLO { rs: MIPS32Register },
    JR { rs: MIPS32Register },
    JALR { rd: MIPS32Register, rs: MIPS32Register },

    // I-Type Instructions
    ADDI { rt: MIPS32Register, rs: MIPS32Register, imm: i16 },
    ADDIU { rt: MIPS32Register, rs: MIPS32Register, imm: i16 },
    ANDI { rt: MIPS32Register, rs: MIPS32Register, imm: u16 },
    ORI { rt: MIPS32Register, rs: MIPS32Register, imm: u16 },
    XORI { rt: MIPS32Register, rs: MIPS32Register, imm: u16 },
    LUI { rt: MIPS32Register, imm: u16 },
    SLTI { rt: MIPS32Register, rs: MIPS32Register, imm: i16 },
    SLTIU { rt: MIPS32Register, rs: MIPS32Register, imm: i16 },
    BEQ { rs: MIPS32Register, rt: MIPS32Register, offset: i16 },
    BNE { rs: MIPS32Register, rt: MIPS32Register, offset: i16 },
    BLEZ { rs: MIPS32Register, offset: i16 },
    BGTZ { rs: MIPS32Register, offset: i16 },
    LW { rt: MIPS32Register, rs: MIPS32Register, offset: i16 },
    LH { rt: MIPS32Register, rs: MIPS32Register, offset: i16 },
    LHU { rt: MIPS32Register, rs: MIPS32Register, offset: i16 },
    LB { rt: MIPS32Register, rs: MIPS32Register, offset: i16 },
    LBU { rt: MIPS32Register, rs: MIPS32Register, offset: i16 },
    SW { rt: MIPS32Register, rs: MIPS32Register, offset: i16 },
    SH { rt: MIPS32Register, rs: MIPS32Register, offset: i16 },
    SB { rt: MIPS32Register, rs: MIPS32Register, offset: i16 },

    // J-Type Instructions
    J { target: u32 },
    JAL { target: u32 },

    // Special
    NOP,
    Unknown { opcode: u32 },
}

/// MIPS32 instruction decoder
pub struct MIPS32Decoder;

impl MIPS32Decoder {
    /// Decode a 32-bit MIPS instruction
    ///
    pub fn decode(instruction: u32) -> DecodedMIPS32 {
        unsafe {
            let opcode = (instruction >> 26) & 0x3F;
            let rs = ((instruction >> 21) & 0x1F) as u8;
            let rt = ((instruction >> 16) & 0x1F) as u8;
            let rd = ((instruction >> 11) & 0x1F) as u8;
            let shamt = ((instruction >> 6) & 0x1F) as u8;
            let funct = instruction & 0x3F;
            let imm = (instruction & 0xFFFF) as u16;
            let imm_signed = imm as i16;
            let target = instruction & 0x03FFFFFF;

            match opcode {
                0x00 => {
                    // R-Type instructions
                    match funct {
                        0x00 => {
                            if instruction == 0 {
                                DecodedMIPS32::NOP
                            } else {
                                DecodedMIPS32::SLL {
                                    rd: MIPS32Register::from_encoding(rd),
                                    rt: MIPS32Register::from_encoding(rt),
                                    shamt,
                                }
                            }
                        }
                        0x02 => DecodedMIPS32::SRL {
                            rd: MIPS32Register::from_encoding(rd),
                            rt: MIPS32Register::from_encoding(rt),
                            shamt,
                        },
                        0x03 => DecodedMIPS32::SRA {
                            rd: MIPS32Register::from_encoding(rd),
                            rt: MIPS32Register::from_encoding(rt),
                            shamt,
                        },
                        0x04 => DecodedMIPS32::SLLV {
                            rd: MIPS32Register::from_encoding(rd),
                            rt: MIPS32Register::from_encoding(rt),
                            rs: MIPS32Register::from_encoding(rs),
                        },
                        0x06 => DecodedMIPS32::SRLV {
                            rd: MIPS32Register::from_encoding(rd),
                            rt: MIPS32Register::from_encoding(rt),
                            rs: MIPS32Register::from_encoding(rs),
                        },
                        0x07 => DecodedMIPS32::SRAV {
                            rd: MIPS32Register::from_encoding(rd),
                            rt: MIPS32Register::from_encoding(rt),
                            rs: MIPS32Register::from_encoding(rs),
                        },
                        0x08 => DecodedMIPS32::JR {
                            rs: MIPS32Register::from_encoding(rs),
                        },
                        0x09 => DecodedMIPS32::JALR {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                        },
                        0x10 => DecodedMIPS32::MFHI {
                            rd: MIPS32Register::from_encoding(rd),
                        },
                        0x11 => DecodedMIPS32::MTHI {
                            rs: MIPS32Register::from_encoding(rs),
                        },
                        0x12 => DecodedMIPS32::MFLO {
                            rd: MIPS32Register::from_encoding(rd),
                        },
                        0x13 => DecodedMIPS32::MTLO {
                            rs: MIPS32Register::from_encoding(rs),
                        },
                        0x18 => DecodedMIPS32::MULT {
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x19 => DecodedMIPS32::MULTU {
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x1A => DecodedMIPS32::DIV {
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x1B => DecodedMIPS32::DIVU {
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x20 => DecodedMIPS32::ADD {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x21 => DecodedMIPS32::ADDU {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x22 => DecodedMIPS32::SUB {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x23 => DecodedMIPS32::SUBU {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x24 => DecodedMIPS32::AND {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x25 => DecodedMIPS32::OR {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x26 => DecodedMIPS32::XOR {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x27 => DecodedMIPS32::NOR {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x2A => DecodedMIPS32::SLT {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        0x2B => DecodedMIPS32::SLTU {
                            rd: MIPS32Register::from_encoding(rd),
                            rs: MIPS32Register::from_encoding(rs),
                            rt: MIPS32Register::from_encoding(rt),
                        },
                        _ => DecodedMIPS32::Unknown { opcode: instruction },
                    }
                }
                0x02 => DecodedMIPS32::J { target },
                0x03 => DecodedMIPS32::JAL { target },
                0x04 => DecodedMIPS32::BEQ {
                    rs: MIPS32Register::from_encoding(rs),
                    rt: MIPS32Register::from_encoding(rt),
                    offset: imm_signed,
                },
                0x05 => DecodedMIPS32::BNE {
                    rs: MIPS32Register::from_encoding(rs),
                    rt: MIPS32Register::from_encoding(rt),
                    offset: imm_signed,
                },
                0x06 => DecodedMIPS32::BLEZ {
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                0x07 => DecodedMIPS32::BGTZ {
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                0x08 => DecodedMIPS32::ADDI {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    imm: imm_signed,
                },
                0x09 => DecodedMIPS32::ADDIU {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    imm: imm_signed,
                },
                0x0A => DecodedMIPS32::SLTI {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    imm: imm_signed,
                },
                0x0B => DecodedMIPS32::SLTIU {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    imm: imm_signed,
                },
                0x0C => DecodedMIPS32::ANDI {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    imm,
                },
                0x0D => DecodedMIPS32::ORI {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    imm,
                },
                0x0E => DecodedMIPS32::XORI {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    imm,
                },
                0x0F => DecodedMIPS32::LUI {
                    rt: MIPS32Register::from_encoding(rt),
                    imm,
                },
                0x20 => DecodedMIPS32::LB {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                0x21 => DecodedMIPS32::LH {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                0x23 => DecodedMIPS32::LW {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                0x24 => DecodedMIPS32::LBU {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                0x25 => DecodedMIPS32::LHU {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                0x28 => DecodedMIPS32::SB {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                0x29 => DecodedMIPS32::SH {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                0x2B => DecodedMIPS32::SW {
                    rt: MIPS32Register::from_encoding(rt),
                    rs: MIPS32Register::from_encoding(rs),
                    offset: imm_signed,
                },
                _ => DecodedMIPS32::Unknown { opcode: instruction },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_nop() {
        unsafe {
            let decoded = MIPS32Decoder::decode(0x00000000);
            assert_eq!(decoded, DecodedMIPS32::NOP);
        }
    }

    #[test]
    fn test_decode_add() {
        unsafe {
            // ADD $t0, $t1, $t2 (R-type: opcode=0, funct=0x20)
            // rd=8, rs=9, rt=10
            let instruction = 0x012A4020;
            let decoded = MIPS32Decoder::decode(instruction);
            match decoded {
                DecodedMIPS32::ADD { rd, rs, rt } => {
                    assert_eq!(rd.offset(), MIPS32Register::R8.offset());
                    assert_eq!(rs.offset(), MIPS32Register::R9.offset());
                    assert_eq!(rt.offset(), MIPS32Register::R10.offset());
                }
                _ => panic!("Expected ADD instruction"),
            }
        }
    }

    #[test]
    fn test_decode_lw() {
        unsafe {
            // LW $t0, 0($sp) (I-type: opcode=0x23)
            let instruction = 0x8FA80000;
            let decoded = MIPS32Decoder::decode(instruction);
            match decoded {
                DecodedMIPS32::LW { rt, rs, offset } => {
                    assert_eq!(rt.offset(), MIPS32Register::R8.offset());
                    assert_eq!(rs.offset(), MIPS32Register::R29.offset());
                    assert_eq!(offset, 0);
                }
                _ => panic!("Expected LW instruction"),
            }
        }
    }

    #[test]
    fn test_decode_j() {
        unsafe {
            // J 0x100000 (J-type: opcode=0x02)
            let instruction = 0x08100000;
            let decoded = MIPS32Decoder::decode(instruction);
            match decoded {
                DecodedMIPS32::J { target } => {
                    assert_eq!(target, 0x100000);
                }
                _ => panic!("Expected J instruction"),
            }
        }
    }
}
