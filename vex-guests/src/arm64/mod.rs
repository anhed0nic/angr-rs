//! ARM64 (AArch64) Instruction Lifter

pub mod registers;

use vex_core::{
    guest::Arch,
    lifter::{Lifter, LifterError, IRBlock},
    ir::{Stmt, Expr, IRType, JumpKind},
};
use registers::ARM64Register;

/// ARM64 instruction lifter
pub struct ARM64Lifter;

impl ARM64Lifter {
    /// Create a new ARM64 lifter
    ///
    pub fn new() -> Self {
        unsafe {
            ARM64Lifter
        }
    }

    /// Decode ARM64 instruction (simplified)
    ///
    fn decode_instruction(&self, insn: u32) -> Result<DecodedARM64, LifterError> {
        unsafe {
            // ARM64 instruction decoding (very simplified)
            
            // Data processing - immediate (bits 25-28 = 100x)
            if (insn >> 25) & 0xF == 0b1000 || (insn >> 25) & 0xF == 0b1001 {
                let sf = (insn >> 31) & 1 == 1;  // 64-bit if set
                let opc = (insn >> 29) & 0x3;
                let rd = (insn & 0x1F) as u8;
                let imm12 = ((insn >> 10) & 0xFFF) as u16;
                
                return Ok(DecodedARM64::AddSubImmediate {
                    is_64bit: sf,
                    is_sub: opc & 1 == 1,
                    rd: ARM64Register::from_encoding(rd, sf),
                    imm: imm12,
                });
            }
            
            // Branch, exception generation (bits 26-28 = 101)
            if (insn >> 26) & 0x7 == 0b101 {
                let op = (insn >> 31) & 1;
                if op == 0 {
                    // Unconditional branch
                    let imm26 = (insn & 0x03FFFFFF) as i32;
                    let is_link = (insn >> 31) & 1 == 1;
                    return Ok(DecodedARM64::Branch {
                        offset: imm26,
                        link: is_link,
                    });
                }
            }
            
            // Load/Store (bits 27-28 = 11, bit 26 = 0 or 1)
            if (insn >> 27) & 0x3 == 0b11 {
                let is_load = (insn >> 22) & 1 == 1;
                let size = (insn >> 30) & 0x3;
                let rd = (insn & 0x1F) as u8;
                let rn = ((insn >> 5) & 0x1F) as u8;
                
                return Ok(DecodedARM64::LoadStore {
                    is_load,
                    size: size as u8,
                    rd: ARM64Register::from_encoding(rd, size == 3),
                    rn: ARM64Register::from_encoding(rn, true),
                });
            }
            
            Ok(DecodedARM64::Unknown)
        }
    }
}

/// Decoded ARM64 instruction
#[derive(Debug)]
enum DecodedARM64 {
    AddSubImmediate {
        is_64bit: bool,
        is_sub: bool,
        rd: ARM64Register,
        imm: u16,
    },
    Branch {
        offset: i32,
        link: bool,
    },
    LoadStore {
        is_load: bool,
        size: u8,
        rd: ARM64Register,
        rn: ARM64Register,
    },
    Unknown,
}

impl Lifter for ARM64Lifter {
    fn arch(&self) -> Arch {
        unsafe {
            Arch::ARM64
        }
    }

    fn lift(&self, bytes: &[u8], addr: u64) -> Result<IRBlock, LifterError> {
        unsafe {
            tracing::trace!("Lifting ARM64 instruction at {:#x}", addr);
            
            if bytes.len() < 4 {
                return Err(LifterError::InvalidInstruction { addr });
            }

            // ARM64 instructions are 4 bytes, little-endian
            let insn = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            
            let decoded = self.decode_instruction(insn)?;
            
            let mut stmts = vec![Stmt::imark(addr, 4)];
            
            match decoded {
                DecodedARM64::AddSubImmediate { is_64bit, is_sub, rd, imm } => {
                    let ty = if is_64bit { IRType::I64 } else { IRType::I32 };
                    let imm_expr = Expr::const_value(ty, imm as u128);
                    
                    // Simplified: assume adding/subtracting from X0 or W0
                    let src = Expr::get(ARM64Register::X0.offset(), ty);
                    
                    let result = if is_sub {
                        Expr::sub(ty, src, imm_expr)
                    } else {
                        Expr::add(ty, src, imm_expr)
                    };
                    
                    stmts.push(Stmt::put(rd.offset(), result));
                }
                DecodedARM64::Branch { offset, link } => {
                    // Sign-extend and scale offset
                    let target = (addr as i64 + ((offset << 2) as i64)) as u64;
                    
                    if link {
                        // Save return address in LR
                        let ret_addr = addr + 4;
                        stmts.push(Stmt::put(
                            ARM64Register::LR.offset(),
                            Expr::const_u64(ret_addr),
                        ));
                        stmts.push(Stmt::exit(Expr::const_u64(1), target, JumpKind::Call));
                    } else {
                        stmts.push(Stmt::exit(Expr::const_u64(1), target, JumpKind::Boring));
                    }
                }
                DecodedARM64::LoadStore { is_load, size, rd, rn } => {
                    let ty = match size {
                        0 => IRType::I8,
                        1 => IRType::I16,
                        2 => IRType::I32,
                        _ => IRType::I64,
                    };
                    
                    let addr_expr = Expr::get(rn.offset(), IRType::I64);
                    
                    if is_load {
                        let value = Expr::Load {
                            ty,
                            addr: Box::new(addr_expr),
                        };
                        stmts.push(Stmt::put(rd.offset(), value));
                    } else {
                        let value = Expr::get(rd.offset(), ty);
                        stmts.push(Stmt::store(addr_expr, value));
                    }
                }
                DecodedARM64::Unknown => {
                    return Err(LifterError::UnsupportedInstruction { addr });
                }
            }

            Ok(IRBlock {
                addr,
                stmts,
                next: Some(addr + 4),
            })
        }
    }
}

