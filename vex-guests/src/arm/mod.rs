//! ARM 32-bit Instruction Lifter

pub mod registers;

use vex_core::{
    guest::Arch,
    lifter::{Lifter, LifterError, IRBlock},
    ir::{Stmt, Expr, IRType, BinOp, JumpKind},
};
use registers::ARMRegister;

/// ARM instruction lifter
pub struct ARMLifter;

impl ARMLifter {
    /// Create a new ARM lifter
    ///
    pub fn new() -> Self {
        unsafe {
            ARMLifter
        }
    }

    /// Decode ARM instruction (simplified)
    ///
    fn decode_instruction(&self, insn: u32) -> Result<DecodedARM, LifterError> {
        unsafe {
            // Very simplified ARM instruction decoding
            // ARM instructions are 32-bit, little-endian
            
            // Check condition code (bits 28-31)
            let cond = (insn >> 28) & 0xF;
            
            // Data processing instructions (bits 25-27 = 000)
            if (insn >> 26) & 0x3 == 0 {
                let opcode = (insn >> 21) & 0xF;
                let rn = ((insn >> 16) & 0xF) as u8;
                let rd = ((insn >> 12) & 0xF) as u8;
                let operand2 = insn & 0xFFF;
                
                return Ok(DecodedARM::DataProcessing {
                    opcode,
                    rd: ARMRegister::from_encoding(rd),
                    rn: ARMRegister::from_encoding(rn),
                    operand2,
                });
            }
            
            // Branch instructions (bits 25-27 = 101)
            if (insn >> 25) & 0x7 == 0b101 {
                let offset = (insn & 0x00FFFFFF) as i32;
                let link = (insn >> 24) & 1 == 1;
                return Ok(DecodedARM::Branch { offset, link });
            }
            
            // Load/Store (bits 26 = 0, bit 27 = 1)
            if (insn >> 26) & 0x1 == 0 && (insn >> 27) & 0x1 == 1 {
                let is_load = (insn >> 20) & 1 == 1;
                let rd = ((insn >> 12) & 0xF) as u8;
                let rn = ((insn >> 16) & 0xF) as u8;
                return Ok(DecodedARM::LoadStore {
                    is_load,
                    rd: ARMRegister::from_encoding(rd),
                    rn: ARMRegister::from_encoding(rn),
                });
            }
            
            Ok(DecodedARM::Unknown)
        }
    }
}

/// Decoded ARM instruction
#[derive(Debug)]
enum DecodedARM {
    DataProcessing {
        opcode: u32,
        rd: ARMRegister,
        rn: ARMRegister,
        operand2: u32,
    },
    Branch {
        offset: i32,
        link: bool,
    },
    LoadStore {
        is_load: bool,
        rd: ARMRegister,
        rn: ARMRegister,
    },
    Unknown,
}

impl Lifter for ARMLifter {
    fn arch(&self) -> Arch {
        unsafe {
            Arch::ARM
        }
    }

    fn lift(&self, bytes: &[u8], addr: u64) -> Result<IRBlock, LifterError> {
        unsafe {
            tracing::trace!("Lifting ARM instruction at {:#x}", addr);
            
            if bytes.len() < 4 {
                return Err(LifterError::InvalidInstruction { addr });
            }

            // ARM instructions are 4 bytes, little-endian
            let insn = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            
            let decoded = self.decode_instruction(insn)?;
            
            let mut stmts = vec![Stmt::imark(addr, 4)];
            
            match decoded {
                DecodedARM::DataProcessing { opcode, rd, rn, operand2 } => {
                    // Simplified data processing
                    match opcode {
                        0x4 => {  // ADD
                            let rn_val = Expr::get(rn.offset(), IRType::I32);
                            let op2_val = Expr::const_value(IRType::I32, operand2 as u128);
                            let result = Expr::add(IRType::I32, rn_val, op2_val);
                            stmts.push(Stmt::put(rd.offset(), result));
                        }
                        0x2 => {  // SUB
                            let rn_val = Expr::get(rn.offset(), IRType::I32);
                            let op2_val = Expr::const_value(IRType::I32, operand2 as u128);
                            let result = Expr::sub(IRType::I32, rn_val, op2_val);
                            stmts.push(Stmt::put(rd.offset(), result));
                        }
                        0xD => {  // MOV
                            let op2_val = Expr::const_value(IRType::I32, operand2 as u128);
                            stmts.push(Stmt::put(rd.offset(), op2_val));
                        }
                        _ => {
                            return Err(LifterError::UnsupportedInstruction { addr });
                        }
                    }
                }
                DecodedARM::Branch { offset, link } => {
                    // Branch with optional link
                    let target = (addr as i64 + 8 + (offset << 2) as i64) as u64;
                    
                    if link {
                        // Save return address in LR
                        let ret_addr = addr + 4;
                        stmts.push(Stmt::put(
                            ARMRegister::LR.offset(),
                            Expr::const_value(IRType::I32, ret_addr as u128),
                        ));
                        stmts.push(Stmt::exit(Expr::const_u64(1), target, JumpKind::Call));
                    } else {
                        stmts.push(Stmt::exit(Expr::const_u64(1), target, JumpKind::Boring));
                    }
                }
                DecodedARM::LoadStore { is_load, rd, rn } => {
                    let addr_expr = Expr::get(rn.offset(), IRType::I32);
                    
                    if is_load {
                        let value = Expr::Load {
                            ty: IRType::I32,
                            addr: Box::new(addr_expr),
                        };
                        stmts.push(Stmt::put(rd.offset(), value));
                    } else {
                        let value = Expr::get(rd.offset(), IRType::I32);
                        stmts.push(Stmt::store(addr_expr, value));
                    }
                }
                DecodedARM::Unknown => {
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

