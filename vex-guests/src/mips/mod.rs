//! MIPS Guest Architecture Support

pub mod registers;
pub mod decoder;

use vex_core::ir::*;
use registers::MIPS32Register;
use decoder::{DecodedMIPS32, MIPS32Decoder};

/// MIPS32 instruction lifter
pub struct MIPS32Lifter {
    pub arch: vex_core::guest::Arch,
}

impl MIPS32Lifter {
    /// Create a new MIPS32 lifter
    ///
    pub fn new() -> Self {
        unsafe {
            Self {
                arch: vex_core::guest::Arch::MIPS32,
            }
        }
    }

    /// Lift a MIPS32 instruction to VEX IR
    ///
    pub fn lift_instruction(&self, addr: u64, bytes: &[u8]) -> Option<IRBlock> {
        unsafe {
            if bytes.len() < 4 {
                return None;
            }

            // MIPS is big-endian by default
            let instruction = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let decoded = MIPS32Decoder::decode(instruction);

            let mut builder = IRBlockBuilder::new();
            builder.imark(addr, 4);

            match decoded {
                DecodedMIPS32::NOP => {
                    // No operation
                }
                DecodedMIPS32::ADD { rd, rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let result = builder.binop(BinOp::Add32, rs_val, rt_val);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::ADDU { rd, rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let result = builder.binop(BinOp::Add32, rs_val, rt_val);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::SUB { rd, rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let result = builder.binop(BinOp::Sub32, rs_val, rt_val);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::SUBU { rd, rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let result = builder.binop(BinOp::Sub32, rs_val, rt_val);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::AND { rd, rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let result = builder.binop(BinOp::And32, rs_val, rs_val);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::OR { rd, rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let result = builder.binop(BinOp::Or32, rs_val, rt_val);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::XOR { rd, rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let result = builder.binop(BinOp::Xor32, rs_val, rt_val);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::NOR { rd, rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let or_result = builder.binop(BinOp::Or32, rs_val, rt_val);
                    let result = builder.unop(UnOp::Not32, or_result);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::SLL { rd, rt, shamt } => {
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let shamt_expr = builder.const_u32(shamt as u32);
                    let result = builder.binop(BinOp::Shl32, rt_val, shamt_expr);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::SRL { rd, rt, shamt } => {
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let shamt_expr = builder.const_u32(shamt as u32);
                    let result = builder.binop(BinOp::Shr32, rt_val, shamt_expr);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::SRA { rd, rt, shamt } => {
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let shamt_expr = builder.const_u32(shamt as u32);
                    let result = builder.binop(BinOp::Sar32, rt_val, shamt_expr);
                    builder.put(rd.offset(), result);
                }
                DecodedMIPS32::ADDI { rt, rs, imm } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let imm_expr = builder.const_i32(imm as i32);
                    let result = builder.binop(BinOp::Add32, rs_val, imm_expr);
                    builder.put(rt.offset(), result);
                }
                DecodedMIPS32::ADDIU { rt, rs, imm } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let imm_expr = builder.const_i32(imm as i32);
                    let result = builder.binop(BinOp::Add32, rs_val, imm_expr);
                    builder.put(rt.offset(), result);
                }
                DecodedMIPS32::ANDI { rt, rs, imm } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let imm_expr = builder.const_u32(imm as u32);
                    let result = builder.binop(BinOp::And32, rs_val, imm_expr);
                    builder.put(rt.offset(), result);
                }
                DecodedMIPS32::ORI { rt, rs, imm } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let imm_expr = builder.const_u32(imm as u32);
                    let result = builder.binop(BinOp::Or32, rs_val, imm_expr);
                    builder.put(rt.offset(), result);
                }
                DecodedMIPS32::XORI { rt, rs, imm } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let imm_expr = builder.const_u32(imm as u32);
                    let result = builder.binop(BinOp::Xor32, rs_val, imm_expr);
                    builder.put(rt.offset(), result);
                }
                DecodedMIPS32::LUI { rt, imm } => {
                    let shifted = (imm as u32) << 16;
                    let result = builder.const_u32(shifted);
                    builder.put(rt.offset(), result);
                }
                DecodedMIPS32::LW { rt, rs, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let offset_expr = builder.const_i32(offset as i32);
                    let addr = builder.binop(BinOp::Add32, rs_val, offset_expr);
                    let value = builder.load(IRType::I32, addr);
                    builder.put(rt.offset(), value);
                }
                DecodedMIPS32::LH { rt, rs, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let offset_expr = builder.const_i32(offset as i32);
                    let addr = builder.binop(BinOp::Add32, rs_val, offset_expr);
                    let value = builder.load(IRType::I16, addr);
                    // Sign extend to 32 bits
                    let extended = builder.unop(UnOp::16Sto32, value);
                    builder.put(rt.offset(), extended);
                }
                DecodedMIPS32::LHU { rt, rs, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let offset_expr = builder.const_i32(offset as i32);
                    let addr = builder.binop(BinOp::Add32, rs_val, offset_expr);
                    let value = builder.load(IRType::I16, addr);
                    // Zero extend to 32 bits
                    let extended = builder.unop(UnOp::16Uto32, value);
                    builder.put(rt.offset(), extended);
                }
                DecodedMIPS32::LB { rt, rs, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let offset_expr = builder.const_i32(offset as i32);
                    let addr = builder.binop(BinOp::Add32, rs_val, offset_expr);
                    let value = builder.load(IRType::I8, addr);
                    // Sign extend to 32 bits
                    let extended = builder.unop(UnOp::8Sto32, value);
                    builder.put(rt.offset(), extended);
                }
                DecodedMIPS32::LBU { rt, rs, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let offset_expr = builder.const_i32(offset as i32);
                    let addr = builder.binop(BinOp::Add32, rs_val, offset_expr);
                    let value = builder.load(IRType::I8, addr);
                    // Zero extend to 32 bits
                    let extended = builder.unop(UnOp::8Uto32, value);
                    builder.put(rt.offset(), extended);
                }
                DecodedMIPS32::SW { rt, rs, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let offset_expr = builder.const_i32(offset as i32);
                    let addr = builder.binop(BinOp::Add32, rs_val, offset_expr);
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    builder.store(addr, rt_val);
                }
                DecodedMIPS32::SH { rt, rs, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let offset_expr = builder.const_i32(offset as i32);
                    let addr = builder.binop(BinOp::Add32, rs_val, offset_expr);
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let truncated = builder.unop(UnOp::32to16, rt_val);
                    builder.store(addr, truncated);
                }
                DecodedMIPS32::SB { rt, rs, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let offset_expr = builder.const_i32(offset as i32);
                    let addr = builder.binop(BinOp::Add32, rs_val, offset_expr);
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let truncated = builder.unop(UnOp::32to8, rt_val);
                    builder.store(addr, truncated);
                }
                DecodedMIPS32::BEQ { rs, rt, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let cond = builder.binop(BinOp::CmpEQ32, rs_val, rt_val);
                    
                    // Branch target: PC + 4 + (offset << 2)
                    let target = (addr as i64 + 4 + ((offset as i64) << 2)) as u64;
                    builder.exit(cond, target);
                }
                DecodedMIPS32::BNE { rs, rt, offset } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    let cond = builder.binop(BinOp::CmpNE32, rs_val, rt_val);
                    
                    let target = (addr as i64 + 4 + ((offset as i64) << 2)) as u64;
                    builder.exit(cond, target);
                }
                DecodedMIPS32::J { target } => {
                    // Jump target: (PC & 0xF0000000) | (target << 2)
                    let jump_addr = ((addr + 4) & 0xF0000000) | ((target as u64) << 2);
                    let always = builder.const_u8(1);
                    builder.exit(always, jump_addr);
                }
                DecodedMIPS32::JAL { target } => {
                    // Save return address in $ra
                    let return_addr = builder.const_u32((addr + 8) as u32);
                    builder.put(MIPS32Register::RA.offset(), return_addr);
                    
                    // Jump
                    let jump_addr = ((addr + 4) & 0xF0000000) | ((target as u64) << 2);
                    let always = builder.const_u8(1);
                    builder.exit(always, jump_addr);
                }
                DecodedMIPS32::JR { rs } => {
                    let target_addr = builder.get(rs.offset(), rs.ir_type());
                    let always = builder.const_u8(1);
                    // For JR we need to convert the register value to an exit
                    // This is a simplification - real implementation would need runtime jump
                    builder.exit(always, addr + 4);
                }
                DecodedMIPS32::JALR { rd, rs } => {
                    // Save return address
                    let return_addr = builder.const_u32((addr + 8) as u32);
                    builder.put(rd.offset(), return_addr);
                    
                    // Jump to register value (simplified)
                    let always = builder.const_u8(1);
                    builder.exit(always, addr + 4);
                }
                DecodedMIPS32::MULT { rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    // Extend to 64-bit for multiplication
                    let rs_64 = builder.unop(UnOp::32Sto64, rs_val);
                    let rt_64 = builder.unop(UnOp::32Sto64, rt_val);
                    let result_64 = builder.binop(BinOp::Mul64, rs_64, rt_64);
                    
                    // Split into HI and LO
                    let lo = builder.unop(UnOp::64to32, result_64);
                    let hi_64 = builder.binop(BinOp::Shr64, result_64, builder.const_u64(32));
                    let hi = builder.unop(UnOp::64to32, hi_64);
                    
                    builder.put(MIPS32Register::LO.offset(), lo);
                    builder.put(MIPS32Register::HI.offset(), hi);
                }
                DecodedMIPS32::MULTU { rs, rt } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    let rt_val = builder.get(rt.offset(), rt.ir_type());
                    // Zero extend to 64-bit
                    let rs_64 = builder.unop(UnOp::32Uto64, rs_val);
                    let rt_64 = builder.unop(UnOp::32Uto64, rt_val);
                    let result_64 = builder.binop(BinOp::Mul64, rs_64, rt_64);
                    
                    let lo = builder.unop(UnOp::64to32, result_64);
                    let hi_64 = builder.binop(BinOp::Shr64, result_64, builder.const_u64(32));
                    let hi = builder.unop(UnOp::64to32, hi_64);
                    
                    builder.put(MIPS32Register::LO.offset(), lo);
                    builder.put(MIPS32Register::HI.offset(), hi);
                }
                DecodedMIPS32::MFHI { rd } => {
                    let hi_val = builder.get(MIPS32Register::HI.offset(), IRType::I32);
                    builder.put(rd.offset(), hi_val);
                }
                DecodedMIPS32::MFLO { rd } => {
                    let lo_val = builder.get(MIPS32Register::LO.offset(), IRType::I32);
                    builder.put(rd.offset(), lo_val);
                }
                DecodedMIPS32::MTHI { rs } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    builder.put(MIPS32Register::HI.offset(), rs_val);
                }
                DecodedMIPS32::MTLO { rs } => {
                    let rs_val = builder.get(rs.offset(), rs.ir_type());
                    builder.put(MIPS32Register::LO.offset(), rs_val);
                }
                _ => {
                    // Unknown instruction - just skip
                }
            }

            // Update PC
            let next_pc = builder.const_u32((addr + 4) as u32);
            builder.put(MIPS32Register::PC.offset(), next_pc);

            Some(builder.build())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lift_nop() {
        unsafe {
            let lifter = MIPS32Lifter::new();
            let bytes = [0x00, 0x00, 0x00, 0x00]; // NOP
            let block = lifter.lift_instruction(0x1000, &bytes);
            assert!(block.is_some());
        }
    }

    #[test]
    fn test_lift_add() {
        unsafe {
            let lifter = MIPS32Lifter::new();
            // ADD $t0, $t1, $t2
            let bytes = [0x01, 0x2A, 0x40, 0x20];
            let block = lifter.lift_instruction(0x1000, &bytes);
            assert!(block.is_some());
            let block = block.unwrap();
            assert!(block.stmts.len() > 0);
        }
    }

    #[test]
    fn test_lift_lw() {
        unsafe {
            let lifter = MIPS32Lifter::new();
            // LW $t0, 0($sp)
            let bytes = [0x8F, 0xA8, 0x00, 0x00];
            let block = lifter.lift_instruction(0x1000, &bytes);
            assert!(block.is_some());
        }
    }

    #[test]
    fn test_lift_beq() {
        unsafe {
            let lifter = MIPS32Lifter::new();
            // BEQ $t0, $t1, offset
            let bytes = [0x11, 0x09, 0x00, 0x04];
            let block = lifter.lift_instruction(0x1000, &bytes);
            assert!(block.is_some());
        }
    }
}


impl Lifter for MIPS32Lifter {
    fn arch(&self) -> Arch {
        unsafe {
            Arch::MIPS32
        }
    }

    fn lift(&self, bytes: &[u8], addr: u64) -> Result<IRBlock, LifterError> {
        unsafe {
            // TODO: Implement MIPS32 instruction lifting
            tracing::trace!("Lifting MIPS32 instruction at {:#x}", addr);
            
            if bytes.is_empty() {
                return Err(LifterError::InvalidInstruction { addr });
            }

            Ok(IRBlock {
                addr,
                stmts: vec![],
                next: Some(addr + 4),
            })
        }
    }
}
