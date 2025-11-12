//! x86-64 (AMD64) Instruction Lifter

pub mod registers;
pub mod decoder;
pub mod modrm;
pub mod eflags;
pub mod conditional;
pub mod arithmetic;

use vex_core::{
    guest::Arch,
    lifter::{Lifter, LifterError, IRBlock},
    ir::{Stmt, Expr, IRType, BinOp, JumpKind},
};
use registers::X64Register;
use decoder::{X64Decoder, Mnemonic, Operand};

/// x86-64 instruction lifter
pub struct X64Lifter {
    decoder: X64Decoder,
}

impl X64Lifter {
    /// Create a new x86-64 lifter
    ///
    pub fn new() -> Self {
        unsafe {
            X64Lifter {
                decoder: X64Decoder::new(),
            }
        }
    }

    /// Lift a decoded instruction to IR
    ///
    fn lift_instruction(
        &self,
        insn: &decoder::DecodedInstruction,
        addr: u64,
    ) -> Result<Vec<Stmt>, LifterError> {
        unsafe {
            let mut stmts = vec![];
            
            // Add instruction marker
            stmts.push(Stmt::imark(addr, insn.length as u32));
            
            match insn.mnemonic {
                Mnemonic::NOP => {
                    // No operation - just the IMark
                }
                
                Mnemonic::MOV => {
                    // MOV dst, src
                    if insn.operands.len() == 2 {
                        let value = self.operand_to_expr(&insn.operands[1])?;
                        match &insn.operands[0] {
                            Operand::Register(reg) => {
                                stmts.push(Stmt::put(reg.offset(), value));
                            }
                            _ => {}
                        }
                    }
                }
                
                Mnemonic::PUSH => {
                    // PUSH src
                    if let Some(operand) = insn.operands.first() {
                        let value = self.operand_to_expr(operand)?;
                        
                        // RSP = RSP - 8
                        let rsp = Expr::get(X64Register::RSP.offset(), IRType::I64);
                        let new_rsp = Expr::sub(IRType::I64, rsp.clone(), Expr::const_u64(8));
                        stmts.push(Stmt::put(X64Register::RSP.offset(), new_rsp.clone()));
                        
                        // Store value at [RSP]
                        stmts.push(Stmt::store(new_rsp, value));
                    }
                }
                
                Mnemonic::POP => {
                    // POP dst
                    if let Some(Operand::Register(reg)) = insn.operands.first() {
                        // Load from [RSP]
                        let rsp = Expr::get(X64Register::RSP.offset(), IRType::I64);
                        let value = Expr::Load {
                            ty: IRType::I64,
                            addr: Box::new(rsp.clone()),
                        };
                        stmts.push(Stmt::put(reg.offset(), value));
                        
                        // RSP = RSP + 8
                        let new_rsp = Expr::add(IRType::I64, rsp, Expr::const_u64(8));
                        stmts.push(Stmt::put(X64Register::RSP.offset(), new_rsp));
                    }
                }
                
                Mnemonic::ADD => {
                    // ADD dst, src (simplified)
                    if insn.operands.len() == 2 {
                        if let Operand::Register(reg) = &insn.operands[0] {
                            let dst = Expr::get(reg.offset(), reg.ir_type());
                            let src = self.operand_to_expr(&insn.operands[1])?;
                            let result = Expr::add(reg.ir_type(), dst, src);
                            stmts.push(Stmt::put(reg.offset(), result));
                        }
                    }
                }
                
                Mnemonic::SUB => {
                    // SUB dst, src (simplified)
                    if insn.operands.len() == 2 {
                        if let Operand::Register(reg) = &insn.operands[0] {
                            let dst = Expr::get(reg.offset(), reg.ir_type());
                            let src = self.operand_to_expr(&insn.operands[1])?;
                            let result = Expr::sub(reg.ir_type(), dst, src);
                            stmts.push(Stmt::put(reg.offset(), result));
                        }
                    }
                }
                
                Mnemonic::RET => {
                    // POP return address and jump
                    let rsp = Expr::get(X64Register::RSP.offset(), IRType::I64);
                    let ret_addr = Expr::Load {
                        ty: IRType::I64,
                        addr: Box::new(rsp.clone()),
                    };
                    
                    // Update RSP
                    let new_rsp = Expr::add(IRType::I64, rsp, Expr::const_u64(8));
                    stmts.push(Stmt::put(X64Register::RSP.offset(), new_rsp));
                    
                    // Update RIP (will be handled by exit)
                    stmts.push(Stmt::put(X64Register::RIP.offset(), ret_addr));
                    
                    // Exit with return jump kind
                    stmts.push(Stmt::exit(
                        Expr::const_u64(1),  // Unconditional
                        0,  // Target determined dynamically
                        JumpKind::Ret,
                    ));
                }
                
                Mnemonic::JMP => {
                    // Unconditional jump
                    if let Some(Operand::Immediate(offset)) = insn.operands.first() {
                        let target = (addr as i64 + insn.length as i64 + *offset as i64) as u64;
                        stmts.push(Stmt::exit(
                            Expr::const_u64(1),
                            target,
                            JumpKind::Boring,
                        ));
                    }
                }
                
                Mnemonic::CALL => {
                    // Function call
                    if let Some(Operand::Immediate(offset)) = insn.operands.first() {
                        let target = (addr as i64 + insn.length as i64 + *offset as i64) as u64;
                        let ret_addr = addr + insn.length as u64;
                        
                        // Push return address
                        let rsp = Expr::get(X64Register::RSP.offset(), IRType::I64);
                        let new_rsp = Expr::sub(IRType::I64, rsp.clone(), Expr::const_u64(8));
                        stmts.push(Stmt::put(X64Register::RSP.offset(), new_rsp.clone()));
                        stmts.push(Stmt::store(new_rsp, Expr::const_u64(ret_addr)));
                        
                        // Jump to target
                        stmts.push(Stmt::exit(
                            Expr::const_u64(1),
                            target,
                            JumpKind::Call,
                        ));
                    }
                }
                
                _ => {
                    // Unsupported instruction
                    return Err(LifterError::UnsupportedInstruction { addr });
                }
            }
            
            Ok(stmts)
        }
    }

    /// Convert an operand to an IR expression
    ///
    fn operand_to_expr(&self, operand: &Operand) -> Result<Expr, LifterError> {
        unsafe {
            match operand {
                Operand::Register(reg) => {
                    Ok(Expr::get(reg.offset(), reg.ir_type()))
                }
                Operand::Immediate(val) => {
                    Ok(Expr::const_u64(*val))
                }
                Operand::Memory { base, index, scale, displacement, size } => {
                    // Build memory address expression
                    let mut addr_expr = Expr::const_u64(*displacement as u64);
                    
                    if let Some(base_reg) = base {
                        let base_val = Expr::get(base_reg.offset(), IRType::I64);
                        addr_expr = Expr::add(IRType::I64, addr_expr, base_val);
                    }
                    
                    if let Some(index_reg) = index {
                        let index_val = Expr::get(index_reg.offset(), IRType::I64);
                        let scaled = if *scale > 1 {
                            Expr::binop(
                                BinOp::Mul,
                                IRType::I64,
                                index_val,
                                Expr::const_u64(*scale as u64),
                            )
                        } else {
                            index_val
                        };
                        addr_expr = Expr::add(IRType::I64, addr_expr, scaled);
                    }
                    
                    // Load from computed address
                    let ty = match size {
                        1 => IRType::I8,
                        2 => IRType::I16,
                        4 => IRType::I32,
                        8 => IRType::I64,
                        _ => IRType::I64,
                    };
                    
                    Ok(Expr::Load {
                        ty,
                        addr: Box::new(addr_expr),
                    })
                }
            }
        }
    }
}

impl Lifter for X64Lifter {
    fn arch(&self) -> Arch {
        unsafe {
            Arch::X64
        }
    }

    fn lift(&self, bytes: &[u8], addr: u64) -> Result<IRBlock, LifterError> {
        unsafe {
            tracing::trace!("Lifting x86-64 instruction at {:#x}", addr);
            
            if bytes.is_empty() {
                return Err(LifterError::InvalidInstruction { addr });
            }

            // Decode the instruction
            let insn = self.decoder.decode(bytes)
                .map_err(|_| LifterError::InvalidInstruction { addr })?;

            // Lift to IR
            let stmts = self.lift_instruction(&insn, addr)?;
            
            // Determine next address
            let next = if matches!(insn.mnemonic, Mnemonic::RET | Mnemonic::JMP) {
                None
            } else {
                Some(addr + insn.length as u64)
            };

            Ok(IRBlock {
                addr,
                stmts,
                next,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x64_lifter_creation() {
        unsafe {
            let lifter = X64Lifter::new();
            assert_eq!(lifter.arch(), Arch::X64);
        }
    }

    #[test]
    fn test_lift_nop() {
        unsafe {
            let lifter = X64Lifter::new();
            let block = lifter.lift(&[0x90], 0x1000).unwrap();
            assert_eq!(block.addr, 0x1000);
            assert_eq!(block.next, Some(0x1001));
            assert!(block.stmts.len() >= 1);
        }
    }

    #[test]
    fn test_lift_ret() {
        unsafe {
            let lifter = X64Lifter::new();
            let block = lifter.lift(&[0xC3], 0x1000).unwrap();
            assert_eq!(block.addr, 0x1000);
            assert_eq!(block.next, None);  // RET has no fallthrough
        }
    }

    #[test]
    fn test_lift_push() {
        unsafe {
            let lifter = X64Lifter::new();
            let block = lifter.lift(&[0x50], 0x1000).unwrap();  // PUSH RAX
            assert_eq!(block.addr, 0x1000);
            assert!(block.stmts.len() > 1);  // Should have IMark + RSP update + Store
        }
    }

    #[test]
    fn test_lift_mov_imm() {
        unsafe {
            let lifter = X64Lifter::new();
            // MOV RAX, 42
            let bytes = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            let block = lifter.lift(&bytes, 0x1000).unwrap();
            assert_eq!(block.addr, 0x1000);
            assert!(block.stmts.len() >= 2);  // IMark + Put
        }
    }
}

