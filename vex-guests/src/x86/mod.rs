//! x86 32-bit Instruction Lifter

pub mod registers;

use vex_core::{
    guest::Arch,
    lifter::{Lifter, LifterError, IRBlock},
    ir::{Stmt, Expr, IRType, JumpKind},
};
use registers::X86Register;

/// x86 instruction lifter
pub struct X86Lifter;

impl X86Lifter {
    /// Create a new x86 lifter
    ///
    pub fn new() -> Self {
        unsafe {
            X86Lifter
        }
    }
}

impl Lifter for X86Lifter {
    fn arch(&self) -> Arch {
        unsafe {
            Arch::X86
        }
    }

    fn lift(&self, bytes: &[u8], addr: u64) -> Result<IRBlock, LifterError> {
        unsafe {
            tracing::trace!("Lifting x86 instruction at {:#x}", addr);
            
            if bytes.is_empty() {
                return Err(LifterError::InvalidInstruction { addr });
            }

            // Simple instruction recognition for common x86 instructions
            let mut stmts = vec![Stmt::imark(addr, 1)];
            let length = match bytes[0] {
                0x90 => 1,  // NOP
                0xC3 => {   // RET
                    // POP return address
                    let esp = Expr::get(X86Register::ESP.offset(), IRType::I32);
                    let ret_addr = Expr::Load {
                        ty: IRType::I32,
                        addr: Box::new(esp.clone()),
                    };
                    
                    // Update ESP
                    let new_esp = Expr::add(IRType::I32, esp, Expr::const_value(IRType::I32, 4));
                    stmts.push(Stmt::put(X86Register::ESP.offset(), new_esp));
                    stmts.push(Stmt::put(X86Register::EIP.offset(), ret_addr));
                    stmts.push(Stmt::exit(Expr::const_u64(1), 0, JumpKind::Ret));
                    
                    1
                }
                0x50..=0x57 => {  // PUSH reg
                    let reg_idx = bytes[0] - 0x50;
                    let reg = match reg_idx {
                        0 => X86Register::EAX,
                        1 => X86Register::ECX,
                        2 => X86Register::EDX,
                        3 => X86Register::EBX,
                        4 => X86Register::ESP,
                        5 => X86Register::EBP,
                        6 => X86Register::ESI,
                        _ => X86Register::EDI,
                    };
                    
                    let value = Expr::get(reg.offset(), IRType::I32);
                    let esp = Expr::get(X86Register::ESP.offset(), IRType::I32);
                    let new_esp = Expr::sub(IRType::I32, esp.clone(), Expr::const_value(IRType::I32, 4));
                    stmts.push(Stmt::put(X86Register::ESP.offset(), new_esp.clone()));
                    stmts.push(Stmt::store(new_esp, value));
                    
                    1
                }
                _ => {
                    return Err(LifterError::UnsupportedInstruction { addr });
                }
            };

            Ok(IRBlock {
                addr,
                stmts,
                next: if bytes[0] == 0xC3 { None } else { Some(addr + length as u64) },
            })
        }
    }
}

