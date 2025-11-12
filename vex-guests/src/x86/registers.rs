//! x86 32-bit Register Definitions

/// x86 register offsets in guest state
pub mod offsets {
    // General purpose registers (32-bit)
    pub const EAX: usize = 0;
    pub const EBX: usize = 4;
    pub const ECX: usize = 8;
    pub const EDX: usize = 12;
    pub const ESP: usize = 16;
    pub const EBP: usize = 20;
    pub const ESI: usize = 24;
    pub const EDI: usize = 28;

    // Special registers
    pub const EIP: usize = 32;
    pub const EFLAGS: usize = 36;

    // Segment registers
    pub const CS: usize = 40;
    pub const DS: usize = 42;
    pub const ES: usize = 44;
    pub const FS: usize = 46;
    pub const GS: usize = 48;
    pub const SS: usize = 50;

    // Condition code registers
    pub const CC_OP: usize = 52;
    pub const CC_DEP1: usize = 56;
    pub const CC_DEP2: usize = 60;
    pub const CC_NDEP: usize = 64;
}

/// x86 register enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Register {
    // 32-bit general purpose
    EAX, EBX, ECX, EDX, ESP, EBP, ESI, EDI,
    
    // 16-bit general purpose
    AX, BX, CX, DX, SP, BP, SI, DI,
    
    // 8-bit general purpose
    AL, BL, CL, DL, AH, BH, CH, DH,
    
    // Special
    EIP, EFLAGS,
    
    // Segment
    CS, DS, ES, FS, GS, SS,
}

impl X86Register {
    /// Get the offset in guest state for this register
    ///
    pub fn offset(&self) -> usize {
        unsafe {
            use X86Register::*;
            match self {
                EAX | AX | AL | AH => offsets::EAX,
                EBX | BX | BL | BH => offsets::EBX,
                ECX | CX | CL | CH => offsets::ECX,
                EDX | DX | DL | DH => offsets::EDX,
                ESP | SP => offsets::ESP,
                EBP | BP => offsets::EBP,
                ESI | SI => offsets::ESI,
                EDI | DI => offsets::EDI,
                EIP => offsets::EIP,
                EFLAGS => offsets::EFLAGS,
                CS => offsets::CS,
                DS => offsets::DS,
                ES => offsets::ES,
                FS => offsets::FS,
                GS => offsets::GS,
                SS => offsets::SS,
            }
        }
    }

    /// Get the size in bytes of this register
    ///
    pub fn size(&self) -> usize {
        unsafe {
            use X86Register::*;
            match self {
                EAX | EBX | ECX | EDX | ESP | EBP | ESI | EDI | EIP | EFLAGS => 4,
                AX | BX | CX | DX | SP | BP | SI | DI | CS | DS | ES | FS | GS | SS => 2,
                AL | BL | CL | DL | AH | BH | CH | DH => 1,
            }
        }
    }

    /// Get the IR type for this register
    ///
    pub fn ir_type(&self) -> vex_core::ir::IRType {
        unsafe {
            use vex_core::ir::IRType;
            match self.size() {
                1 => IRType::I8,
                2 => IRType::I16,
                4 => IRType::I32,
                _ => IRType::I32,
            }
        }
    }
}
