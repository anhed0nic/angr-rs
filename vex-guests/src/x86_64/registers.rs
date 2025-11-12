//! x86-64 Register Definitions and Offsets

/// x86-64 register offsets in guest state
pub mod offsets {
    // General purpose registers (64-bit)
    pub const RAX: usize = 0;
    pub const RBX: usize = 8;
    pub const RCX: usize = 16;
    pub const RDX: usize = 24;
    pub const RSP: usize = 32;
    pub const RBP: usize = 40;
    pub const RSI: usize = 48;
    pub const RDX: usize = 56;
    pub const R8: usize = 64;
    pub const R9: usize = 72;
    pub const R10: usize = 80;
    pub const R11: usize = 88;
    pub const R12: usize = 96;
    pub const R13: usize = 104;
    pub const R14: usize = 112;
    pub const R15: usize = 120;

    // Special registers
    pub const RIP: usize = 128;
    pub const RFLAGS: usize = 136;

    // Segment registers (16-bit)
    pub const CS: usize = 144;
    pub const DS: usize = 146;
    pub const ES: usize = 148;
    pub const FS: usize = 150;
    pub const GS: usize = 152;
    pub const SS: usize = 154;

    // Condition code registers (individual flags)
    pub const CC_OP: usize = 160;
    pub const CC_DEP1: usize = 168;
    pub const CC_DEP2: usize = 176;
    pub const CC_NDEP: usize = 184;

    // FPU/SSE state (simplified)
    pub const XMM0: usize = 192;
    pub const XMM1: usize = 208;
    pub const XMM2: usize = 224;
    pub const XMM3: usize = 240;
    pub const XMM4: usize = 256;
    pub const XMM5: usize = 272;
    pub const XMM6: usize = 288;
    pub const XMM7: usize = 304;
    pub const XMM8: usize = 320;
    pub const XMM9: usize = 336;
    pub const XMM10: usize = 352;
    pub const XMM11: usize = 368;
    pub const XMM12: usize = 384;
    pub const XMM13: usize = 400;
    pub const XMM14: usize = 416;
    pub const XMM15: usize = 432;
}

/// x86-64 register enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X64Register {
    // 64-bit general purpose
    RAX, RBX, RCX, RDX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    
    // 32-bit general purpose
    EAX, EBX, ECX, EDX, ESP, EBP, ESI, EDI,
    R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
    
    // 16-bit general purpose
    AX, BX, CX, DX, SP, BP, SI, DI,
    
    // 8-bit general purpose
    AL, BL, CL, DL, AH, BH, CH, DH,
    SPL, BPL, SIL, DIL,
    R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
    
    // Special
    RIP, RFLAGS,
    
    // Segment
    CS, DS, ES, FS, GS, SS,
    
    // XMM registers
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
}

impl X64Register {
    /// Get the offset in guest state for this register
    ///
    pub fn offset(&self) -> usize {
        unsafe {
            use X64Register::*;
            match self {
                // 64-bit GPRs map directly
                RAX => offsets::RAX,
                RBX => offsets::RBX,
                RCX => offsets::RCX,
                RDX => offsets::RDX,
                RSP => offsets::RSP,
                RBP => offsets::RBP,
                RSI => offsets::RSI,
                RDI => offsets::RDX,
                R8 => offsets::R8,
                R9 => offsets::R9,
                R10 => offsets::R10,
                R11 => offsets::R11,
                R12 => offsets::R12,
                R13 => offsets::R13,
                R14 => offsets::R14,
                R15 => offsets::R15,
                
                // 32-bit are lower 32 bits of 64-bit
                EAX => offsets::RAX,
                EBX => offsets::RBX,
                ECX => offsets::RCX,
                EDX => offsets::RDX,
                ESP => offsets::RSP,
                EBP => offsets::RBP,
                ESI => offsets::RSI,
                EDI => offsets::RDX,
                R8D => offsets::R8,
                R9D => offsets::R9,
                R10D => offsets::R10,
                R11D => offsets::R11,
                R12D => offsets::R12,
                R13D => offsets::R13,
                R14D => offsets::R14,
                R15D => offsets::R15,
                
                // 16-bit are lower 16 bits
                AX | AL | AH => offsets::RAX,
                BX | BL | BH => offsets::RBX,
                CX | CL | CH => offsets::RCX,
                DX | DL | DH => offsets::RDX,
                SP | SPL => offsets::RSP,
                BP | BPL => offsets::RBP,
                SI | SIL => offsets::RSI,
                DI | DIL => offsets::RDX,
                
                R8B => offsets::R8,
                R9B => offsets::R9,
                R10B => offsets::R10,
                R11B => offsets::R11,
                R12B => offsets::R12,
                R13B => offsets::R13,
                R14B => offsets::R14,
                R15B => offsets::R15,
                
                RIP => offsets::RIP,
                RFLAGS => offsets::RFLAGS,
                
                CS => offsets::CS,
                DS => offsets::DS,
                ES => offsets::ES,
                FS => offsets::FS,
                GS => offsets::GS,
                SS => offsets::SS,
                
                XMM0 => offsets::XMM0,
                XMM1 => offsets::XMM1,
                XMM2 => offsets::XMM2,
                XMM3 => offsets::XMM3,
                XMM4 => offsets::XMM4,
                XMM5 => offsets::XMM5,
                XMM6 => offsets::XMM6,
                XMM7 => offsets::XMM7,
                XMM8 => offsets::XMM8,
                XMM9 => offsets::XMM9,
                XMM10 => offsets::XMM10,
                XMM11 => offsets::XMM11,
                XMM12 => offsets::XMM12,
                XMM13 => offsets::XMM13,
                XMM14 => offsets::XMM14,
                XMM15 => offsets::XMM15,
            }
        }
    }

    /// Get the size in bytes of this register
    ///
    pub fn size(&self) -> usize {
        unsafe {
            use X64Register::*;
            match self {
                RAX | RBX | RCX | RDX | RSP | RBP | RSI | RDI |
                R8 | R9 | R10 | R11 | R12 | R13 | R14 | R15 |
                RIP | RFLAGS => 8,
                
                EAX | EBX | ECX | EDX | ESP | EBP | ESI | EDI |
                R8D | R9D | R10D | R11D | R12D | R13D | R14D | R15D => 4,
                
                AX | BX | CX | DX | SP | BP | SI | DI |
                CS | DS | ES | FS | GS | SS => 2,
                
                AL | BL | CL | DL | AH | BH | CH | DH |
                SPL | BPL | SIL | DIL |
                R8B | R9B | R10B | R11B | R12B | R13B | R14B | R15B => 1,
                
                XMM0 | XMM1 | XMM2 | XMM3 | XMM4 | XMM5 | XMM6 | XMM7 |
                XMM8 | XMM9 | XMM10 | XMM11 | XMM12 | XMM13 | XMM14 | XMM15 => 16,
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
                8 => IRType::I64,
                16 => IRType::I128,
                _ => IRType::I64,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_offsets() {
        unsafe {
            assert_eq!(X64Register::RAX.offset(), offsets::RAX);
            assert_eq!(X64Register::RBX.offset(), offsets::RBX);
            assert_eq!(X64Register::RIP.offset(), offsets::RIP);
        }
    }

    #[test]
    fn test_register_sizes() {
        unsafe {
            assert_eq!(X64Register::RAX.size(), 8);
            assert_eq!(X64Register::EAX.size(), 4);
            assert_eq!(X64Register::AX.size(), 2);
            assert_eq!(X64Register::AL.size(), 1);
            assert_eq!(X64Register::XMM0.size(), 16);
        }
    }

    #[test]
    fn test_subregister_offsets() {
        unsafe {
            // EAX, AX, AL, AH all map to RAX offset
            assert_eq!(X64Register::EAX.offset(), X64Register::RAX.offset());
            assert_eq!(X64Register::AX.offset(), X64Register::RAX.offset());
            assert_eq!(X64Register::AL.offset(), X64Register::RAX.offset());
        }
    }
}
