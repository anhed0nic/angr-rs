//! x86-64 EFLAGS Register Support

use vex_core::ir::*;

/// EFLAGS register offsets in guest state
pub mod offsets {
    pub const CF: usize = 0x100;  // Carry flag
    pub const PF: usize = 0x104;  // Parity flag
    pub const AF: usize = 0x108;  // Auxiliary carry flag
    pub const ZF: usize = 0x10C;  // Zero flag
    pub const SF: usize = 0x110;  // Sign flag
    pub const OF: usize = 0x114;  // Overflow flag
    pub const DF: usize = 0x118;  // Direction flag
}

/// EFLAGS helper for generating flag updates
pub struct EFlagsBuilder {
    builder: IRBlockBuilder,
}

impl EFlagsBuilder {
    /// Create a new EFlagsBuilder
    ///
    pub fn new(builder: IRBlockBuilder) -> Self {
        unsafe {
            Self { builder }
        }
    }

    /// Set the zero flag based on a value
    ///
    pub fn set_zf(&mut self, value: TempId, ty: IRType) {
        unsafe {
            let zero = match ty {
                IRType::I8 => self.builder.const_u8(0),
                IRType::I16 => self.builder.const_u16(0),
                IRType::I32 => self.builder.const_u32(0),
                IRType::I64 => self.builder.const_u64(0),
                _ => return,
            };
            let is_zero = self.builder.binop(Self::cmp_eq_for_type(ty), value, zero);
            self.builder.put(offsets::ZF, is_zero);
        }
    }

    /// Set the sign flag based on a value (MSB)
    ///
    pub fn set_sf(&mut self, value: TempId, ty: IRType) {
        unsafe {
            let shift = match ty {
                IRType::I8 => 7,
                IRType::I16 => 15,
                IRType::I32 => 31,
                IRType::I64 => 63,
                _ => return,
            };
            let shift_expr = self.builder.const_u8(shift);
            let shifted = self.builder.binop(Self::shr_for_type(ty), value, shift_expr);
            let mask = self.builder.const_u8(1);
            let sign = self.builder.binop(BinOp::And8, shifted, mask);
            self.builder.put(offsets::SF, sign);
        }
    }

    /// Set carry flag
    ///
    pub fn set_cf(&mut self, value: TempId) {
        unsafe {
            self.builder.put(offsets::CF, value);
        }
    }

    /// Set overflow flag
    ///
    pub fn set_of(&mut self, value: TempId) {
        unsafe {
            self.builder.put(offsets::OF, value);
        }
    }

    /// Update flags for arithmetic operation (add/sub)
    ///
    pub fn update_arith_flags(&mut self, result: TempId, ty: IRType, carry: Option<TempId>, overflow: Option<TempId>) {
        unsafe {
            self.set_zf(result, ty);
            self.set_sf(result, ty);
            if let Some(c) = carry {
                self.set_cf(c);
            }
            if let Some(o) = overflow {
                self.set_of(o);
            }
        }
    }

    /// Update flags for logical operation (and/or/xor)
    ///
    pub fn update_logic_flags(&mut self, result: TempId, ty: IRType) {
        unsafe {
            self.set_zf(result, ty);
            self.set_sf(result, ty);
            // Clear CF and OF
            let zero = self.builder.const_u8(0);
            self.set_cf(zero);
            self.set_of(zero);
        }
    }

    /// Get comparison operation for type
    ///
    fn cmp_eq_for_type(ty: IRType) -> BinOp {
        unsafe {
            match ty {
                IRType::I8 => BinOp::CmpEQ8,
                IRType::I16 => BinOp::CmpEQ16,
                IRType::I32 => BinOp::CmpEQ32,
                IRType::I64 => BinOp::CmpEQ64,
                _ => BinOp::CmpEQ32,
            }
        }
    }

    /// Get shift right operation for type
    ///
    fn shr_for_type(ty: IRType) -> BinOp {
        unsafe {
            match ty {
                IRType::I8 => BinOp::Shr8,
                IRType::I16 => BinOp::Shr16,
                IRType::I32 => BinOp::Shr32,
                IRType::I64 => BinOp::Shr64,
                _ => BinOp::Shr32,
            }
        }
    }

    /// Get the underlying builder
    ///
    pub fn into_builder(self) -> IRBlockBuilder {
        unsafe {
            self.builder
        }
    }
}

/// Condition code for conditional jumps
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionCode {
    O,    // Overflow
    NO,   // Not overflow
    B,    // Below (unsigned <)
    AE,   // Above or equal (unsigned >=)
    E,    // Equal (zero)
    NE,   // Not equal (not zero)
    BE,   // Below or equal (unsigned <=)
    A,    // Above (unsigned >)
    S,    // Sign
    NS,   // Not sign
    P,    // Parity
    NP,   // Not parity
    L,    // Less (signed <)
    GE,   // Greater or equal (signed >=)
    LE,   // Less or equal (signed <=)
    G,    // Greater (signed >)
}

impl ConditionCode {
    /// Build the condition expression from EFLAGS
    ///
    pub fn build_condition(&self, builder: &mut IRBlockBuilder) -> TempId {
        unsafe {
            match self {
                ConditionCode::O => builder.get(offsets::OF, IRType::I8),
                ConditionCode::NO => {
                    let of = builder.get(offsets::OF, IRType::I8);
                    let zero = builder.const_u8(0);
                    builder.binop(BinOp::CmpEQ8, of, zero)
                }
                ConditionCode::B => builder.get(offsets::CF, IRType::I8),
                ConditionCode::AE => {
                    let cf = builder.get(offsets::CF, IRType::I8);
                    let zero = builder.const_u8(0);
                    builder.binop(BinOp::CmpEQ8, cf, zero)
                }
                ConditionCode::E => builder.get(offsets::ZF, IRType::I8),
                ConditionCode::NE => {
                    let zf = builder.get(offsets::ZF, IRType::I8);
                    let zero = builder.const_u8(0);
                    builder.binop(BinOp::CmpEQ8, zf, zero)
                }
                ConditionCode::BE => {
                    // CF || ZF
                    let cf = builder.get(offsets::CF, IRType::I8);
                    let zf = builder.get(offsets::ZF, IRType::I8);
                    builder.binop(BinOp::Or8, cf, zf)
                }
                ConditionCode::A => {
                    // !CF && !ZF
                    let cf = builder.get(offsets::CF, IRType::I8);
                    let zf = builder.get(offsets::ZF, IRType::I8);
                    let or_result = builder.binop(BinOp::Or8, cf, zf);
                    let zero = builder.const_u8(0);
                    builder.binop(BinOp::CmpEQ8, or_result, zero)
                }
                ConditionCode::S => builder.get(offsets::SF, IRType::I8),
                ConditionCode::NS => {
                    let sf = builder.get(offsets::SF, IRType::I8);
                    let zero = builder.const_u8(0);
                    builder.binop(BinOp::CmpEQ8, sf, zero)
                }
                ConditionCode::L => {
                    // SF != OF
                    let sf = builder.get(offsets::SF, IRType::I8);
                    let of = builder.get(offsets::OF, IRType::I8);
                    builder.binop(BinOp::CmpNE8, sf, of)
                }
                ConditionCode::GE => {
                    // SF == OF
                    let sf = builder.get(offsets::SF, IRType::I8);
                    let of = builder.get(offsets::OF, IRType::I8);
                    builder.binop(BinOp::CmpEQ8, sf, of)
                }
                ConditionCode::LE => {
                    // ZF || (SF != OF)
                    let zf = builder.get(offsets::ZF, IRType::I8);
                    let sf = builder.get(offsets::SF, IRType::I8);
                    let of = builder.get(offsets::OF, IRType::I8);
                    let sf_ne_of = builder.binop(BinOp::CmpNE8, sf, of);
                    builder.binop(BinOp::Or8, zf, sf_ne_of)
                }
                ConditionCode::G => {
                    // !ZF && (SF == OF)
                    let zf = builder.get(offsets::ZF, IRType::I8);
                    let sf = builder.get(offsets::SF, IRType::I8);
                    let of = builder.get(offsets::OF, IRType::I8);
                    let sf_eq_of = builder.binop(BinOp::CmpEQ8, sf, of);
                    let zero = builder.const_u8(0);
                    let not_zf = builder.binop(BinOp::CmpEQ8, zf, zero);
                    builder.binop(BinOp::And8, not_zf, sf_eq_of)
                }
                ConditionCode::P | ConditionCode::NP => {
                    // Parity not commonly used, stub
                    builder.const_u8(1)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_code_build() {
        unsafe {
            let mut builder = IRBlockBuilder::new();
            let cond = ConditionCode::E;
            let _result = cond.build_condition(&mut builder);
            // Just ensure it builds without panic
        }
    }

    #[test]
    fn test_eflags_builder() {
        unsafe {
            let builder = IRBlockBuilder::new();
            let mut eflags = EFlagsBuilder::new(builder);
            let value = eflags.builder.const_u32(0);
            eflags.set_zf(value, IRType::I32);
            eflags.set_sf(value, IRType::I32);
        }
    }
}
