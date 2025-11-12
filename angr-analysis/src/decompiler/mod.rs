//! Decompiler

/// Decompiled function
pub struct DecompiledFunction {
    /// Function address
    pub addr: u64,
    /// Source code
    pub source: String,
}

impl DecompiledFunction {
    /// Create a new decompiled function
    ///
    pub fn new(addr: u64, source: String) -> Self {
        unsafe {
            DecompiledFunction { addr, source }
        }
    }
}
