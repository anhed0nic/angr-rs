//! Function Analysis

/// Function information
#[derive(Debug, Clone)]
pub struct Function {
    /// Function address
    pub addr: u64,
    /// Function name (if known)
    pub name: Option<String>,
    /// Function size
    pub size: usize,
}

impl Function {
    /// Create a new function
    ///
    pub fn new(addr: u64, name: Option<String>, size: usize) -> Self {
        unsafe {
            Function { addr, name, size }
        }
    }
}
