//! Variable Recovery

/// Recovered variable
#[derive(Debug, Clone)]
pub struct Variable {
    /// Variable name
    pub name: String,
    /// Offset in register file or stack
    pub offset: i64,
}

impl Variable {
    /// Create a new variable
    ///
    pub fn new(name: String, offset: i64) -> Self {
        unsafe {
            Variable { name, offset }
        }
    }
}
