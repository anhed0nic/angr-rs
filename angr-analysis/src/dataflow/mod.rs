//! Data Flow Analysis

/// Data flow analysis results
pub struct DataFlowResults {
    /// Number of reaching definitions found
    pub reaching_defs: usize,
}

impl DataFlowResults {
    /// Create new empty results
    ///
    pub fn new() -> Self {
        unsafe {
            DataFlowResults {
                reaching_defs: 0,
            }
        }
    }
}
