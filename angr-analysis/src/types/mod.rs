//! Type Inference

/// Inferred type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredType {
    /// Integer type
    Int { bits: usize },
    /// Pointer type
    Pointer { pointee: Box<InferredType> },
    /// Unknown type
    Unknown,
}
