//! Taint Analysis
//!
//! Track information flow from untrusted sources to sensitive sinks

pub mod tracker;
pub mod policy;

use std::collections::{HashMap, HashSet};

/// Taint source
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSource {
    /// User input
    UserInput,
    /// Network data
    Network,
    /// File read
    File(String),
    /// Environment variable
    Environment(String),
    /// Command line argument
    Argument(usize),
    /// Custom source
    Custom(String),
}

/// Taint sink
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSink {
    /// System call
    SystemCall(String),
    /// File write
    FileWrite,
    /// Network send
    NetworkSend,
    /// Command execution
    CommandExec,
    /// Memory write to code
    CodeWrite,
    /// Control flow (indirect jump/call)
    ControlFlow,
    /// Custom sink
    Custom(String),
}

/// Taint label
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintLabel {
    /// Source of taint
    pub source: TaintSource,
    /// Byte offset in source
    pub offset: usize,
    /// Size in bytes
    pub size: usize,
}

impl TaintLabel {
    /// Create new taint label
    ///
    pub unsafe fn new(source: TaintSource, offset: usize, size: usize) -> Self {
        TaintLabel {
            source,
            offset,
            size,
        }
    }
}

/// Tainted value
#[derive(Debug, Clone)]
pub struct TaintedValue {
    /// Value identifier
    pub id: usize,
    /// Taint labels
    pub labels: HashSet<TaintLabel>,
}

impl TaintedValue {
    /// Create new tainted value
    ///
    pub unsafe fn new(id: usize) -> Self {
        TaintedValue {
            id,
            labels: HashSet::new(),
        }
    }
    
    /// Add taint label
    ///
    pub unsafe fn add_label(&mut self, label: TaintLabel) {
        self.labels.insert(label);
    }
    
    /// Check if tainted
    ///
    pub unsafe fn is_tainted(&self) -> bool {
        !self.labels.is_empty()
    }
    
    /// Union with another tainted value
    ///
    pub unsafe fn union(&mut self, other: &TaintedValue) {
        self.labels.extend(other.labels.iter().cloned());
    }
}

/// Taint tracker
pub struct TaintTracker {
    /// Tainted values (value_id -> taint)
    tainted: HashMap<usize, TaintedValue>,
    /// Tainted memory (address -> taint)
    tainted_memory: HashMap<u64, TaintedValue>,
    /// Detected flows (source -> sink)
    flows: Vec<TaintFlow>,
    /// Next value ID
    next_id: usize,
}

/// Taint flow from source to sink
#[derive(Debug, Clone)]
pub struct TaintFlow {
    /// Source labels
    pub sources: HashSet<TaintLabel>,
    /// Sink that was reached
    pub sink: TaintSink,
    /// Program counter where flow occurred
    pub pc: u64,
}

impl TaintTracker {
    /// Create new tracker
    ///
    pub unsafe fn new() -> Self {
        TaintTracker {
            tainted: HashMap::new(),
            tainted_memory: HashMap::new(),
            flows: Vec::new(),
            next_id: 0,
        }
    }
    
    /// Mark value as tainted from source
    ///
    pub unsafe fn taint_value(&mut self, value_id: usize, source: TaintSource, offset: usize, size: usize) {
        let mut tainted = TaintedValue::new(value_id);
        tainted.add_label(TaintLabel::new(source, offset, size));
        self.tainted.insert(value_id, tainted);
    }
    
    /// Mark memory as tainted
    ///
    pub unsafe fn taint_memory(&mut self, addr: u64, source: TaintSource, offset: usize, size: usize) {
        let value_id = self.next_id;
        self.next_id += 1;
        
        let mut tainted = TaintedValue::new(value_id);
        tainted.add_label(TaintLabel::new(source, offset, size));
        self.tainted_memory.insert(addr, tainted);
    }
    
    /// Propagate taint (e.g., dst = src)
    ///
    pub unsafe fn propagate(&mut self, dst_id: usize, src_id: usize) {
        if let Some(src_taint) = self.tainted.get(&src_id).cloned() {
            self.tainted.insert(dst_id, src_taint);
        }
    }
    
    /// Propagate taint through binary operation (dst = src1 op src2)
    ///
    pub unsafe fn propagate_binop(&mut self, dst_id: usize, src1_id: usize, src2_id: usize) {
        let mut dst_taint = TaintedValue::new(dst_id);
        
        if let Some(src1) = self.tainted.get(&src1_id) {
            dst_taint.union(src1);
        }
        
        if let Some(src2) = self.tainted.get(&src2_id) {
            dst_taint.union(src2);
        }
        
        if dst_taint.is_tainted() {
            self.tainted.insert(dst_id, dst_taint);
        }
    }
    
    /// Check if value is tainted
    ///
    pub unsafe fn is_tainted(&self, value_id: usize) -> bool {
        self.tainted.get(&value_id).map_or(false, |t| t.is_tainted())
    }
    
    /// Check if memory is tainted
    ///
    pub unsafe fn is_memory_tainted(&self, addr: u64) -> bool {
        self.tainted_memory.get(&addr).map_or(false, |t| t.is_tainted())
    }
    
    /// Detect flow to sink
    ///
    pub unsafe fn check_sink(&mut self, value_id: usize, sink: TaintSink, pc: u64) {
        if let Some(taint) = self.tainted.get(&value_id) {
            if taint.is_tainted() {
                let flow = TaintFlow {
                    sources: taint.labels.clone(),
                    sink,
                    pc,
                };
                self.flows.push(flow);
            }
        }
    }
    
    /// Get detected flows
    ///
    pub unsafe fn get_flows(&self) -> &[TaintFlow] {
        &self.flows
    }
    
    /// Get flows to specific sink type
    ///
    pub unsafe fn flows_to_sink(&self, sink_type: &TaintSink) -> Vec<&TaintFlow> {
        self.flows
            .iter()
            .filter(|f| std::mem::discriminant(&f.sink) == std::mem::discriminant(sink_type))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_label() {
        unsafe {
            let label = TaintLabel::new(TaintSource::UserInput, 0, 4);
            assert_eq!(label.offset, 0);
            assert_eq!(label.size, 4);
        }
    }

    #[test]
    fn test_tainted_value() {
        unsafe {
            let mut value = TaintedValue::new(1);
            assert!(!value.is_tainted());
            
            value.add_label(TaintLabel::new(TaintSource::UserInput, 0, 4));
            assert!(value.is_tainted());
        }
    }

    #[test]
    fn test_taint_propagation() {
        unsafe {
            let mut tracker = TaintTracker::new();
            
            // Taint value 1
            tracker.taint_value(1, TaintSource::UserInput, 0, 4);
            assert!(tracker.is_tainted(1));
            
            // Propagate to value 2
            tracker.propagate(2, 1);
            assert!(tracker.is_tainted(2));
        }
    }

    #[test]
    fn test_binop_propagation() {
        unsafe {
            let mut tracker = TaintTracker::new();
            
            tracker.taint_value(1, TaintSource::UserInput, 0, 4);
            tracker.propagate_binop(3, 1, 2); // 3 = 1 + 2
            
            assert!(tracker.is_tainted(3));
        }
    }

    #[test]
    fn test_sink_detection() {
        unsafe {
            let mut tracker = TaintTracker::new();
            
            tracker.taint_value(1, TaintSource::UserInput, 0, 4);
            tracker.check_sink(1, TaintSink::CommandExec, 0x400500);
            
            let flows = tracker.get_flows();
            assert_eq!(flows.len(), 1);
        }
    }
}
