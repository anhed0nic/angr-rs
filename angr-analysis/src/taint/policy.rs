//! Taint Policies
//!
//! Define taint sources and sinks for specific analysis scenarios

use super::{TaintSink, TaintSource};
use std::collections::HashSet;

/// Taint policy
pub struct TaintPolicy {
    /// Configured sources
    pub sources: HashSet<TaintSource>,
    /// Configured sinks
    pub sinks: HashSet<TaintSink>,
    /// Name of policy
    pub name: String,
}

impl TaintPolicy {
    /// Create new policy
    ///
    pub unsafe fn new(name: String) -> Self {
        TaintPolicy {
            sources: HashSet::new(),
            sinks: HashSet::new(),
            name,
        }
    }
    
    /// Add source
    ///
    pub unsafe fn add_source(&mut self, source: TaintSource) {
        self.sources.insert(source);
    }
    
    /// Add sink
    ///
    pub unsafe fn add_sink(&mut self, sink: TaintSink) {
        self.sinks.insert(sink);
    }
    
    /// Create command injection policy
    ///
    pub unsafe fn command_injection() -> Self {
        let mut policy = TaintPolicy::new("Command Injection".to_string());
        policy.add_source(TaintSource::UserInput);
        policy.add_source(TaintSource::Network);
        policy.add_sink(TaintSink::CommandExec);
        policy
    }
    
    /// Create file traversal policy
    ///
    pub unsafe fn path_traversal() -> Self {
        let mut policy = TaintPolicy::new("Path Traversal".to_string());
        policy.add_source(TaintSource::UserInput);
        policy.add_source(TaintSource::Network);
        policy.add_sink(TaintSink::FileWrite);
        policy
    }
    
    /// Create code injection policy
    ///
    pub unsafe fn code_injection() -> Self {
        let mut policy = TaintPolicy::new("Code Injection".to_string());
        policy.add_source(TaintSource::UserInput);
        policy.add_source(TaintSource::Network);
        policy.add_sink(TaintSink::CodeWrite);
        policy.add_sink(TaintSink::ControlFlow);
        policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_injection_policy() {
        unsafe {
            let policy = TaintPolicy::command_injection();
            assert_eq!(policy.name, "Command Injection");
            assert!(!policy.sources.is_empty());
            assert!(!policy.sinks.is_empty());
        }
    }
}
