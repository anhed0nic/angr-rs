//! Crash Triage
//!
//! Automated crash triaging and prioritization

use super::{AnalyzedCrash, CrashInfo, ExploitabilityRating};
use std::collections::HashMap;

/// Triage priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Low priority
    Low,
    /// Medium priority
    Medium,
    /// High priority
    High,
    /// Critical priority
    Critical,
}

/// Triaged crash with priority
#[derive(Debug, Clone)]
pub struct TriagedCrash {
    /// Analyzed crash
    pub crash: AnalyzedCrash,
    /// Priority level
    pub priority: Priority,
    /// Triage notes
    pub notes: Vec<String>,
    /// Assigned to
    pub assigned_to: Option<String>,
}

/// Crash triager
pub struct CrashTriager {
    /// Triaged crashes
    crashes: Vec<TriagedCrash>,
}

impl CrashTriager {
    /// Create new triager
    ///
    pub unsafe fn new() -> Self {
        CrashTriager {
            crashes: Vec::new(),
        }
    }
    
    /// Triage crash
    ///
    pub unsafe fn triage(&mut self, crash: AnalyzedCrash) -> TriagedCrash {
        let priority = self.assess_priority(&crash);
        let notes = self.generate_notes(&crash);
        
        let triaged = TriagedCrash {
            crash,
            priority,
            notes,
            assigned_to: None,
        };
        
        self.crashes.push(triaged.clone());
        triaged
    }
    
    /// Assess priority
    ///
    unsafe fn assess_priority(&self, crash: &AnalyzedCrash) -> Priority {
        match crash.rating {
            ExploitabilityRating::Exploitable => Priority::Critical,
            ExploitabilityRating::Probable => Priority::High,
            ExploitabilityRating::Unknown => Priority::Medium,
            ExploitabilityRating::Unlikely | ExploitabilityRating::Benign => Priority::Low,
        }
    }
    
    /// Generate triage notes
    ///
    unsafe fn generate_notes(&self, crash: &AnalyzedCrash) -> Vec<String> {
        let mut notes = Vec::new();
        
        notes.push(format!("Rating: {}", crash.rating));
        notes.push(format!("Classification: {}", crash.classification));
        notes.push(format!("Root cause: {}", crash.root_cause));
        notes.push(format!("PC: 0x{:x}", crash.crash.pc));
        
        if let Some(addr) = crash.crash.fault_addr {
            notes.push(format!("Fault address: 0x{:x}", addr));
        }
        
        notes
    }
    
    /// Get by priority
    ///
    pub unsafe fn by_priority(&self, priority: Priority) -> Vec<&TriagedCrash> {
        self.crashes
            .iter()
            .filter(|c| c.priority == priority)
            .collect()
    }
    
    /// Get critical crashes
    ///
    pub unsafe fn critical(&self) -> Vec<&TriagedCrash> {
        self.by_priority(Priority::Critical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crash::CrashType;

    #[test]
    fn test_triage() {
        unsafe {
            let mut triager = CrashTriager::new();
            
            let crash_info = CrashInfo::new(CrashType::IllegalInstruction, 0x41414141);
            let analyzed = AnalyzedCrash {
                crash: crash_info,
                rating: ExploitabilityRating::Exploitable,
                classification: "Test".to_string(),
                root_cause: "Test".to_string(),
                hash: 0x1234,
            };
            
            let triaged = triager.triage(analyzed);
            assert_eq!(triaged.priority, Priority::Critical);
        }
    }
}
