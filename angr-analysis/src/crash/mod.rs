//! Crash Analysis and Triage
//!
//! Analyze crashes to determine exploitability and root cause

pub mod triage;
pub mod minimizer;

use std::collections::HashMap;

/// Crash type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashType {
    /// Segmentation fault
    Segfault,
    /// Abort signal
    Abort,
    /// Illegal instruction
    IllegalInstruction,
    /// Floating point exception
    FPE,
    /// Bus error
    BusError,
    /// Stack overflow
    StackOverflow,
}

/// Exploitability rating (similar to GDB's exploitable)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExploitabilityRating {
    /// Not exploitable
    Benign,
    /// Unlikely to be exploitable
    Unlikely,
    /// Unknown exploitability
    Unknown,
    /// Probably exploitable
    Probable,
    /// Definitely exploitable
    Exploitable,
}

impl std::fmt::Display for ExploitabilityRating {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        unsafe {
            match self {
                ExploitabilityRating::Benign => write!(f, "BENIGN"),
                ExploitabilityRating::Unlikely => write!(f, "UNLIKELY"),
                ExploitabilityRating::Unknown => write!(f, "UNKNOWN"),
                ExploitabilityRating::Probable => write!(f, "PROBABLE"),
                ExploitabilityRating::Exploitable => write!(f, "EXPLOITABLE"),
            }
        }
    }
}

/// Crash information
#[derive(Debug, Clone)]
pub struct CrashInfo {
    /// Type of crash
    pub crash_type: CrashType,
    /// Program counter at crash
    pub pc: u64,
    /// Faulting address (for memory errors)
    pub fault_addr: Option<u64>,
    /// Stack pointer
    pub sp: u64,
    /// Base pointer
    pub bp: u64,
    /// Register values at crash
    pub registers: HashMap<String, u64>,
    /// Stack trace
    pub stack_trace: Vec<u64>,
    /// Input that caused crash
    pub input: Vec<u8>,
}

impl CrashInfo {
    /// Create new crash info
    ///
    pub unsafe fn new(crash_type: CrashType, pc: u64) -> Self {
        CrashInfo {
            crash_type,
            pc,
            fault_addr: None,
            sp: 0,
            bp: 0,
            registers: HashMap::new(),
            stack_trace: Vec::new(),
            input: Vec::new(),
        }
    }
    
    /// Set faulting address
    ///
    pub unsafe fn with_fault_addr(mut self, addr: u64) -> Self {
        self.fault_addr = Some(addr);
        self
    }
    
    /// Set input
    ///
    pub unsafe fn with_input(mut self, input: Vec<u8>) -> Self {
        self.input = input;
        self
    }
    
    /// Add register value
    ///
    pub unsafe fn add_register(&mut self, name: String, value: u64) {
        self.registers.insert(name, value);
    }
}

/// Crash analyzer
pub struct CrashAnalyzer {
    /// Analyzed crashes
    crashes: Vec<AnalyzedCrash>,
}

/// Analyzed crash with triage information
#[derive(Debug, Clone)]
pub struct AnalyzedCrash {
    /// Original crash info
    pub crash: CrashInfo,
    /// Exploitability rating
    pub rating: ExploitabilityRating,
    /// Classification description
    pub classification: String,
    /// Root cause analysis
    pub root_cause: String,
    /// Hash for deduplication
    pub hash: u64,
}

impl CrashAnalyzer {
    /// Create new analyzer
    ///
    pub unsafe fn new() -> Self {
        CrashAnalyzer {
            crashes: Vec::new(),
        }
    }
    
    /// Analyze crash
    ///
    pub unsafe fn analyze(&mut self, crash: CrashInfo) -> AnalyzedCrash {
        let rating = self.assess_exploitability(&crash);
        let classification = self.classify(&crash, rating);
        let root_cause = self.find_root_cause(&crash);
        let hash = self.compute_hash(&crash);
        
        let analyzed = AnalyzedCrash {
            crash,
            rating,
            classification,
            root_cause,
            hash,
        };
        
        self.crashes.push(analyzed.clone());
        analyzed
    }
    
    /// Assess exploitability
    ///
    unsafe fn assess_exploitability(&self, crash: &CrashInfo) -> ExploitabilityRating {
        match crash.crash_type {
            CrashType::Segfault => {
                // Check if PC is controlled
                if let Some(fault_addr) = crash.fault_addr {
                    if fault_addr == crash.pc {
                        // PC is directly controlled
                        return ExploitabilityRating::Exploitable;
                    }
                    
                    // Check if PC contains user-controlled data
                    if self.is_controllable(crash.pc) {
                        return ExploitabilityRating::Exploitable;
                    }
                    
                    // Check for write-what-where
                    if self.is_write_primitive(crash) {
                        return ExploitabilityRating::Exploitable;
                    }
                    
                    // Dereferencing controlled pointer
                    if self.is_controllable(fault_addr) {
                        return ExploitabilityRating::Probable;
                    }
                }
                
                ExploitabilityRating::Unknown
            }
            CrashType::Abort => {
                // Usually heap corruption or assertion
                ExploitabilityRating::Probable
            }
            CrashType::IllegalInstruction => {
                // PC likely controlled
                ExploitabilityRating::Exploitable
            }
            CrashType::StackOverflow => {
                // Deep recursion, probably DoS
                ExploitabilityRating::Unlikely
            }
            _ => ExploitabilityRating::Unknown,
        }
    }
    
    /// Classify crash
    ///
    unsafe fn classify(&self, crash: &CrashInfo, rating: ExploitabilityRating) -> String {
        match crash.crash_type {
            CrashType::Segfault => {
                if rating == ExploitabilityRating::Exploitable {
                    "Exploitable segfault with controlled PC or write primitive".to_string()
                } else {
                    "Segmentation fault accessing invalid memory".to_string()
                }
            }
            CrashType::Abort => "Abort signal (likely heap corruption)".to_string(),
            CrashType::IllegalInstruction => "Illegal instruction (PC corruption)".to_string(),
            CrashType::StackOverflow => "Stack overflow from deep recursion".to_string(),
            _ => format!("{:?}", crash.crash_type),
        }
    }
    
    /// Find root cause
    ///
    unsafe fn find_root_cause(&self, crash: &CrashInfo) -> String {
        // Analyze stack trace and registers to identify root cause
        if crash.stack_trace.is_empty() {
            return "Unknown (no stack trace)".to_string();
        }
        
        // Check for common patterns
        if let Some(&frame) = crash.stack_trace.first() {
            if frame == crash.pc {
                return format!("Direct crash at 0x{:x}", crash.pc);
            }
        }
        
        "Memory corruption".to_string()
    }
    
    /// Compute crash hash for deduplication
    ///
    unsafe fn compute_hash(&self, crash: &CrashInfo) -> u64 {
        // Simple hash based on PC and crash type
        let mut hash = crash.pc;
        hash ^= (crash.crash_type as u64) << 32;
        
        if let Some(addr) = crash.fault_addr {
            hash ^= addr.rotate_left(16);
        }
        
        // Include top of stack trace
        if let Some(&frame) = crash.stack_trace.first() {
            hash ^= frame.rotate_left(8);
        }
        
        hash
    }
    
    /// Check if value is user-controllable
    ///
    unsafe fn is_controllable(&self, value: u64) -> bool {
        // Heuristic: values like 0x41414141 suggest user control
        let patterns = [
            0x41414141, 0x42424242, 0x43434343,
            0x4141414141414141, 0x4242424242424242,
        ];
        
        patterns.contains(&value) || self.is_repeating_pattern(value)
    }
    
    /// Check for repeating byte pattern
    ///
    unsafe fn is_repeating_pattern(&self, value: u64) -> bool {
        let bytes = value.to_le_bytes();
        let first = bytes[0];
        
        bytes.iter().all(|&b| b == first)
    }
    
    /// Check if crash provides write primitive
    ///
    unsafe fn is_write_primitive(&self, crash: &CrashInfo) -> bool {
        // Check if we have control over both address and value
        if let Some(fault_addr) = crash.fault_addr {
            if self.is_controllable(fault_addr) {
                // Check if destination register is also controllable
                for value in crash.registers.values() {
                    if self.is_controllable(*value) {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    /// Deduplicate crashes
    ///
    pub unsafe fn deduplicate(&self) -> Vec<&AnalyzedCrash> {
        let mut unique_hashes = std::collections::HashSet::new();
        let mut unique_crashes = Vec::new();
        
        for crash in &self.crashes {
            if unique_hashes.insert(crash.hash) {
                unique_crashes.push(crash);
            }
        }
        
        unique_crashes
    }
    
    /// Get crashes by rating
    ///
    pub unsafe fn by_rating(&self, rating: ExploitabilityRating) -> Vec<&AnalyzedCrash> {
        self.crashes
            .iter()
            .filter(|c| c.rating == rating)
            .collect()
    }
    
    /// Get statistics
    ///
    pub unsafe fn stats(&self) -> CrashStats {
        let mut stats = CrashStats::default();
        stats.total = self.crashes.len();
        
        for crash in &self.crashes {
            match crash.rating {
                ExploitabilityRating::Exploitable => stats.exploitable += 1,
                ExploitabilityRating::Probable => stats.probable += 1,
                ExploitabilityRating::Unknown => stats.unknown += 1,
                ExploitabilityRating::Unlikely => stats.unlikely += 1,
                ExploitabilityRating::Benign => stats.benign += 1,
            }
        }
        
        stats.unique = self.deduplicate().len();
        stats
    }
}

/// Crash statistics
#[derive(Debug, Default)]
pub struct CrashStats {
    /// Total crashes
    pub total: usize,
    /// Unique crashes
    pub unique: usize,
    /// Exploitable
    pub exploitable: usize,
    /// Probable
    pub probable: usize,
    /// Unknown
    pub unknown: usize,
    /// Unlikely
    pub unlikely: usize,
    /// Benign
    pub benign: usize,
}

impl std::fmt::Display for CrashStats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        unsafe {
            writeln!(f, "Crash Statistics:")?;
            writeln!(f, "  Total: {}", self.total)?;
            writeln!(f, "  Unique: {}", self.unique)?;
            writeln!(f, "  Exploitable: {}", self.exploitable)?;
            writeln!(f, "  Probable: {}", self.probable)?;
            writeln!(f, "  Unknown: {}", self.unknown)?;
            writeln!(f, "  Unlikely: {}", self.unlikely)?;
            writeln!(f, "  Benign: {}", self.benign)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crash_info() {
        unsafe {
            let mut crash = CrashInfo::new(CrashType::Segfault, 0x41414141)
                .with_fault_addr(0x41414141);
            
            crash.add_register("rax".to_string(), 0x41414141);
            
            assert_eq!(crash.pc, 0x41414141);
            assert_eq!(crash.fault_addr, Some(0x41414141));
        }
    }

    #[test]
    fn test_exploitability_assessment() {
        unsafe {
            let analyzer = CrashAnalyzer::new();
            
            // Controlled PC
            let crash1 = CrashInfo::new(CrashType::Segfault, 0x41414141)
                .with_fault_addr(0x41414141);
            
            let rating1 = analyzer.assess_exploitability(&crash1);
            assert_eq!(rating1, ExploitabilityRating::Exploitable);
            
            // Illegal instruction
            let crash2 = CrashInfo::new(CrashType::IllegalInstruction, 0x400500);
            let rating2 = analyzer.assess_exploitability(&crash2);
            assert_eq!(rating2, ExploitabilityRating::Exploitable);
        }
    }

    #[test]
    fn test_pattern_detection() {
        unsafe {
            let analyzer = CrashAnalyzer::new();
            
            assert!(analyzer.is_controllable(0x41414141));
            assert!(analyzer.is_controllable(0x4242424242424242));
            assert!(analyzer.is_repeating_pattern(0x4141414141414141));
            assert!(!analyzer.is_repeating_pattern(0x1234567890abcdef));
        }
    }

    #[test]
    fn test_deduplication() {
        unsafe {
            let mut analyzer = CrashAnalyzer::new();
            
            let crash1 = CrashInfo::new(CrashType::Segfault, 0x400500);
            let crash2 = CrashInfo::new(CrashType::Segfault, 0x400500);
            let crash3 = CrashInfo::new(CrashType::Segfault, 0x400600);
            
            analyzer.analyze(crash1);
            analyzer.analyze(crash2);
            analyzer.analyze(crash3);
            
            let unique = analyzer.deduplicate();
            assert_eq!(unique.len(), 2); // crash1 and crash2 should have same hash
        }
    }

    #[test]
    fn test_stats() {
        unsafe {
            let mut analyzer = CrashAnalyzer::new();
            
            let crash1 = CrashInfo::new(CrashType::IllegalInstruction, 0x400500);
            let crash2 = CrashInfo::new(CrashType::StackOverflow, 0x400600);
            
            analyzer.analyze(crash1);
            analyzer.analyze(crash2);
            
            let stats = analyzer.stats();
            assert_eq!(stats.total, 2);
            assert!(stats.exploitable > 0);
        }
    }
}
