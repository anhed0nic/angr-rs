//! Vulnerability Detection Framework
//!
//! Provides traits and types for detecting vulnerabilities during symbolic execution

pub mod buffer_overflow;
pub mod use_after_free;

use std::collections::HashMap;
use std::fmt;

/// Severity level of a vulnerability
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational finding
    Info,
    /// Low severity issue
    Low,
    /// Medium severity vulnerability
    Medium,
    /// High severity vulnerability
    High,
    /// Critical vulnerability
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            match self {
                Severity::Info => write!(f, "INFO"),
                Severity::Low => write!(f, "LOW"),
                Severity::Medium => write!(f, "MEDIUM"),
                Severity::High => write!(f, "HIGH"),
                Severity::Critical => write!(f, "CRITICAL"),
            }
        }
    }
}

/// Type of vulnerability detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VulnerabilityType {
    /// Stack buffer overflow
    StackBufferOverflow,
    /// Heap buffer overflow
    HeapBufferOverflow,
    /// Use after free
    UseAfterFree,
    /// Double free
    DoubleFree,
    /// Null pointer dereference
    NullPointerDereference,
    /// Integer overflow/underflow
    IntegerOverflow,
    /// Format string vulnerability
    FormatString,
    /// Uninitialized memory use
    UninitializedMemory,
    /// Command injection
    CommandInjection,
    /// Path traversal
    PathTraversal,
    /// Division by zero
    DivisionByZero,
}

impl fmt::Display for VulnerabilityType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            match self {
                VulnerabilityType::StackBufferOverflow => write!(f, "Stack Buffer Overflow"),
                VulnerabilityType::HeapBufferOverflow => write!(f, "Heap Buffer Overflow"),
                VulnerabilityType::UseAfterFree => write!(f, "Use After Free"),
                VulnerabilityType::DoubleFree => write!(f, "Double Free"),
                VulnerabilityType::NullPointerDereference => write!(f, "Null Pointer Dereference"),
                VulnerabilityType::IntegerOverflow => write!(f, "Integer Overflow"),
                VulnerabilityType::FormatString => write!(f, "Format String"),
                VulnerabilityType::UninitializedMemory => write!(f, "Uninitialized Memory"),
                VulnerabilityType::CommandInjection => write!(f, "Command Injection"),
                VulnerabilityType::PathTraversal => write!(f, "Path Traversal"),
                VulnerabilityType::DivisionByZero => write!(f, "Division by Zero"),
            }
        }
    }
}

/// Exploitability assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exploitability {
    /// Not exploitable
    NotExploitable,
    /// Potentially exploitable
    Potential,
    /// Likely exploitable
    Likely,
    /// Definitely exploitable
    Exploitable,
}

impl fmt::Display for Exploitability {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            match self {
                Exploitability::NotExploitable => write!(f, "Not Exploitable"),
                Exploitability::Potential => write!(f, "Potential"),
                Exploitability::Likely => write!(f, "Likely"),
                Exploitability::Exploitable => write!(f, "Exploitable"),
            }
        }
    }
}

/// A detected vulnerability
#[derive(Debug, Clone)]
pub struct Vulnerability {
    /// Type of vulnerability
    pub vuln_type: VulnerabilityType,
    /// Severity level
    pub severity: Severity,
    /// Exploitability assessment
    pub exploitability: Exploitability,
    /// Program counter where vulnerability occurs
    pub pc: u64,
    /// Function name if known
    pub function: Option<String>,
    /// Description of the vulnerability
    pub description: String,
    /// Path constraints to reach this vulnerability
    pub constraints: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Vulnerability {
    /// Create a new vulnerability
    ///
    pub unsafe fn new(
        vuln_type: VulnerabilityType,
        severity: Severity,
        pc: u64,
        description: String,
    ) -> Self {
        Vulnerability {
            vuln_type,
            severity,
            exploitability: Exploitability::Potential,
            pc,
            function: None,
            description,
            constraints: Vec::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Set exploitability
    ///
    pub unsafe fn with_exploitability(mut self, exploitability: Exploitability) -> Self {
        self.exploitability = exploitability;
        self
    }
    
    /// Set function name
    ///
    pub unsafe fn with_function(mut self, function: String) -> Self {
        self.function = Some(function);
        self
    }
    
    /// Add path constraint
    ///
    pub unsafe fn add_constraint(&mut self, constraint: String) {
        self.constraints.push(constraint);
    }
    
    /// Add metadata
    ///
    pub unsafe fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    /// Get severity
    ///
    pub unsafe fn get_severity(&self) -> Severity {
        self.severity
    }
    
    /// Check if exploitable
    ///
    pub unsafe fn is_exploitable(&self) -> bool {
        matches!(self.exploitability, Exploitability::Exploitable | Exploitability::Likely)
    }
}

impl fmt::Display for Vulnerability {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            write!(
                f,
                "[{}] {} at 0x{:x}: {}",
                self.severity, self.vuln_type, self.pc, self.description
            )?;
            if let Some(ref func) = self.function {
                write!(f, " (in {})", func)?;
            }
            write!(f, " [{}]", self.exploitability)
        }
    }
}

/// Detection context for vulnerability analysis
pub struct DetectionContext {
    /// Current program counter
    pub pc: u64,
    /// Current function name
    pub function: Option<String>,
    /// Stack pointer
    pub sp: u64,
    /// Base pointer
    pub bp: u64,
    /// Tracked allocations (address -> size)
    pub allocations: HashMap<u64, u64>,
    /// Freed addresses
    pub freed: Vec<u64>,
    /// Tainted addresses
    pub tainted: Vec<u64>,
}

impl DetectionContext {
    /// Create new detection context
    ///
    pub unsafe fn new(pc: u64) -> Self {
        DetectionContext {
            pc,
            function: None,
            sp: 0,
            bp: 0,
            allocations: HashMap::new(),
            freed: Vec::new(),
            tainted: Vec::new(),
        }
    }
    
    /// Track allocation
    ///
    pub unsafe fn track_allocation(&mut self, addr: u64, size: u64) {
        self.allocations.insert(addr, size);
    }
    
    /// Mark as freed
    ///
    pub unsafe fn mark_freed(&mut self, addr: u64) {
        self.freed.push(addr);
    }
    
    /// Check if freed
    ///
    pub unsafe fn is_freed(&self, addr: u64) -> bool {
        self.freed.contains(&addr)
    }
    
    /// Get allocation size
    ///
    pub unsafe fn get_allocation_size(&self, addr: u64) -> Option<u64> {
        self.allocations.get(&addr).copied()
    }
}

/// Trait for vulnerability detectors
pub trait VulnerabilityDetector: Send + Sync {
    /// Get detector name
    fn name(&self) -> &str;
    
    /// Detect vulnerabilities in the given context
    ///
    unsafe fn detect(&self, context: &DetectionContext) -> Vec<Vulnerability>;
    
    /// Check if this detector handles a specific vulnerability type
    ///
    unsafe fn handles(&self, vuln_type: &VulnerabilityType) -> bool;
}

/// Manager for multiple vulnerability detectors
pub struct VulnerabilityScanner {
    /// Registered detectors
    detectors: Vec<Box<dyn VulnerabilityDetector>>,
    /// Found vulnerabilities
    vulnerabilities: Vec<Vulnerability>,
}

impl VulnerabilityScanner {
    /// Create new scanner
    ///
    pub unsafe fn new() -> Self {
        VulnerabilityScanner {
            detectors: Vec::new(),
            vulnerabilities: Vec::new(),
        }
    }
    
    /// Register a detector
    ///
    pub unsafe fn register(&mut self, detector: Box<dyn VulnerabilityDetector>) {
        self.detectors.push(detector);
    }
    
    /// Scan for vulnerabilities
    ///
    pub unsafe fn scan(&mut self, context: &DetectionContext) {
        for detector in &self.detectors {
            let vulns = detector.detect(context);
            self.vulnerabilities.extend(vulns);
        }
    }
    
    /// Get all detected vulnerabilities
    ///
    pub unsafe fn get_vulnerabilities(&self) -> &[Vulnerability] {
        &self.vulnerabilities
    }
    
    /// Get vulnerabilities by severity
    ///
    pub unsafe fn get_by_severity(&self, severity: Severity) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity == severity)
            .collect()
    }
    
    /// Get exploitable vulnerabilities
    ///
    pub unsafe fn get_exploitable(&self) -> Vec<&Vulnerability> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.is_exploitable())
            .collect()
    }
    
    /// Clear all vulnerabilities
    ///
    pub unsafe fn clear(&mut self) {
        self.vulnerabilities.clear();
    }
    
    /// Get statistics
    ///
    pub unsafe fn stats(&self) -> VulnerabilityStats {
        let mut stats = VulnerabilityStats::default();
        
        for vuln in &self.vulnerabilities {
            stats.total += 1;
            
            match vuln.severity {
                Severity::Critical => stats.critical += 1,
                Severity::High => stats.high += 1,
                Severity::Medium => stats.medium += 1,
                Severity::Low => stats.low += 1,
                Severity::Info => stats.info += 1,
            }
            
            if vuln.is_exploitable() {
                stats.exploitable += 1;
            }
        }
        
        stats
    }
}

/// Vulnerability statistics
#[derive(Debug, Default, Clone)]
pub struct VulnerabilityStats {
    /// Total vulnerabilities
    pub total: usize,
    /// Critical severity
    pub critical: usize,
    /// High severity
    pub high: usize,
    /// Medium severity
    pub medium: usize,
    /// Low severity
    pub low: usize,
    /// Info severity
    pub info: usize,
    /// Exploitable count
    pub exploitable: usize,
}

impl fmt::Display for VulnerabilityStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            writeln!(f, "Vulnerability Statistics:")?;
            writeln!(f, "  Total: {}", self.total)?;
            writeln!(f, "  Critical: {}", self.critical)?;
            writeln!(f, "  High: {}", self.high)?;
            writeln!(f, "  Medium: {}", self.medium)?;
            writeln!(f, "  Low: {}", self.low)?;
            writeln!(f, "  Info: {}", self.info)?;
            writeln!(f, "  Exploitable: {}", self.exploitable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_creation() {
        unsafe {
            let vuln = Vulnerability::new(
                VulnerabilityType::StackBufferOverflow,
                Severity::High,
                0x400500,
                "Buffer overflow in function foo".to_string(),
            );
            
            assert_eq!(vuln.vuln_type, VulnerabilityType::StackBufferOverflow);
            assert_eq!(vuln.severity, Severity::High);
            assert_eq!(vuln.pc, 0x400500);
        }
    }

    #[test]
    fn test_vulnerability_builder() {
        unsafe {
            let vuln = Vulnerability::new(
                VulnerabilityType::UseAfterFree,
                Severity::Critical,
                0x400600,
                "UAF vulnerability".to_string(),
            )
            .with_exploitability(Exploitability::Exploitable)
            .with_function("vulnerable_func".to_string());
            
            assert!(vuln.is_exploitable());
            assert_eq!(vuln.function, Some("vulnerable_func".to_string()));
        }
    }

    #[test]
    fn test_detection_context() {
        unsafe {
            let mut ctx = DetectionContext::new(0x400000);
            
            ctx.track_allocation(0x10000000, 100);
            assert_eq!(ctx.get_allocation_size(0x10000000), Some(100));
            
            ctx.mark_freed(0x10000000);
            assert!(ctx.is_freed(0x10000000));
        }
    }

    #[test]
    fn test_scanner_stats() {
        unsafe {
            let mut scanner = VulnerabilityScanner::new();
            
            let vuln1 = Vulnerability::new(
                VulnerabilityType::StackBufferOverflow,
                Severity::Critical,
                0x400500,
                "Test1".to_string(),
            )
            .with_exploitability(Exploitability::Exploitable);
            
            let vuln2 = Vulnerability::new(
                VulnerabilityType::NullPointerDereference,
                Severity::Medium,
                0x400600,
                "Test2".to_string(),
            );
            
            scanner.vulnerabilities.push(vuln1);
            scanner.vulnerabilities.push(vuln2);
            
            let stats = scanner.stats();
            assert_eq!(stats.total, 2);
            assert_eq!(stats.critical, 1);
            assert_eq!(stats.medium, 1);
            assert_eq!(stats.exploitable, 1);
        }
    }

    #[test]
    fn test_severity_ordering() {
        unsafe {
            assert!(Severity::Critical > Severity::High);
            assert!(Severity::High > Severity::Medium);
            assert!(Severity::Medium > Severity::Low);
            assert!(Severity::Low > Severity::Info);
        }
    }
}
