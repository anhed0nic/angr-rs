//! Use-After-Free Detection
//!
//! Detects temporal memory safety violations including use-after-free and double-free

use super::{
    DetectionContext, Exploitability, Severity, Vulnerability, VulnerabilityDetector,
    VulnerabilityType,
};
use std::collections::{HashMap, HashSet};

/// Allocation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationState {
    /// Allocated and active
    Allocated,
    /// Freed
    Freed,
    /// Double freed
    DoubleFree,
}

/// Heap allocation tracking
#[derive(Debug, Clone)]
pub struct HeapAllocation {
    /// Address of allocation
    pub address: u64,
    /// Size of allocation
    pub size: u64,
    /// Program counter where allocated
    pub alloc_pc: u64,
    /// Program counter where freed (if freed)
    pub free_pc: Option<u64>,
    /// Current state
    pub state: AllocationState,
    /// Function where allocated
    pub alloc_function: Option<String>,
    /// Function where freed
    pub free_function: Option<String>,
}

impl HeapAllocation {
    /// Create new allocation
    ///
    pub unsafe fn new(address: u64, size: u64, pc: u64) -> Self {
        HeapAllocation {
            address,
            size,
            alloc_pc: pc,
            free_pc: None,
            state: AllocationState::Allocated,
            alloc_function: None,
            free_function: None,
        }
    }
    
    /// Mark as freed
    ///
    pub unsafe fn mark_freed(&mut self, pc: u64) {
        if self.state == AllocationState::Freed {
            self.state = AllocationState::DoubleFree;
        } else {
            self.state = AllocationState::Freed;
        }
        self.free_pc = Some(pc);
    }
    
    /// Check if address is within this allocation
    ///
    pub unsafe fn contains(&self, addr: u64) -> bool {
        addr >= self.address && addr < (self.address + self.size)
    }
}

/// Memory access operation
#[derive(Debug, Clone)]
struct MemoryAccess {
    /// Program counter
    pc: u64,
    /// Address accessed
    address: u64,
    /// Size of access
    size: u64,
    /// Is read operation
    is_read: bool,
    /// Is write operation
    is_write: bool,
    /// Function name
    function: Option<String>,
}

/// Use-after-free detector
pub struct UseAfterFreeDetector {
    /// Tracked allocations (address -> allocation)
    allocations: HashMap<u64, HeapAllocation>,
    /// Memory accesses
    accesses: Vec<MemoryAccess>,
    /// Pointers that point to allocations
    pointers: HashMap<u64, u64>, // ptr_addr -> alloc_addr
}

impl UseAfterFreeDetector {
    /// Create new detector
    ///
    pub unsafe fn new() -> Self {
        UseAfterFreeDetector {
            allocations: HashMap::new(),
            accesses: Vec::new(),
            pointers: HashMap::new(),
        }
    }
    
    /// Track allocation
    ///
    pub unsafe fn track_allocation(&mut self, addr: u64, size: u64, pc: u64) {
        let alloc = HeapAllocation::new(addr, size, pc);
        self.allocations.insert(addr, alloc);
    }
    
    /// Track free operation
    ///
    pub unsafe fn track_free(&mut self, addr: u64, pc: u64) {
        if let Some(alloc) = self.allocations.get_mut(&addr) {
            alloc.mark_freed(pc);
        }
    }
    
    /// Track memory access
    ///
    pub unsafe fn track_access(&mut self, pc: u64, addr: u64, size: u64, is_read: bool, is_write: bool) {
        self.accesses.push(MemoryAccess {
            pc,
            address: addr,
            size,
            is_read,
            is_write,
            function: None,
        });
    }
    
    /// Track pointer to allocation
    ///
    pub unsafe fn track_pointer(&mut self, ptr_addr: u64, alloc_addr: u64) {
        self.pointers.insert(ptr_addr, alloc_addr);
    }
    
    /// Check for use-after-free
    ///
    unsafe fn check_use_after_free(&self, access: &MemoryAccess) -> Option<Vulnerability> {
        // Find allocation containing this address
        for alloc in self.allocations.values() {
            if alloc.contains(access.address) {
                if alloc.state == AllocationState::Freed {
                    let mut vuln = Vulnerability::new(
                        VulnerabilityType::UseAfterFree,
                        Severity::Critical,
                        access.pc,
                        format!(
                            "Use-after-free: {} at 0x{:x} (freed at 0x{:x})",
                            if access.is_read { "read" } else { "write" },
                            access.address,
                            alloc.free_pc.unwrap_or(0)
                        ),
                    );
                    
                    // UAF are highly exploitable, especially writes
                    let exploitability = if access.is_write {
                        Exploitability::Exploitable
                    } else {
                        Exploitability::Likely
                    };
                    
                    vuln = vuln.with_exploitability(exploitability);
                    vuln.add_metadata("alloc_pc".to_string(), format!("0x{:x}", alloc.alloc_pc));
                    vuln.add_metadata("free_pc".to_string(), format!("0x{:x}", alloc.free_pc.unwrap_or(0)));
                    vuln.add_metadata("access_type".to_string(), if access.is_read { "read" } else { "write" }.to_string());
                    
                    return Some(vuln);
                }
            }
        }
        
        None
    }
    
    /// Check for double-free
    ///
    unsafe fn check_double_free(&self) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        
        for alloc in self.allocations.values() {
            if alloc.state == AllocationState::DoubleFree {
                let mut vuln = Vulnerability::new(
                    VulnerabilityType::DoubleFree,
                    Severity::High,
                    alloc.free_pc.unwrap_or(0),
                    format!(
                        "Double-free at 0x{:x} (allocated at 0x{:x}, first freed at 0x{:x})",
                        alloc.free_pc.unwrap_or(0),
                        alloc.alloc_pc,
                        alloc.free_pc.unwrap_or(0)
                    ),
                )
                .with_exploitability(Exploitability::Likely);
                
                vuln.add_metadata("alloc_addr".to_string(), format!("0x{:x}", alloc.address));
                vuln.add_metadata("alloc_size".to_string(), alloc.size.to_string());
                
                vulns.push(vuln);
            }
        }
        
        vulns
    }
    
    /// Check for dangling pointers
    ///
    unsafe fn check_dangling_pointers(&self) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        
        for (ptr_addr, alloc_addr) in &self.pointers {
            if let Some(alloc) = self.allocations.get(alloc_addr) {
                if alloc.state == AllocationState::Freed {
                    let vuln = Vulnerability::new(
                        VulnerabilityType::UseAfterFree,
                        Severity::Medium,
                        alloc.free_pc.unwrap_or(0),
                        format!(
                            "Dangling pointer at 0x{:x} points to freed memory at 0x{:x}",
                            ptr_addr, alloc_addr
                        ),
                    )
                    .with_exploitability(Exploitability::Potential);
                    
                    vulns.push(vuln);
                }
            }
        }
        
        vulns
    }
    
    /// Get allocation statistics
    ///
    pub unsafe fn stats(&self) -> AllocationStats {
        let mut stats = AllocationStats::default();
        
        for alloc in self.allocations.values() {
            match alloc.state {
                AllocationState::Allocated => stats.active += 1,
                AllocationState::Freed => stats.freed += 1,
                AllocationState::DoubleFree => {
                    stats.freed += 1;
                    stats.double_freed += 1;
                }
            }
            stats.total_allocated += alloc.size;
        }
        
        stats.total_allocations = self.allocations.len();
        stats
    }
}

/// Allocation statistics
#[derive(Debug, Default)]
pub struct AllocationStats {
    /// Total number of allocations
    pub total_allocations: usize,
    /// Active allocations
    pub active: usize,
    /// Freed allocations
    pub freed: usize,
    /// Double freed
    pub double_freed: usize,
    /// Total bytes allocated
    pub total_allocated: u64,
}

impl VulnerabilityDetector for UseAfterFreeDetector {
    fn name(&self) -> &str {
        "UseAfterFreeDetector"
    }
    
    unsafe fn detect(&self, _context: &DetectionContext) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        
        // Check all memory accesses for UAF
        for access in &self.accesses {
            if let Some(vuln) = self.check_use_after_free(access) {
                vulns.push(vuln);
            }
        }
        
        // Check for double-frees
        vulns.extend(self.check_double_free());
        
        // Check for dangling pointers
        vulns.extend(self.check_dangling_pointers());
        
        vulns
    }
    
    unsafe fn handles(&self, vuln_type: &VulnerabilityType) -> bool {
        matches!(
            vuln_type,
            VulnerabilityType::UseAfterFree | VulnerabilityType::DoubleFree
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heap_allocation() {
        unsafe {
            let mut alloc = HeapAllocation::new(0x10000000, 64, 0x400500);
            
            assert_eq!(alloc.state, AllocationState::Allocated);
            assert!(alloc.contains(0x10000020));
            assert!(!alloc.contains(0x10000100));
            
            alloc.mark_freed(0x400600);
            assert_eq!(alloc.state, AllocationState::Freed);
            
            alloc.mark_freed(0x400700);
            assert_eq!(alloc.state, AllocationState::DoubleFree);
        }
    }

    #[test]
    fn test_use_after_free_detection() {
        unsafe {
            let mut detector = UseAfterFreeDetector::new();
            
            // Track allocation
            detector.track_allocation(0x10000000, 64, 0x400500);
            
            // Free it
            detector.track_free(0x10000000, 0x400600);
            
            // Access after free
            detector.track_access(0x400700, 0x10000020, 4, false, true);
            
            let context = DetectionContext::new(0x400700);
            let vulns = detector.detect(&context);
            
            assert!(!vulns.is_empty());
            assert_eq!(vulns[0].vuln_type, VulnerabilityType::UseAfterFree);
            assert_eq!(vulns[0].severity, Severity::Critical);
        }
    }

    #[test]
    fn test_double_free_detection() {
        unsafe {
            let mut detector = UseAfterFreeDetector::new();
            
            detector.track_allocation(0x10000000, 64, 0x400500);
            detector.track_free(0x10000000, 0x400600);
            detector.track_free(0x10000000, 0x400700);
            
            let context = DetectionContext::new(0x400700);
            let vulns = detector.detect(&context);
            
            let double_free = vulns.iter().find(|v| v.vuln_type == VulnerabilityType::DoubleFree);
            assert!(double_free.is_some());
        }
    }

    #[test]
    fn test_allocation_stats() {
        unsafe {
            let mut detector = UseAfterFreeDetector::new();
            
            detector.track_allocation(0x10000000, 64, 0x400500);
            detector.track_allocation(0x10001000, 128, 0x400550);
            detector.track_free(0x10000000, 0x400600);
            
            let stats = detector.stats();
            assert_eq!(stats.total_allocations, 2);
            assert_eq!(stats.active, 1);
            assert_eq!(stats.freed, 1);
            assert_eq!(stats.total_allocated, 192);
        }
    }

    #[test]
    fn test_dangling_pointer() {
        unsafe {
            let mut detector = UseAfterFreeDetector::new();
            
            detector.track_allocation(0x10000000, 64, 0x400500);
            detector.track_pointer(0x7fff0000, 0x10000000);
            detector.track_free(0x10000000, 0x400600);
            
            let context = DetectionContext::new(0x400600);
            let vulns = detector.detect(&context);
            
            // Should detect dangling pointer
            assert!(!vulns.is_empty());
        }
    }
}
