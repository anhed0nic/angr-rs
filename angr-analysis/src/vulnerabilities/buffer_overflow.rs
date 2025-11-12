//! Buffer Overflow Detection
//!
//! Detects stack and heap buffer overflows during symbolic execution

use super::{
    DetectionContext, Exploitability, Severity, Vulnerability, VulnerabilityDetector,
    VulnerabilityType,
};
use std::collections::HashMap;

/// Dangerous functions that often lead to buffer overflows
const DANGEROUS_FUNCTIONS: &[&str] = &[
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "gets",
    "scanf",
    "fscanf",
    "sscanf",
];

/// Stack frame information
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Base pointer
    pub bp: u64,
    /// Stack pointer
    pub sp: u64,
    /// Return address
    pub return_addr: Option<u64>,
    /// Local buffer allocations (offset -> size)
    pub buffers: HashMap<i64, u64>,
}

impl StackFrame {
    /// Create new stack frame
    ///
    pub unsafe fn new(bp: u64, sp: u64) -> Self {
        StackFrame {
            bp,
            sp,
            return_addr: None,
            buffers: HashMap::new(),
        }
    }
    
    /// Add buffer allocation
    ///
    pub unsafe fn add_buffer(&mut self, offset: i64, size: u64) {
        self.buffers.insert(offset, size);
    }
    
    /// Check if address is within stack frame
    ///
    pub unsafe fn contains(&self, addr: u64) -> bool {
        addr >= self.sp && addr < self.bp
    }
    
    /// Get buffer at offset
    ///
    pub unsafe fn get_buffer(&self, offset: i64) -> Option<u64> {
        self.buffers.get(&offset).copied()
    }
}

/// Buffer overflow detector
pub struct BufferOverflowDetector {
    /// Stack frames being tracked
    stack_frames: Vec<StackFrame>,
    /// Heap allocations (address -> size)
    heap_allocations: HashMap<u64, u64>,
    /// Detected write operations
    writes: Vec<WriteOperation>,
}

/// Write operation tracking
#[derive(Debug, Clone)]
struct WriteOperation {
    /// Program counter of write
    pc: u64,
    /// Destination address
    dest: u64,
    /// Size of write
    size: u64,
    /// Is destination symbolic
    dest_symbolic: bool,
    /// Is size symbolic
    size_symbolic: bool,
}

impl BufferOverflowDetector {
    /// Create new detector
    ///
    pub unsafe fn new() -> Self {
        BufferOverflowDetector {
            stack_frames: Vec::new(),
            heap_allocations: HashMap::new(),
            writes: Vec::new(),
        }
    }
    
    /// Track stack frame
    ///
    pub unsafe fn track_frame(&mut self, frame: StackFrame) {
        self.stack_frames.push(frame);
    }
    
    /// Track heap allocation
    ///
    pub unsafe fn track_heap(&mut self, addr: u64, size: u64) {
        self.heap_allocations.insert(addr, size);
    }
    
    /// Track write operation
    ///
    pub unsafe fn track_write(&mut self, pc: u64, dest: u64, size: u64, dest_symbolic: bool, size_symbolic: bool) {
        self.writes.push(WriteOperation {
            pc,
            dest,
            size,
            dest_symbolic,
            size_symbolic,
        });
    }
    
    /// Check for stack overflow
    ///
    unsafe fn check_stack_overflow(&self, write: &WriteOperation) -> Option<Vulnerability> {
        for frame in &self.stack_frames {
            // Check if write destination is in this frame
            if !frame.contains(write.dest) {
                continue;
            }
            
            // Find matching buffer
            let frame_offset = (write.dest as i64) - (frame.bp as i64);
            
            for (buf_offset, buf_size) in &frame.buffers {
                // Check if write is to this buffer
                if frame_offset >= *buf_offset && frame_offset < (*buf_offset + *buf_size as i64) {
                    let available = (*buf_offset + *buf_size as i64) - frame_offset;
                    
                    // Check if write exceeds buffer
                    if write.size as i64 > available {
                        let overflow = write.size as i64 - available;
                        
                        let mut vuln = Vulnerability::new(
                            VulnerabilityType::StackBufferOverflow,
                            Severity::High,
                            write.pc,
                            format!(
                                "Stack buffer overflow: write of {} bytes to buffer of {} bytes (overflow: {} bytes)",
                                write.size, available, overflow
                            ),
                        );
                        
                        // Assess exploitability
                        let exploitability = if write.dest_symbolic || write.size_symbolic {
                            Exploitability::Exploitable
                        } else if overflow >= 8 {
                            // Enough to overwrite return address
                            Exploitability::Likely
                        } else {
                            Exploitability::Potential
                        };
                        
                        vuln = vuln.with_exploitability(exploitability);
                        vuln.add_metadata("overflow_size".to_string(), overflow.to_string());
                        vuln.add_metadata("buffer_size".to_string(), available.to_string());
                        
                        return Some(vuln);
                    }
                }
            }
            
            // Check if write overwrites return address
            if let Some(ret_addr) = frame.return_addr {
                let ret_offset = (ret_addr as i64) - (frame.bp as i64);
                let write_end = (write.dest as i64) - (frame.bp as i64) + write.size as i64;
                
                if write_end >= ret_offset {
                    let mut vuln = Vulnerability::new(
                        VulnerabilityType::StackBufferOverflow,
                        Severity::Critical,
                        write.pc,
                        format!(
                            "Stack buffer overflow overwrites return address at offset {}",
                            ret_offset
                        ),
                    )
                    .with_exploitability(Exploitability::Exploitable);
                    
                    vuln.add_metadata("overwrites".to_string(), "return_address".to_string());
                    
                    return Some(vuln);
                }
            }
        }
        
        None
    }
    
    /// Check for heap overflow
    ///
    unsafe fn check_heap_overflow(&self, write: &WriteOperation) -> Option<Vulnerability> {
        for (alloc_addr, alloc_size) in &self.heap_allocations {
            // Check if write is within this allocation
            if write.dest >= *alloc_addr && write.dest < (*alloc_addr + *alloc_size) {
                let offset = write.dest - *alloc_addr;
                let available = *alloc_size - offset;
                
                // Check if write exceeds allocation
                if write.size > available {
                    let overflow = write.size - available;
                    
                    let mut vuln = Vulnerability::new(
                        VulnerabilityType::HeapBufferOverflow,
                        Severity::High,
                        write.pc,
                        format!(
                            "Heap buffer overflow: write of {} bytes to buffer with {} bytes available (overflow: {} bytes)",
                            write.size, available, overflow
                        ),
                    );
                    
                    // Heap overflows are often exploitable via metadata corruption
                    let exploitability = if write.dest_symbolic || write.size_symbolic {
                        Exploitability::Exploitable
                    } else if overflow >= 16 {
                        // Enough to overwrite heap metadata
                        Exploitability::Likely
                    } else {
                        Exploitability::Potential
                    };
                    
                    vuln = vuln.with_exploitability(exploitability);
                    vuln.add_metadata("overflow_size".to_string(), overflow.to_string());
                    vuln.add_metadata("heap_addr".to_string(), format!("0x{:x}", alloc_addr));
                    
                    return Some(vuln);
                }
            }
        }
        
        None
    }
    
    /// Check for off-by-one errors
    ///
    unsafe fn check_off_by_one(&self, write: &WriteOperation) -> Option<Vulnerability> {
        // Stack check
        for frame in &self.stack_frames {
            if frame.contains(write.dest) {
                let frame_offset = (write.dest as i64) - (frame.bp as i64);
                
                for (buf_offset, buf_size) in &frame.buffers {
                    if frame_offset >= *buf_offset && frame_offset < (*buf_offset + *buf_size as i64) {
                        let available = (*buf_offset + *buf_size as i64) - frame_offset;
                        
                        // Off-by-one: exactly 1 byte over
                        if write.size as i64 == available + 1 {
                            return Some(
                                Vulnerability::new(
                                    VulnerabilityType::StackBufferOverflow,
                                    Severity::Medium,
                                    write.pc,
                                    "Off-by-one stack buffer overflow".to_string(),
                                )
                                .with_exploitability(Exploitability::Potential),
                            );
                        }
                    }
                }
            }
        }
        
        // Heap check
        for (alloc_addr, alloc_size) in &self.heap_allocations {
            if write.dest >= *alloc_addr && write.dest < (*alloc_addr + *alloc_size) {
                let offset = write.dest - *alloc_addr;
                let available = *alloc_size - offset;
                
                if write.size == available + 1 {
                    return Some(
                        Vulnerability::new(
                            VulnerabilityType::HeapBufferOverflow,
                            Severity::Medium,
                            write.pc,
                            "Off-by-one heap buffer overflow".to_string(),
                        )
                        .with_exploitability(Exploitability::Potential),
                    );
                }
            }
        }
        
        None
    }
}

impl VulnerabilityDetector for BufferOverflowDetector {
    fn name(&self) -> &str {
        "BufferOverflowDetector"
    }
    
    unsafe fn detect(&self, context: &DetectionContext) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        
        // Synchronize state from context
        // In real implementation, would track writes during execution
        
        // Check all tracked writes
        for write in &self.writes {
            // Check stack overflow
            if let Some(vuln) = self.check_stack_overflow(write) {
                vulns.push(vuln);
            }
            
            // Check heap overflow
            if let Some(vuln) = self.check_heap_overflow(write) {
                vulns.push(vuln);
            }
            
            // Check off-by-one
            if let Some(vuln) = self.check_off_by_one(write) {
                vulns.push(vuln);
            }
        }
        
        vulns
    }
    
    unsafe fn handles(&self, vuln_type: &VulnerabilityType) -> bool {
        matches!(
            vuln_type,
            VulnerabilityType::StackBufferOverflow | VulnerabilityType::HeapBufferOverflow
        )
    }
}

/// Check if function is dangerous
///
pub unsafe fn is_dangerous_function(name: &str) -> bool {
    DANGEROUS_FUNCTIONS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_frame() {
        unsafe {
            let mut frame = StackFrame::new(0x7fff0000, 0x7ffef000);
            frame.add_buffer(-0x100, 256);
            
            assert!(frame.contains(0x7ffef500));
            assert_eq!(frame.get_buffer(-0x100), Some(256));
        }
    }

    #[test]
    fn test_dangerous_function() {
        unsafe {
            assert!(is_dangerous_function("strcpy"));
            assert!(is_dangerous_function("gets"));
            assert!(!is_dangerous_function("strncpy"));
        }
    }

    #[test]
    fn test_stack_overflow_detection() {
        unsafe {
            let mut detector = BufferOverflowDetector::new();
            
            // Create stack frame with buffer
            let mut frame = StackFrame::new(0x7fff0000, 0x7ffef000);
            frame.add_buffer(-0x100, 100); // 100-byte buffer
            detector.track_frame(frame);
            
            // Simulate write that overflows
            detector.track_write(0x400500, 0x7ffef000 - 0x100, 150, false, false);
            
            let context = DetectionContext::new(0x400500);
            let vulns = detector.detect(&context);
            
            assert!(!vulns.is_empty());
            assert_eq!(vulns[0].vuln_type, VulnerabilityType::StackBufferOverflow);
        }
    }

    #[test]
    fn test_heap_overflow_detection() {
        unsafe {
            let mut detector = BufferOverflowDetector::new();
            
            // Track heap allocation
            detector.track_heap(0x10000000, 64);
            
            // Simulate write that overflows
            detector.track_write(0x400600, 0x10000000, 100, false, false);
            
            let context = DetectionContext::new(0x400600);
            let vulns = detector.detect(&context);
            
            assert!(!vulns.is_empty());
            assert_eq!(vulns[0].vuln_type, VulnerabilityType::HeapBufferOverflow);
        }
    }

    #[test]
    fn test_off_by_one() {
        unsafe {
            let mut detector = BufferOverflowDetector::new();
            
            detector.track_heap(0x10000000, 64);
            detector.track_write(0x400700, 0x10000000, 65, false, false);
            
            let context = DetectionContext::new(0x400700);
            let vulns = detector.detect(&context);
            
            // Should detect off-by-one
            assert!(!vulns.is_empty());
            assert_eq!(vulns[0].severity, Severity::Medium);
        }
    }
}
