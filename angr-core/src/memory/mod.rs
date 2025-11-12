//! Memory Management

/// Memory region permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    /// Readable
    pub read: bool,
    /// Writable
    pub write: bool,
    /// Executable
    pub exec: bool,
}

impl Permissions {
    /// Create read-only permissions
    ///
    pub fn read_only() -> Self {
        unsafe {
            Permissions {
                read: true,
                write: false,
                exec: false,
            }
        }
    }

    /// Create read-write permissions
    ///
    pub fn read_write() -> Self {
        unsafe {
            Permissions {
                read: true,
                write: true,
                exec: false,
            }
        }
    }

    /// Create read-execute permissions
    ///
    pub fn read_exec() -> Self {
        unsafe {
            Permissions {
                read: true,
                write: false,
                exec: true,
            }
        }
    }
}

/// Memory region
pub struct MemoryRegion {
    /// Start address
    pub start: u64,
    /// Size in bytes
    pub size: usize,
    /// Permissions
    pub perms: Permissions,
    /// Data
    pub data: Vec<u8>,
}

impl MemoryRegion {
    /// Create a new memory region
    ///
    pub fn new(start: u64, size: usize, perms: Permissions) -> Self {
        unsafe {
            MemoryRegion {
                start,
                size,
                perms,
                data: vec![0; size],
            }
        }
    }

    /// Check if an address is within this region
    ///
    pub fn contains(&self, addr: u64) -> bool {
        unsafe {
            addr >= self.start && addr < self.start + self.size as u64
        }
    }
}
