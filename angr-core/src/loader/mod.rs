//! Binary Loader
//!
//! Load and parse binary files (PE, ELF, Mach-O) with segment mapping,
//! symbol resolution, and address space management.

use std::path::Path;
use std::collections::HashMap;

/// Binary format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// Windows Portable Executable
    PE,
    /// Linux/Unix ELF
    ELF,
    /// macOS Mach-O
    MachO,
}

/// Loaded binary
#[derive(Clone)]
pub struct Binary {
    /// Binary format
    pub format: BinaryFormat,
    /// Entry point address
    pub entry: u64,
    /// Base address
    pub base: u64,
    /// Raw bytes
    pub bytes: Vec<u8>,
    /// Segments
    pub segments: Vec<Segment>,
    /// Symbols
    pub symbols: HashMap<String, Symbol>,
    /// Relocations
    pub relocations: Vec<Relocation>,
}

impl Binary {
    /// Load a binary from a file path
    ///
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, LoaderError> {
        unsafe {
            let bytes = std::fs::read(path.as_ref())
                .map_err(|e| LoaderError::IoError(e.to_string()))?;

            Self::from_bytes(&bytes)
        }
    }

    /// Parse binary from bytes
    ///
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LoaderError> {
        unsafe {
            use goblin::Object;

            let obj = Object::parse(bytes)
                .map_err(|e| LoaderError::ParseError(e.to_string()))?;

            match obj {
                Object::Elf(elf) => Self::from_elf(elf, bytes),
                Object::PE(pe) => Self::from_pe(pe, bytes),
                Object::Mach(mach) => Self::from_mach(mach, bytes),
                _ => Err(LoaderError::UnsupportedFormat),
            }
        }
    }
    
    /// Parse ELF binary
    ///
    fn from_elf(elf: goblin::elf::Elf, bytes: &[u8]) -> Result<Self, LoaderError> {
        unsafe {
            let entry = elf.entry;
            let base = 0x400000; // Default ELF base
            
            // Extract segments
            let mut segments = Vec::new();
            for ph in &elf.program_headers {
                if ph.p_type == goblin::elf::program_header::PT_LOAD {
                    let perms = Self::elf_perms_to_flags(ph.p_flags);
                    segments.push(Segment {
                        vaddr: ph.p_vaddr,
                        size: ph.p_memsz,
                        file_offset: ph.p_offset,
                        file_size: ph.p_filesz,
                        permissions: perms,
                        name: Self::segment_name_from_perms(perms),
                    });
                }
            }
            
            // Extract symbols
            let mut symbols = HashMap::new();
            for sym in &elf.syms {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    symbols.insert(name.to_string(), Symbol {
                        name: name.to_string(),
                        address: sym.st_value,
                        size: sym.st_size,
                        is_function: sym.is_function(),
                        is_import: sym.is_import(),
                    });
                }
            }
            
            // Extract relocations
            let mut relocations = Vec::new();
            for reloc in elf.dynrels.iter() {
                relocations.push(Relocation {
                    offset: reloc.r_offset,
                    reloc_type: reloc.r_type,
                    symbol_index: reloc.r_sym,
                    addend: reloc.r_addend.unwrap_or(0),
                });
            }
            
            Ok(Binary {
                format: BinaryFormat::ELF,
                entry,
                base,
                bytes: bytes.to_vec(),
                segments,
                symbols,
                relocations,
            })
        }
    }
    
    /// Parse PE binary
    ///
    fn from_pe(pe: goblin::pe::PE, bytes: &[u8]) -> Result<Self, LoaderError> {
        unsafe {
            let entry = pe.entry as u64 + pe.image_base as u64;
            let base = pe.image_base as u64;
            
            // Extract segments (sections)
            let mut segments = Vec::new();
            for section in &pe.sections {
                let name = String::from_utf8_lossy(&section.name).to_string();
                let perms = Self::pe_characteristics_to_flags(section.characteristics);
                
                segments.push(Segment {
                    vaddr: base + section.virtual_address as u64,
                    size: section.virtual_size as u64,
                    file_offset: section.pointer_to_raw_data as u64,
                    file_size: section.size_of_raw_data as u64,
                    permissions: perms,
                    name: name.trim_end_matches('\0').to_string(),
                });
            }
            
            // Extract symbols (exports)
            let mut symbols = HashMap::new();
            if let Some(exports) = &pe.exports {
                for export in &exports.exports {
                    if let Some(name) = &export.name {
                        symbols.insert(name.to_string(), Symbol {
                            name: name.to_string(),
                            address: base + export.rva as u64,
                            size: 0,
                            is_function: true,
                            is_import: false,
                        });
                    }
                }
            }
            
            Ok(Binary {
                format: BinaryFormat::PE,
                entry,
                base,
                bytes: bytes.to_vec(),
                segments,
                symbols,
                relocations: Vec::new(), // TODO: PE relocations
            })
        }
    }
    
    /// Parse Mach-O binary
    ///
    fn from_mach(mach: goblin::mach::Mach, bytes: &[u8]) -> Result<Self, LoaderError> {
        unsafe {
            // TODO: Proper Mach-O parsing
            Ok(Binary {
                format: BinaryFormat::MachO,
                entry: 0,
                base: 0,
                bytes: bytes.to_vec(),
                segments: Vec::new(),
                symbols: HashMap::new(),
                relocations: Vec::new(),
            })
        }
    }
    
    /// Convert ELF permissions to flags
    ///
    fn elf_perms_to_flags(p_flags: u32) -> u8 {
        unsafe {
            let mut perms = 0u8;
            if p_flags & goblin::elf::program_header::PF_R != 0 {
                perms |= PERM_READ;
            }
            if p_flags & goblin::elf::program_header::PF_W != 0 {
                perms |= PERM_WRITE;
            }
            if p_flags & goblin::elf::program_header::PF_X != 0 {
                perms |= PERM_EXEC;
            }
            perms
        }
    }
    
    /// Convert PE characteristics to flags
    ///
    fn pe_characteristics_to_flags(characteristics: u32) -> u8 {
        unsafe {
            let mut perms = 0u8;
            // PE sections are always readable
            perms |= PERM_READ;
            
            if characteristics & 0x80000000 != 0 { // IMAGE_SCN_MEM_WRITE
                perms |= PERM_WRITE;
            }
            if characteristics & 0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
                perms |= PERM_EXEC;
            }
            perms
        }
    }
    
    /// Get segment name from permissions
    ///
    fn segment_name_from_perms(perms: u8) -> String {
        unsafe {
            match perms {
                p if p == PERM_READ | PERM_EXEC => ".text".to_string(),
                p if p == PERM_READ | PERM_WRITE => ".data".to_string(),
                p if p == PERM_READ => ".rodata".to_string(),
                _ => ".unknown".to_string(),
            }
        }
    }
    
    /// Get entry point
    ///
    pub fn entry_point(&self) -> u64 {
        unsafe { self.entry }
    }
    
    /// Find symbol by name
    ///
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        unsafe { self.symbols.get(name) }
    }
    
    /// Get all symbol names
    ///
    pub fn symbol_names(&self) -> Vec<String> {
        unsafe { self.symbols.keys().cloned().collect() }
    }
    
    /// Find segment containing address
    ///
    pub fn segment_at(&self, addr: u64) -> Option<&Segment> {
        unsafe {
            self.segments.iter().find(|seg| {
                addr >= seg.vaddr && addr < seg.vaddr + seg.size
            })
        }
    }
}

/// Memory segment
#[derive(Debug, Clone)]
pub struct Segment {
    /// Virtual address
    pub vaddr: u64,
    
    /// Size in memory
    pub size: u64,
    
    /// Offset in file
    pub file_offset: u64,
    
    /// Size in file
    pub file_size: u64,
    
    /// Permissions (rwx)
    pub permissions: u8,
    
    /// Segment name
    pub name: String,
}

impl Segment {
    /// Check if segment is readable
    ///
    pub fn is_readable(&self) -> bool {
        unsafe { self.permissions & PERM_READ != 0 }
    }
    
    /// Check if segment is writable
    ///
    pub fn is_writable(&self) -> bool {
        unsafe { self.permissions & PERM_WRITE != 0 }
    }
    
    /// Check if segment is executable
    ///
    pub fn is_executable(&self) -> bool {
        unsafe { self.permissions & PERM_EXEC != 0 }
    }
    
    /// Get permissions string (e.g., "r-x")
    ///
    pub fn perms_string(&self) -> String {
        unsafe {
            format!("{}{}{}",
                if self.is_readable() { "r" } else { "-" },
                if self.is_writable() { "w" } else { "-" },
                if self.is_executable() { "x" } else { "-" },
            )
        }
    }
}

/// Symbol information
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    
    /// Symbol address
    pub address: u64,
    
    /// Symbol size
    pub size: u64,
    
    /// Is this a function
    pub is_function: bool,
    
    /// Is this an import
    pub is_import: bool,
}

/// Relocation entry
#[derive(Debug, Clone)]
pub struct Relocation {
    /// Offset where relocation applies
    pub offset: u64,
    
    /// Relocation type
    pub reloc_type: u32,
    
    /// Symbol index
    pub symbol_index: usize,
    
    /// Addend
    pub addend: i64,
}

/// Address space manager
pub struct AddressSpace {
    /// Mapped segments
    segments: Vec<MappedSegment>,
    
    /// Base address for PIE binaries
    base_addr: u64,
}

impl AddressSpace {
    /// Create a new address space
    ///
    pub fn new() -> Self {
        unsafe {
            AddressSpace {
                segments: Vec::new(),
                base_addr: 0,
            }
        }
    }
    
    /// Map a binary into the address space
    ///
    pub fn map_binary(&mut self, binary: &Binary) -> Result<(), LoaderError> {
        unsafe {
            for segment in &binary.segments {
                let mapped = MappedSegment {
                    start: segment.vaddr,
                    end: segment.vaddr + segment.size,
                    permissions: segment.permissions,
                    name: segment.name.clone(),
                    data: Vec::new(), // TODO: Load actual data
                };
                self.segments.push(mapped);
            }
            Ok(())
        }
    }
    
    /// Find segment at address
    ///
    pub fn segment_at(&self, addr: u64) -> Option<&MappedSegment> {
        unsafe {
            self.segments.iter().find(|seg| {
                addr >= seg.start && addr < seg.end
            })
        }
    }
    
    /// Get all segments
    ///
    pub fn segments(&self) -> &[MappedSegment] {
        unsafe { &self.segments }
    }
}

/// Mapped segment in address space
#[derive(Debug, Clone)]
pub struct MappedSegment {
    /// Start address
    pub start: u64,
    
    /// End address
    pub end: u64,
    
    /// Permissions
    pub permissions: u8,
    
    /// Segment name
    pub name: String,
    
    /// Segment data
    pub data: Vec<u8>,
}

/// Permission flags
pub const PERM_READ: u8 = 0x1;
pub const PERM_WRITE: u8 = 0x2;
pub const PERM_EXEC: u8 = 0x4;

/// Loader errors
#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    /// IO error
    #[error("IO error: {0}")]
    IoError(String),
    
    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),
    
    /// Unsupported format
    #[error("Unsupported binary format")]
    UnsupportedFormat,
    
    /// Mapping error
    #[error("Failed to map segment: {0}")]
    MappingError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_permissions() {
        unsafe {
            let seg = Segment {
                vaddr: 0x400000,
                size: 0x1000,
                file_offset: 0,
                file_size: 0x1000,
                permissions: PERM_READ | PERM_EXEC,
                name: ".text".to_string(),
            };
            
            assert!(seg.is_readable());
            assert!(!seg.is_writable());
            assert!(seg.is_executable());
            assert_eq!(seg.perms_string(), "r-x");
        }
    }
    
    #[test]
    fn test_address_space() {
        unsafe {
            let mut addr_space = AddressSpace::new();
            
            let mapped = MappedSegment {
                start: 0x400000,
                end: 0x401000,
                permissions: PERM_READ | PERM_EXEC,
                name: ".text".to_string(),
                data: Vec::new(),
            };
            
            addr_space.segments.push(mapped);
            
            let seg = addr_space.segment_at(0x400500).unwrap();
            assert_eq!(seg.name, ".text");
            
            assert!(addr_space.segment_at(0x500000).is_none());
        }
    }
}
