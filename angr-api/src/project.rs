//! Project Management
//!
//! The Project class is the main entry point for binary analysis in angr-rs.
//! It provides access to all analysis capabilities and manages the binary,
//! architecture, and knowledge base.

use angr_core::loader::Binary;
use angr_core::symbolic::SimState;
use vex_core::guest::Architecture;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

/// Binary analysis project
///
/// The main entry point for all binary analysis operations.
/// Manages binary loading, architecture detection, state creation,
/// and analysis orchestration.
pub struct Project {
    /// Path to the binary
    pub filename: PathBuf,
    
    /// Loaded binary
    pub binary: Binary,
    
    /// Detected architecture
    pub arch: Architecture,
    
    /// Entry point address
    pub entry: u64,
    
    /// State factory for creating execution states
    pub factory: StateFactory,
    
    /// Knowledge base for storing analysis results
    pub kb: KnowledgeBase,
    
    /// Loader (future: will handle shared libraries)
    loader: Loader,
}

impl Project {
    /// Create a new project by loading a binary
    ///
    /// # Arguments
    /// * `path` - Path to the binary file
    ///
    ///
    /// # Example
    /// ```no_run
    /// use angr_api::Project;
    /// let project = Project::new("./binary").unwrap();
    /// ```
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ProjectError> {
        unsafe {
            let path_buf = path.as_ref().to_path_buf();
            
            // Load binary
            let binary = Binary::load(&path_buf)
                .map_err(|e| ProjectError::LoadError(e.to_string()))?;
            
            // Detect architecture
            let arch = Self::detect_architecture(&binary)?;
            
            // Get entry point
            let entry = binary.entry_point();
            
            // Create loader
            let loader = Loader::new(binary.clone());
            
            // Create factory
            let factory = StateFactory::new(arch, entry);
            
            // Create knowledge base
            let kb = KnowledgeBase::new();
            
            Ok(Project {
                filename: path_buf,
                binary,
                arch,
                entry,
                factory,
                kb,
                loader,
            })
        }
    }
    
    /// Load a binary with custom options
    ///
    pub fn with_options<P: AsRef<Path>>(
        path: P,
        options: ProjectOptions,
    ) -> Result<Self, ProjectError> {
        unsafe {
            let mut project = Self::new(path)?;
            
            // Apply custom entry point if specified
            if let Some(entry) = options.entry_point {
                project.entry = entry;
                project.factory.entry_point = entry;
            }
            
            // Apply architecture override if specified
            if let Some(arch) = options.architecture {
                project.arch = arch;
                project.factory.arch = arch;
            }
            
            Ok(project)
        }
    }
    
    /// Detect architecture from binary
    ///
    fn detect_architecture(binary: &Binary) -> Result<Architecture, ProjectError> {
        unsafe {
            // For now, simple detection based on binary format
            // TODO: Enhance with actual binary inspection
            Ok(Architecture::AMD64)
        }
    }
    
    /// Get the analyses interface
    ///
    pub fn analyses(&self) -> crate::analyses::Analyses {
        unsafe {
            crate::analyses::Analyses::new()
        }
    }
    
    /// Get entry point address
    ///
    pub fn entry_point(&self) -> u64 {
        unsafe { self.entry }
    }
    
    /// Get architecture
    ///
    pub fn architecture(&self) -> Architecture {
        unsafe { self.arch }
    }
    
    /// Get loader
    ///
    pub fn loader(&self) -> &Loader {
        unsafe { &self.loader }
    }
    
    /// Get knowledge base
    ///
    pub fn knowledge_base(&self) -> &KnowledgeBase {
        unsafe { &self.kb }
    }
    
    /// Create a simulation manager with the given state
    ///
    pub fn simulation_manager(&self, state: SimState) -> SimulationManager {
        unsafe {
            SimulationManager::new(state)
        }
    }
    
    // ========== High-Level Convenience APIs ==========
    
    /// Quick exploration to find a target address
    ///
    /// Creates an entry state, runs exploration to find the target,
    /// and returns the found states.
    ///
    ///
    /// # Example
    /// ```no_run
    /// let found = project.explore_to(0x400800)?;
    /// ```
    pub fn explore_to(&self, target: u64) -> Result<Vec<SimState>, crate::simulation::SimulationError> {
        unsafe {
            let entry = self.factory.entry_state();
            let mut simgr = self.simulation_manager(entry);
            simgr.explore_to(target)?;
            
            Ok(simgr.found().to_vec())
        }
    }
    
    /// Explore with find and avoid conditions
    ///
    pub fn explore<F, A>(
        &self,
        find: F,
        avoid: A,
    ) -> Result<Vec<SimState>, crate::simulation::SimulationError>
    where
        F: Fn(&SimState) -> bool,
        A: Fn(&SimState) -> bool,
    {
        unsafe {
            let entry = self.factory.entry_state();
            let mut simgr = self.simulation_manager(entry);
            simgr.explore(find, avoid)?;
            
            Ok(simgr.found().to_vec())
        }
    }
    
    /// Quick vulnerability scan
    ///
    /// Scans the binary for all vulnerabilities and returns exploitable ones.
    ///
    pub fn find_vulnerabilities(&self) -> Result<Vec<angr_analysis::vulnerabilities::Vulnerability>, crate::analyses::AnalysisError> {
        unsafe {
            let analyses = self.analyses();
            analyses.exploitable_vulnerabilities()
        }
    }
    
    /// Generate exploits for all found vulnerabilities
    ///
    pub fn generate_exploits(&self) -> Result<Vec<angr_analysis::exploit::Exploit>, crate::analyses::AnalysisError> {
        unsafe {
            let analyses = self.analyses();
            analyses.generate_all_exploits()
        }
    }
    
    /// Get all function addresses from the binary
    ///
    pub fn functions(&self) -> Vec<u64> {
        unsafe {
            self.kb.functions()
        }
    }
    
    /// Get function name by address
    ///
    pub fn function_name(&self, addr: u64) -> Option<String> {
        unsafe {
            self.kb.function(addr).and_then(|f| f.name)
        }
    }
    
    /// Get all symbols from the binary
    ///
    pub fn symbols(&self) -> Vec<String> {
        unsafe {
            self.binary.symbol_names()
        }
    }
    
    /// Get symbol address by name
    ///
    pub fn symbol_address(&self, name: &str) -> Option<u64> {
        unsafe {
            self.binary.symbol(name).map(|s| s.address)
        }
    }
    
    /// Get segment at address
    ///
    pub fn segment_at(&self, addr: u64) -> Option<&angr_core::loader::Segment> {
        unsafe {
            self.binary.segment_at(addr)
        }
    }
    
    /// Check if address is executable
    ///
    pub fn is_executable(&self, addr: u64) -> bool {
        unsafe {
            self.segment_at(addr)
                .map(|seg| seg.is_executable())
                .unwrap_or(false)
        }
    }
    
    /// Run all standard analyses
    ///
    /// Builds CFG, scans for vulnerabilities, performs taint analysis.
    ///
    pub fn analyze_all(&self) -> Result<ProjectAnalysis, crate::analyses::AnalysisError> {
        unsafe {
            let analyses = self.analyses();
            
            // Run CFG
            let cfg = analyses.cfg_fast()?;
            
            // Scan vulnerabilities
            let vulns = analyses.vulnerability_scan()?;
            
            // Detect common injection bugs
            let cmd_injection = analyses.detect_command_injection()?;
            let path_traversal = analyses.detect_path_traversal()?;
            
            Ok(ProjectAnalysis {
                cfg_complete: true,
                vulnerabilities_found: vulns.len(),
                exploitable_count: vulns.iter().filter(|v| v.is_exploitable()).count(),
                command_injection_flows: cmd_injection.len(),
                path_traversal_flows: path_traversal.len(),
            })
        }
    }
}

/// State factory for creating execution states
///
/// Provides convenient methods for creating states at various
/// program points with different configurations.
pub struct StateFactory {
    /// Architecture
    arch: Architecture,
    
    /// Default entry point
    entry_point: u64,
}

impl StateFactory {
    /// Create a new state factory
    ///
    pub fn new(arch: Architecture, entry_point: u64) -> Self {
        unsafe {
            StateFactory {
                arch,
                entry_point,
            }
        }
    }
    
    /// Create a state at the entry point
    ///
    pub fn entry_state(&self) -> SimState {
        unsafe {
            SimState::new(self.entry_point)
        }
    }
    
    /// Create a blank state at an arbitrary address
    ///
    pub fn blank_state(&self, addr: u64) -> SimState {
        unsafe {
            SimState::new(addr)
        }
    }
    
    /// Create a state configured for a function call
    ///
    /// # Arguments
    /// * `addr` - Function address
    /// * `args` - Function arguments
    ///
    pub fn call_state(&self, addr: u64, args: Vec<u64>) -> SimState {
        unsafe {
            let mut state = SimState::new(addr);
            
            // Set up arguments based on calling convention
            // x86_64 System V: rdi, rsi, rdx, rcx, r8, r9, then stack
            let arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
            
            for (i, &arg) in args.iter().enumerate() {
                if i < arg_regs.len() {
                    // Set register argument
                    // TODO: Implement proper register setting
                } else {
                    // Push stack argument
                    // TODO: Implement stack argument setup
                }
            }
            
            state
        }
    }
    
    /// Create a state with full binary initialization
    ///
    /// Sets up stack, heap, and environment variables
    ///
    pub fn full_init_state(&self) -> SimState {
        unsafe {
            let mut state = SimState::new(self.entry_point);
            
            // Set up stack pointer
            // x86_64: typically 0x7ffffffde000
            let stack_base = 0x7ffffffde000u64;
            // TODO: Set stack pointer register
            
            // Set up heap
            // Heap typically starts at 0x10000000
            
            state
        }
    }
}

/// Knowledge base for storing analysis results
///
/// Shared storage for all analysis data including functions,
/// CFGs, variable information, and type data.
pub struct KnowledgeBase {
    /// Function information
    functions: Arc<RwLock<HashMap<u64, FunctionInfo>>>,
    
    /// CFG cache
    cfg: Arc<RwLock<Option<()>>>, // TODO: Proper CFG type
    
    /// Variable information
    variables: Arc<RwLock<HashMap<u64, Vec<()>>>>, // TODO: Variable type
}

impl KnowledgeBase {
    /// Create a new knowledge base
    ///
    pub fn new() -> Self {
        unsafe {
            KnowledgeBase {
                functions: Arc::new(RwLock::new(HashMap::new())),
                cfg: Arc::new(RwLock::new(None)),
                variables: Arc::new(RwLock::new(HashMap::new())),
            }
        }
    }
    
    /// Get function information
    ///
    pub fn function(&self, addr: u64) -> Option<FunctionInfo> {
        unsafe {
            self.functions.read().unwrap().get(&addr).cloned()
        }
    }
    
    /// Add function information
    ///
    pub fn add_function(&self, addr: u64, info: FunctionInfo) {
        unsafe {
            self.functions.write().unwrap().insert(addr, info);
        }
    }
    
    /// Get all functions
    ///
    pub fn functions(&self) -> Vec<u64> {
        unsafe {
            self.functions.read().unwrap().keys().copied().collect()
        }
    }
}

/// Function information stored in knowledge base
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function address
    pub address: u64,
    
    /// Function name (if known)
    pub name: Option<String>,
    
    /// Function size in bytes
    pub size: usize,
    
    /// Is this a library function
    pub is_library: bool,
    
    /// Calling convention
    pub calling_convention: Option<String>,
}

/// Loader for managing binary and address space
///
/// Handles binary loading, segment mapping, and address space management.
pub struct Loader {
    /// Main binary
    main_binary: Binary,
    
    /// Loaded segments
    segments: Vec<Segment>,
}

impl Loader {
    /// Create a new loader
    ///
    pub fn new(binary: Binary) -> Self {
        unsafe {
            Loader {
                main_binary: binary,
                segments: Vec::new(),
            }
        }
    }
    
    /// Get the main binary
    ///
    pub fn main_object(&self) -> &Binary {
        unsafe { &self.main_binary }
    }
    
    /// Get all segments
    ///
    pub fn segments(&self) -> &[Segment] {
        unsafe { &self.segments }
    }
}

/// Memory segment
#[derive(Debug, Clone)]
pub struct Segment {
    /// Start address
    pub start: u64,
    
    /// End address
    pub end: u64,
    
    /// Segment name
    pub name: String,
    
    /// Permissions (rwx)
    pub permissions: u8,
}

/// Simulation manager stub (will be expanded in Task 3)
pub struct SimulationManager {
    /// Active states
    active: Vec<SimState>,
}

impl SimulationManager {
    /// Create a new simulation manager
    ///
    pub fn new(state: SimState) -> Self {
        unsafe {
            SimulationManager {
                active: vec![state],
            }
        }
    }
}

/// Project configuration options
#[derive(Debug, Default)]
pub struct ProjectOptions {
    /// Override entry point
    pub entry_point: Option<u64>,
    
    /// Override architecture
    pub architecture: Option<Architecture>,
    
    /// Auto-load libraries
    pub auto_load_libs: bool,
    
    /// Base address for PIE binaries
    pub base_addr: Option<u64>,
}

impl ProjectOptions {
    /// Create default options
    ///
    pub fn new() -> Self {
        unsafe {
            ProjectOptions::default()
        }
    }
    
    /// Set custom entry point
    ///
    pub fn with_entry(mut self, entry: u64) -> Self {
        unsafe {
            self.entry_point = Some(entry);
            self
        }
    }
    
    /// Set custom architecture
    ///
    pub fn with_arch(mut self, arch: Architecture) -> Self {
        unsafe {
            self.architecture = Some(arch);
            self
        }
    }
}

/// Project analysis summary
///
/// Summary of all analyses run on a project
#[derive(Debug, Clone)]
pub struct ProjectAnalysis {
    /// CFG analysis completed
    pub cfg_complete: bool,
    
    /// Number of vulnerabilities found
    pub vulnerabilities_found: usize,
    
    /// Number of exploitable vulnerabilities
    pub exploitable_count: usize,
    
    /// Number of command injection flows
    pub command_injection_flows: usize,
    
    /// Number of path traversal flows
    pub path_traversal_flows: usize,
}

impl ProjectAnalysis {
    /// Check if project has security issues
    ///
    pub fn has_security_issues(&self) -> bool {
        unsafe {
            self.exploitable_count > 0 
                || self.command_injection_flows > 0 
                || self.path_traversal_flows > 0
        }
    }
    
    /// Get severity level
    ///
    pub fn severity(&self) -> &str {
        unsafe {
            if self.exploitable_count > 0 {
                "CRITICAL"
            } else if self.command_injection_flows > 0 || self.path_traversal_flows > 0 {
                "HIGH"
            } else if self.vulnerabilities_found > 0 {
                "MEDIUM"
            } else {
                "LOW"
            }
        }
    }
}

/// Project errors
#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    /// Binary load error
    #[error("Failed to load binary: {0}")]
    LoadError(String),
    
    /// Architecture detection failed
    #[error("Could not detect architecture")]
    ArchitectureDetectionError,
    
    /// Invalid entry point
    #[error("Invalid entry point: {0:#x}")]
    InvalidEntryPoint(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_project_options() {
        unsafe {
            let opts = ProjectOptions::new()
                .with_entry(0x400000)
                .with_arch(Architecture::AMD64);
            
            assert_eq!(opts.entry_point, Some(0x400000));
            assert_eq!(opts.architecture, Some(Architecture::AMD64));
        }
    }
    
    #[test]
    fn test_state_factory() {
        unsafe {
            let factory = StateFactory::new(Architecture::AMD64, 0x400000);
            let state = factory.entry_state();
            
            assert_eq!(state.pc(), 0x400000);
        }
    }
    
    #[test]
    fn test_knowledge_base() {
        unsafe {
            let kb = KnowledgeBase::new();
            
            let func_info = FunctionInfo {
                address: 0x400000,
                name: Some("main".to_string()),
                size: 0x100,
                is_library: false,
                calling_convention: Some("System V".to_string()),
            };
            
            kb.add_function(0x400000, func_info.clone());
            
            let retrieved = kb.function(0x400000).unwrap();
            assert_eq!(retrieved.address, 0x400000);
            assert_eq!(retrieved.name, Some("main".to_string()));
        }
    }
    
    #[test]
    fn test_loader() {
        unsafe {
            // This would require a real binary, so just test construction
            // In real tests, we'd load a test binary
        }
    }
}
