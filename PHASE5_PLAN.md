# Phase 5: Angr API & Integration

**Timeline:** Weeks 17-20  
**Status:** IN PROGRESS  
**Goal:** Create a unified, high-level API that integrates all previous phases into a cohesive binary analysis platform matching Python angr's capabilities

---

## Overview

Phase 5 focuses on creating the user-facing API layer that makes angr-rs accessible and powerful. This includes the Project class (entry point for all analyses), simulation management, analysis orchestration, Python bindings, and a comprehensive CLI tool.

**Key Design Principles:**
- Match Python angr's API where possible for familiarity
- Maintain Rust idioms and safety guarantees
- Provide both high-level convenience and low-level control
- Enable seamless Python interoperability

---

## Task Breakdown

### Task 1: Project Class Implementation (~500 LOC)
**File:** `angr-api/src/project.rs`  
**Duration:** Week 17, Days 1-2

**Core Components:**
- **Project Struct:**
  - Binary path and loaded binary
  - Architecture information
  - Entry point & main object
  - Loader with address space
  - Factory for creating states
  - Knowledge base for analysis results

- **Project::new() Constructor:**
  - Load binary from path
  - Auto-detect architecture
  - Initialize loader
  - Set up address space
  - Configure factory

- **Factory Pattern:**
  - `factory.entry_state()` - Create state at entry point
  - `factory.blank_state(addr)` - Create state at arbitrary address
  - `factory.call_state(addr, args)` - State with function call setup
  - `factory.full_init_state()` - State with full binary initialization

- **Analysis Integration:**
  - `project.analyses` - Access to analysis manager
  - `project.kb` - Knowledge base access

**API Example:**
```rust
let project = Project::new("./binary")?;
let entry = project.factory.entry_state();
let cfg = project.analyses.cfg_fast()?;
```

---

### Task 2: Binary Loader & Address Space (~600 LOC)
**Files:** `angr-core/src/loader/mod.rs`, `loader/backend.rs`, `loader/memory.rs`  
**Duration:** Week 17, Days 3-5

**Loader Components:**
- **LoaderBackend Trait:**
  - `load()` - Load binary into memory
  - `segments()` - Get loadable segments
  - `symbols()` - Symbol table
  - `relocations()` - Relocation entries
  - `entry_point()` - Binary entry point

- **Concrete Backends:**
  - `ElfBackend` - ELF binary loader
  - `PeBackend` - PE binary loader
  - `MachOBackend` - Mach-O loader

- **Address Space:**
  - Segment mapping (code, data, bss, etc.)
  - Virtual memory layout
  - Load address handling
  - PIE/ASLR support
  - Shared library loading (stub for Phase 5)

- **Memory Regions:**
  - Track loaded segments with permissions
  - Handle overlapping regions
  - Provide address lookup
  - Support memory snapshots

**API Example:**
```rust
let loader = Loader::new("./binary")?;
loader.map_binary()?;
let addr_space = loader.address_space();
let segment = addr_space.segment_at(0x400000)?;
```

---

### Task 3: State & Simulation Management (~450 LOC)
**File:** `angr-api/src/simulation.rs`  
**Duration:** Week 18, Days 1-2

**SimulationManager (simgr):**
- **State Collections (Stashes):**
  - `active` - States being explored
  - `deadended` - States that exited/errored
  - `found` - States matching find condition
  - `avoided` - States matching avoid condition
  - `unconstrained` - States with unconstrained PC

- **Exploration Methods:**
  - `step()` - Single step all active states
  - `run()` - Run until completion
  - `explore(find, avoid)` - Goal-directed exploration
  - `use_technique(technique)` - Apply exploration technique

- **Exploration Techniques:**
  - DFS, BFS, Random (from Phase 3)
  - Loop limiter
  - Threading
  - Veritesting (future)

- **State Management:**
  - Move states between stashes
  - Prune deadended states
  - State prioritization
  - Memory limits

**API Example:**
```rust
let simgr = project.simulation_manager(entry_state);
simgr.explore(
    |state| state.pc() == 0x400800,  // find
    |state| state.pc() == 0x400900,  // avoid
)?;
let found = simgr.found();
```

---

### Task 4: Analysis Management Framework (~400 LOC)
**File:** `angr-api/src/analyses.rs`  
**Duration:** Week 18, Days 3-4

**AnalysisManager:**
- **Analysis Registry:**
  - Register available analyses
  - Analysis dependencies
  - Result caching

- **Built-in Analyses:**
  - `cfg_fast()` - Fast CFG recovery
  - `cfg_emulated()` - Precise CFG via symbolic execution
  - `reaching_definitions(func)` - RD analysis
  - `variable_recovery(func)` - Recover variables
  - `calling_convention(func)` - CC identification
  - `vulnerability_scan()` - Run vuln detectors
  - `taint_analysis(sources, sinks)` - Taint tracking

- **Knowledge Base:**
  - Store analysis results
  - Cross-analysis data sharing
  - Function metadata
  - Variable types

- **Analysis Interface:**
  ```rust
  pub trait Analysis {
      type Result;
      fn name(&self) -> &str;
      unsafe fn run(&mut self, project: &Project) -> Result<Self::Result>;
  }
  ```

**API Example:**
```rust
let cfg = project.analyses.cfg_fast()?;
let funcs = cfg.functions();
for func in funcs {
    let vars = project.analyses.variable_recovery(func)?;
}
```

---

### Task 5: High-Level API (~350 LOC)
**File:** `angr-api/src/lib.rs`  
**Duration:** Week 19, Days 1-2

**Convenience APIs:**
- **Project Methods:**
  - `project.entry_point()` - Get entry address
  - `project.arch()` - Architecture info
  - `project.loader()` - Binary loader access
  - `project.kb()` - Knowledge base

- **Explorer Pattern:**
  ```rust
  let result = project.explore(
      entry_state,
      |s| s.pc() == target,
      |s| s.pc() == avoid,
  )?;
  ```

- **Quick Analysis:**
  ```rust
  let vulns = project.find_vulnerabilities()?;
  let exploits = project.generate_exploits(&vulns)?;
  ```

- **Fluent API:**
  ```rust
  let state = project.factory
      .blank_state(0x400000)
      .with_symbolic_arg(0, 100)
      .with_constraint(condition);
  ```

**Re-exports:**
- Export key types from all crates
- Provide prelude module
- Organize by functionality

---

### Task 6: Python FFI Bindings (~500 LOC)
**Files:** `angr-ffi/src/python/mod.rs`, `python/project.rs`, `python/state.rs`  
**Duration:** Week 19, Days 3-5

**PyO3 Bindings:**
- **PyProject:**
  ```python
  project = angr.Project("./binary")
  state = project.factory.entry_state()
  simgr = project.factory.simulation_manager(state)
  ```

- **PyState:**
  ```python
  state.regs.rax = 0x1234
  val = state.mem[0x400000].uint64_t.resolved
  state.solver.add(condition)
  ```

- **PySimulationManager:**
  ```python
  simgr.explore(find=0x400800, avoid=0x400900)
  if simgr.found:
      solution = simgr.found[0].solver.eval(user_input)
  ```

- **PyAnalyses:**
  ```python
  cfg = project.analyses.CFGFast()
  vulns = project.analyses.VulnerabilityScanner()
  ```

**Type Conversions:**
- Rust types ↔ Python types
- Error handling across FFI
- Memory management
- GIL handling

---

### Task 7: Enhanced CLI Tool (~400 LOC)
**File:** `angr-cli/src/main.rs`  
**Duration:** Week 20, Days 1-3

**Subcommands:**
- **analyze:**
  ```bash
  angr analyze binary --cfg --functions
  angr analyze binary --vulnerabilities
  angr analyze binary --taint-sources stdin --taint-sinks exec
  ```

- **explore:**
  ```bash
  angr explore binary --find 0x400800 --avoid 0x400900
  angr explore binary --entry-state --symbolic-arg 0 100
  ```

- **exploit:**
  ```bash
  angr exploit binary --vuln-scan
  angr exploit binary --generate --vuln-id 1
  ```

- **disasm:**
  ```bash
  angr disasm binary --function main
  angr disasm binary --address 0x400000 --count 20
  ```

- **info:**
  ```bash
  angr info binary --arch --entry --segments
  angr info binary --symbols
  ```

**Features:**
- Colored output
- Progress bars
- JSON output mode
- Verbose logging
- Configuration files

---

### Task 8: Documentation & Examples (~300 LOC)
**Files:** `examples/phase5_api.rs`, `PHASE5_COMPLETE.md`, API docs  
**Duration:** Week 20, Days 4-5

**Examples:**
1. **Basic Project Usage:**
   - Load binary
   - Create states
   - Simple exploration

2. **CFG Analysis:**
   - Build CFG
   - Enumerate functions
   - Find paths

3. **Symbolic Exploration:**
   - Symbolic arguments
   - Constraint solving
   - Find vulnerabilities

4. **Vulnerability Hunting:**
   - Run scanners
   - Generate exploits
   - Verify exploits

5. **Complete Workflow:**
   - Load → Analyze → Explore → Exploit
   - End-to-end pipeline

**Documentation:**
- API reference for all public types
- Usage guides
- Architecture overview
- Migration from Python angr
- PHASE5_COMPLETE.md summary

---

## Integration Points

### With Previous Phases:
- **Phase 1 (VEX):** Used by loader for lifting
- **Phase 2 (Architectures):** Architecture detection and lifting
- **Phase 3 (Symbolic Execution):** State creation and exploration
- **Phase 4 (Analysis):** Vulnerability detection and exploit generation

### Module Dependencies:
```
angr-api (Phase 5)
├── angr-core (Phases 1-3)
│   ├── vex-core (Phase 1)
│   ├── vex-guests (Phase 2)
│   └── symbolic execution (Phase 3)
└── angr-analysis (Phase 4)
    └── vulnerabilities, exploits, etc.
```

---

## API Design Philosophy

### Python angr Compatibility:
- Match naming conventions where possible
- Maintain familiar workflow patterns
- Support similar exploration techniques

### Rust Idioms:
- Strong typing with Result<T, E>
- Builder patterns for configuration
- Trait-based extensibility
- Zero-cost abstractions

### Performance:
- Lazy loading where possible
- Efficient state management
- Parallel analysis support
- Memory-conscious design

---

## Success Criteria

✅ **Project Class:**
- Load binaries of all formats (ELF, PE, Mach-O)
- Auto-detect architecture
- Create states at arbitrary addresses
- Access all analysis capabilities

✅ **Simulation Manager:**
- Explore with find/avoid conditions
- Multiple exploration strategies
- State stash management
- Efficient state handling

✅ **Analysis Framework:**
- Run all Phase 4 analyses
- Cache results in knowledge base
- Cross-analysis integration
- Extensible for new analyses

✅ **Python Bindings:**
- Full API coverage
- Natural Python interface
- Error handling across FFI
- Performance comparable to Rust API

✅ **CLI Tool:**
- All major workflows supported
- User-friendly output
- JSON export capability
- Comprehensive help text

✅ **Documentation:**
- Complete API reference
- Usage examples for all features
- Migration guide from Python angr
- Architecture documentation

---

## Testing Strategy

### Unit Tests:
- Project initialization
- State factory methods
- Simulation manager operations
- Analysis execution

### Integration Tests:
- Full analysis workflows
- Python FFI boundary
- CLI commands
- Cross-module integration

### Example Binaries:
- Simple crackme
- Buffer overflow sample
- Multi-function binary
- Stripped binary

---

## Estimated Metrics

| Component | LOC | Tests |
|-----------|-----|-------|
| Project class | 500 | 8 |
| Loader & address space | 600 | 10 |
| Simulation manager | 450 | 8 |
| Analysis manager | 400 | 6 |
| High-level API | 350 | 5 |
| Python FFI | 500 | 8 |
| CLI tool | 400 | 5 |
| Examples & docs | 300 | - |
| **Total** | **3,500** | **50** |

---

## Timeline

### Week 17:
- Days 1-2: Project class
- Days 3-5: Binary loader

### Week 18:
- Days 1-2: Simulation manager
- Days 3-4: Analysis manager
- Day 5: Buffer/catchup

### Week 19:
- Days 1-2: High-level API
- Days 3-5: Python FFI

### Week 20:
- Days 1-3: CLI tool
- Days 4-5: Documentation

---

## Phase 5 Deliverables

1. Complete Project API
2. Binary loader with segment mapping
3. Simulation manager with exploration
4. Analysis management framework
5. High-level convenience APIs
6. Python bindings (PyO3)
7. Enhanced CLI tool
8. Comprehensive examples and documentation

**Total:** ~3,500 LOC with 50 tests

This phase transforms angr-rs from a collection of powerful components into a unified, user-friendly binary analysis platform!
