# Phase 4: Analysis Techniques (Weeks 13-16)

## Overview

Build practical binary analysis capabilities on top of the symbolic execution engine from Phase 3. Focus on vulnerability detection, exploit generation, and automated analysis techniques.

## Goals

1. Implement vulnerability detection techniques
2. Create exploit generation framework (AEG)
3. Build crash analysis and triaging
4. Develop automated input generation
5. Integration with real-world binaries

## Tasks

### Task 1: Vulnerability Detection Framework (~400 LOC)
**Files**: `angr-analysis/src/vulnerabilities/mod.rs`, `detector.rs`

**Components**:
- VulnerabilityDetector trait
- Vulnerability enum (BufferOverflow, UseAfterFree, NullPointerDeref, IntegerOverflow, FormatString, etc.)
- Detection context (state, constraints, memory operations)
- Reporting and severity classification

**Features**:
- Track dangerous operations (strcpy, gets, sprintf)
- Monitor memory accesses for bounds violations
- Detect use-after-free patterns
- Integer overflow detection
- Path conditions for exploitability

### Task 2: Buffer Overflow Detection (~450 LOC)
**Files**: `angr-analysis/src/vulnerabilities/buffer_overflow.rs`

**Components**:
- Stack buffer overflow detector
- Heap buffer overflow detector
- Write bounds checking
- Symbolic size analysis
- Exploitability assessment

**Features**:
- Track stack frame boundaries
- Monitor string operations (strcpy, sprintf, gets)
- Check symbolic write addresses
- Detect controllable overwrites
- Generate PoC inputs

### Task 3: Use-After-Free Detection (~400 LOC)
**Files**: `angr-analysis/src/vulnerabilities/use_after_free.rs`

**Components**:
- Heap allocation tracker
- Free operation monitor
- Use detection after free
- Double-free detection
- Temporal safety violations

**Features**:
- Track allocation/free pairs
- Monitor pointer usage
- Detect dangling pointer dereferences
- Report double-free attempts
- Path conditions for reachability

### Task 4: Exploit Generation Engine (~600 LOC)
**Files**: `angr-analysis/src/exploit/mod.rs`, `aeg.rs`, `payload.rs`

**Components**:
- AutomaticExploitGenerator (AEG)
- Payload builder
- Constraint-guided input generation
- ROP chain construction (basic)
- Shellcode generation

**Features**:
- Find vulnerability automatically
- Generate constraints for control
- Build exploit payloads
- Verify exploit success
- Multi-stage exploitation

### Task 5: Crash Analysis and Triage (~450 LOC)
**Files**: `angr-analysis/src/crash/mod.rs`, `triage.rs`, `minimizer.rs`

**Components**:
- CrashAnalyzer
- Crash classification (exploitable, DoS, benign)
- Input minimizer
- Crash deduplication
- Root cause analysis

**Features**:
- Analyze crash state
- Classify exploitability (PC control, write-what-where)
- Minimize crashing input
- Group similar crashes
- Generate crash reports

### Task 6: Input Generation (~400 LOC)
**Files**: `angr-analysis/src/input/mod.rs`, `generator.rs`, `constraints.rs`

**Components**:
- InputGenerator
- Constraint-based generation
- Coverage-guided generation
- Format-aware generation
- Mutation strategies

**Features**:
- Generate inputs from path constraints
- Maximize code coverage
- Handle structured inputs (files, packets)
- Smart mutation based on symbolic info
- Integration with fuzzers

### Task 7: Taint Analysis (~500 LOC)
**Files**: `angr-analysis/src/taint/mod.rs`, `tracker.rs`, `policy.rs`

**Components**:
- TaintTracker
- Taint sources and sinks
- Taint propagation rules
- Information flow analysis
- Taint policies

**Features**:
- Track user-controlled data
- Propagate taint through operations
- Detect tainted control flow
- Identify dangerous sinks
- Custom taint policies

### Task 8: Analysis Integration and Examples (~350 LOC)
**Files**: `angr-analysis/src/lib.rs`, `examples/phase4_analysis.rs`, `PHASE4_COMPLETE.md`

**Components**:
- Unified analysis interface
- Example workflows
- Real binary analysis
- Performance benchmarks
- Documentation

**Features**:
- End-to-end examples
- CTF challenge solving
- Vulnerability scanning
- Automated exploit generation demo
- Best practices guide

## Dependencies

Add to `angr-analysis/Cargo.toml`:
```toml
[dependencies]
angr-core = { path = "../angr-core" }
vex-core = { path = "../vex-core" }
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }
tracing = "0.1"
```

## Architecture

```
angr-analysis/
└── src/
    ├── lib.rs                      # Module exports
    ├── vulnerabilities/
    │   ├── mod.rs                  # Detector framework
    │   ├── buffer_overflow.rs      # Buffer overflow detection
    │   ├── use_after_free.rs       # UAF detection
    │   ├── format_string.rs        # Format string bugs
    │   └── integer_overflow.rs     # Integer issues
    ├── exploit/
    │   ├── mod.rs                  # AEG framework
    │   ├── aeg.rs                  # Automatic exploit generation
    │   ├── payload.rs              # Payload construction
    │   └── rop.rs                  # ROP chain building
    ├── crash/
    │   ├── mod.rs                  # Crash analysis
    │   ├── triage.rs               # Exploitability triage
    │   └── minimizer.rs            # Input minimization
    ├── input/
    │   ├── mod.rs                  # Input generation
    │   ├── generator.rs            # Constraint solving for inputs
    │   └── mutator.rs              # Smart mutation
    └── taint/
        ├── mod.rs                  # Taint tracking
        ├── tracker.rs              # Taint propagation
        └── policy.rs               # Taint policies
```

## Key Design Principles

### 1. Layered Detection
- Generic vulnerability detection framework
- Specific detectors for each vulnerability class
- Composable detection strategies

### 2. Constraint-Driven
- Use Z3 solver for input generation
- Constraint-guided exploit construction
- Symbolic reasoning for exploitability

### 3. Practical Focus
- Real-world vulnerability patterns
- Actual binary analysis workflows
- CTF and security research oriented

### 4. Performance
- Early pruning of infeasible paths
- Caching of solver queries
- Parallel analysis where possible

## Integration Points

### With Phase 3 (Symbolic Execution)
- Use PathGroup for exploration
- Leverage SymbolicStepper for execution
- Query Z3Solver for input generation
- Hook vulnerable functions with SimProcedures

### With Phase 2 (Architectures)
- Architecture-specific vulnerability patterns
- Calling convention awareness
- Register usage patterns

### With Phase 1 (VEX IR)
- IR-level vulnerability detection
- Operation pattern matching
- Memory access analysis

## Success Criteria

- [ ] Detect buffer overflows in test binaries
- [ ] Find use-after-free vulnerabilities
- [ ] Generate working exploits automatically
- [ ] Triage crashes by exploitability
- [ ] Generate inputs achieving >80% coverage
- [ ] Track taint through >10 operations
- [ ] Analyze real CVE examples
- [ ] Complete integration examples

## Timeline

**Week 13**: Tasks 1-2 (Vulnerability framework + Buffer overflow)
**Week 14**: Tasks 3-4 (UAF + Exploit generation)
**Week 15**: Tasks 5-6 (Crash analysis + Input generation)
**Week 16**: Tasks 7-8 (Taint analysis + Integration)

## Expected Code Volume

- **Total**: ~3,150 LOC
- **Tests**: ~40 tests
- **Examples**: 5-7 complete examples
- **Documentation**: ~2,000 LOC

## Example Usage

```rust
unsafe {
    // Load binary
    let binary = Binary::load("vulnerable_app")?;
    
    // Create vulnerability detector
    let mut detector = VulnerabilityDetector::new();
    detector.register_all();
    
    // Scan for vulnerabilities
    let vulns = detector.scan(&binary)?;
    
    for vuln in vulns {
        println!("Found {}: {}", vuln.severity(), vuln.description());
        
        // Generate exploit
        if vuln.is_exploitable() {
            let aeg = AutomaticExploitGenerator::new();
            let exploit = aeg.generate(&vuln)?;
            
            println!("Generated exploit:");
            exploit.save("exploit.py")?;
        }
    }
}
```

## Testing Strategy

### Unit Tests
- Test each detector in isolation
- Known vulnerable code patterns
- Edge cases and false positives

### Integration Tests
- Real vulnerable binaries
- CTF challenge solving
- CVE reproduction

### Benchmarks
- Analysis performance
- Solver query efficiency
- Path exploration scaling

## Known Limitations

1. **No concrete execution**: Pure symbolic (for now)
2. **Limited ROP**: Basic gadget chaining only
3. **Single-threaded**: Parallel analysis in Phase 5
4. **No heap modeling**: Simple heap simulation
5. **Format string parsing**: Basic implementation

## Future Enhancements (Beyond Phase 4)

- Advanced heap exploitation techniques
- Kernel vulnerability detection
- Fuzzing integration (AFL, LibFuzzer)
- Concolic execution hybrid
- Machine learning for triage
- Advanced ROP/JOP construction

## References

- Python angr's vulnerability detection
- Mayhem/AEG papers
- Exploitable crash triage (GDB exploitable)
- Symbolic fuzzing techniques

---

**Status**: READY TO START
**Phase**: 4 of 6
**Estimated Effort**: 4 weeks
**Prerequisites**: Phase 3 complete ✅
