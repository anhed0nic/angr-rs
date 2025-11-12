//! Phase 4 Analysis Integration Examples
//!
//! End-to-end workflows demonstrating vulnerability detection,
//! exploit generation, crash analysis, input generation, and taint tracking

use angr_analysis::vulnerabilities::*;
use angr_analysis::exploit::*;
use angr_analysis::crash::*;
use angr_analysis::input::*;
use angr_analysis::taint::*;

/// Example 1: Complete vulnerability detection workflow
unsafe fn example_vulnerability_detection() {
    println!("=== Example 1: Vulnerability Detection ===\n");
    
    // Create scanner with multiple detectors
    let mut scanner = VulnerabilityScanner::new();
    scanner.register(Box::new(buffer_overflow::BufferOverflowDetector::new()));
    scanner.register(Box::new(use_after_free::UseAfterFreeDetector::new()));
    
    // Create detection context
    let ctx = DetectionContext::new(0x400500);
    
    // Scan for vulnerabilities
    scanner.scan(&ctx);
    
    // Get results
    let stats = scanner.stats();
    println!("{}", stats);
    
    // Get exploitable vulnerabilities
    let exploitable = scanner.get_exploitable();
    println!("\nFound {} exploitable vulnerabilities\n", exploitable.len());
    
    for vuln in exploitable {
        println!("{}", vuln);
    }
}

/// Example 2: Automatic exploit generation
unsafe fn example_exploit_generation() {
    println!("\n=== Example 2: Exploit Generation ===\n");
    
    // Create a sample vulnerability
    let mut vuln = Vulnerability::new(
        VulnerabilityType::StackBufferOverflow,
        Severity::High,
        0x400500,
        "Stack buffer overflow in function parse_input".to_string(),
    )
    .with_exploitability(Exploitability::Exploitable)
    .with_function("parse_input".to_string());
    
    vuln.add_metadata("buffer_size".to_string(), "128".to_string());
    vuln.add_metadata("overflow_size".to_string(), "64".to_string());
    
    println!("Vulnerability: {}\n", vuln);
    
    // Generate exploit automatically
    let aeg = AutomaticExploitGenerator::new()
        .with_timeout(5000)
        .with_rop();
    
    match aeg.generate(&vuln) {
        Ok(exploit) => {
            println!("✓ Successfully generated exploit!");
            println!("  Type: {:?}", exploit.exploit_type);
            println!("  Target: {:?}", exploit.target);
            println!("  Payload size: {} bytes\n", exploit.payload.len());
            
            // Generate Python exploit script
            let python_script = exploit.to_python();
            println!("Generated Python script:");
            println!("{}", python_script.lines().take(10).collect::<Vec<_>>().join("\n"));
        }
        Err(e) => println!("✗ Failed to generate exploit: {}", e),
    }
}

/// Example 3: Manual exploit construction
unsafe fn example_manual_exploit() {
    println!("\n=== Example 3: Manual Exploit Construction ===\n");
    
    // Create vulnerability
    let vuln = Vulnerability::new(
        VulnerabilityType::StackBufferOverflow,
        Severity::Critical,
        0x400600,
        "Buffer overflow with RIP control".to_string(),
    );
    
    // Build exploit manually
    let exploit = ExploitBuilder::new(vuln, ExploitType::ControlFlow)
        .target(ExploitTarget::ReturnAddress)
        .padding(128, b'A')                    // Fill buffer
        .address(0x7fffffffe000)               // Saved RBP
        .address(0x400700)                     // Return address (pop rdi; ret)
        .address(0x601100)                     // Argument (/bin/sh)
        .address(0x400800)                     // system() address
        .build();
    
    println!("Built exploit:");
    println!("  Payload size: {} bytes", exploit.payload.len());
    println!("  First 32 bytes: {:?}", &exploit.payload[..32.min(exploit.payload.len())]);
}

/// Example 4: Crash analysis and triage
unsafe fn example_crash_analysis() {
    println!("\n=== Example 4: Crash Analysis ===\n");
    
    let mut analyzer = CrashAnalyzer::new();
    
    // Analyze multiple crashes
    let crashes = vec![
        CrashInfo::new(CrashType::Segfault, 0x41414141)
            .with_fault_addr(0x41414141)
            .with_input(vec![b'A'; 200]),
        
        CrashInfo::new(CrashType::IllegalInstruction, 0x42424242)
            .with_input(vec![b'B'; 150]),
        
        CrashInfo::new(CrashType::StackOverflow, 0x400500)
            .with_input(vec![b'C'; 50]),
    ];
    
    for crash in crashes {
        let analyzed = analyzer.analyze(crash);
        println!("Crash: {}", analyzed.classification);
        println!("  Rating: {}", analyzed.rating);
        println!("  PC: 0x{:x}", analyzed.crash.pc);
        println!("  Root cause: {}\n", analyzed.root_cause);
    }
    
    // Get statistics
    let stats = analyzer.stats();
    println!("{}", stats);
    
    // Deduplicate
    let unique = analyzer.deduplicate();
    println!("\nUnique crashes: {}", unique.len());
}

/// Example 5: Crash triage
unsafe fn example_crash_triage() {
    println!("\n=== Example 5: Crash Triage ===\n");
    
    let mut triager = triage::CrashTriager::new();
    
    // Create analyzed crash
    let crash_info = CrashInfo::new(CrashType::Segfault, 0x41414141)
        .with_fault_addr(0x41414141);
    
    let analyzed = AnalyzedCrash {
        crash: crash_info,
        rating: ExploitabilityRating::Exploitable,
        classification: "Controlled PC crash".to_string(),
        root_cause: "Buffer overflow in parse_input".to_string(),
        hash: 0x1234567890abcdef,
    };
    
    let triaged = triager.triage(analyzed);
    
    println!("Triaged crash:");
    println!("  Priority: {:?}", triaged.priority);
    println!("  Notes:");
    for note in &triaged.notes {
        println!("    - {}", note);
    }
    
    println!("\nCritical crashes: {}", triager.critical().len());
}

/// Example 6: Input minimization
unsafe fn example_input_minimization() {
    println!("\n=== Example 6: Input Minimization ===\n");
    
    // Original crashing input
    let mut original = vec![b'A'; 100];
    original.extend(vec![b'X'; 10]); // Only X's trigger crash
    original.extend(vec![b'B'; 50]);
    
    println!("Original input size: {} bytes", original.len());
    
    let mut minimizer = minimizer::InputMinimizer::new(original);
    
    // Minimize (crash triggers on 'X')
    let minimized = minimizer.minimize(|input| {
        input.contains(&b'X')
    });
    
    println!("Minimized input size: {} bytes", minimized.len());
    println!("Reduction: {:.1}%", minimizer.reduction_percent());
}

/// Example 7: Coverage-guided input generation
unsafe fn example_coverage_guided() {
    println!("\n=== Example 7: Coverage-Guided Generation ===\n");
    
    let mut generator = CoverageGuidedGenerator::new();
    
    // Set target addresses
    generator.add_target(0x400000);
    generator.add_target(0x400100);
    generator.add_target(0x400200);
    generator.add_target(0x400300);
    
    let seed = vec![0x41, 0x42, 0x43];
    
    // Generate inputs (simulated execution)
    let inputs = generator.generate(seed, 20, |_input| {
        // Simulate coverage (would run actual execution)
        let mut cov = std::collections::HashSet::new();
        cov.insert(0x400000);
        cov.insert(0x400100);
        cov
    });
    
    println!("Generated {} inputs", inputs.len());
    println!("Coverage: {:.1}%", generator.coverage_percent());
}

/// Example 8: Taint analysis
unsafe fn example_taint_analysis() {
    println!("\n=== Example 8: Taint Analysis ===\n");
    
    let mut tracker = TaintTracker::new();
    
    // Mark user input as tainted
    tracker.taint_value(1, TaintSource::UserInput, 0, 4);
    println!("Tainted value 1 from user input");
    
    // Propagate through operations
    tracker.propagate(2, 1); // value2 = value1
    tracker.propagate_binop(3, 2, 5); // value3 = value2 + value5
    
    println!("Propagated to values 2 and 3");
    
    // Check sinks
    tracker.check_sink(3, TaintSink::CommandExec, 0x400500);
    println!("Checked command execution sink");
    
    let flows = tracker.get_flows();
    println!("\nDetected {} taint flows:", flows.len());
    
    for flow in flows {
        println!("  Flow to {:?} at 0x{:x}", flow.sink, flow.pc);
        println!("    Sources: {} labels", flow.sources.len());
    }
}

/// Example 9: Taint policies
unsafe fn example_taint_policies() {
    println!("\n=== Example 9: Taint Policies ===\n");
    
    // Command injection policy
    let cmd_policy = policy::TaintPolicy::command_injection();
    println!("Policy: {}", cmd_policy.name);
    println!("  Sources: {}", cmd_policy.sources.len());
    println!("  Sinks: {}", cmd_policy.sinks.len());
    
    // Path traversal policy
    let path_policy = policy::TaintPolicy::path_traversal();
    println!("\nPolicy: {}", path_policy.name);
    
    // Code injection policy
    let code_policy = policy::TaintPolicy::code_injection();
    println!("\nPolicy: {}", code_policy.name);
}

/// Example 10: Complete analysis workflow
unsafe fn example_complete_workflow() {
    println!("\n=== Example 10: Complete Analysis Workflow ===\n");
    
    println!("Step 1: Scan for vulnerabilities");
    let mut scanner = VulnerabilityScanner::new();
    scanner.register(Box::new(buffer_overflow::BufferOverflowDetector::new()));
    
    let ctx = DetectionContext::new(0x400500);
    scanner.scan(&ctx);
    
    let exploitable = scanner.get_exploitable();
    println!("  Found {} exploitable vulnerabilities\n", exploitable.len());
    
    if let Some(vuln) = exploitable.first() {
        println!("Step 2: Generate exploit");
        let aeg = AutomaticExploitGenerator::new();
        
        if let Ok(exploit) = aeg.generate(vuln) {
            println!("  ✓ Generated exploit ({}bytes)\n", exploit.payload.len());
            
            println!("Step 3: Verify exploit");
            if aeg.verify(&exploit).unwrap_or(false) {
                println!("  ✓ Exploit verified\n");
            }
        }
    }
    
    println!("Step 4: Track taint flows");
    let mut tracker = TaintTracker::new();
    tracker.taint_value(1, TaintSource::UserInput, 0, 100);
    tracker.check_sink(1, TaintSink::CommandExec, 0x400500);
    println!("  Detected {} flows\n", tracker.get_flows().len());
    
    println!("Analysis complete! ✓");
}

fn main() {
    unsafe {
        example_vulnerability_detection();
        example_exploit_generation();
        example_manual_exploit();
        example_crash_analysis();
        example_crash_triage();
        example_input_minimization();
        example_coverage_guided();
        example_taint_analysis();
        example_taint_policies();
        example_complete_workflow();
        
        println!("\n=== All Phase 4 Examples Complete ===");
        println!("Successfully demonstrated:");
        println!("  ✓ Vulnerability detection");
        println!("  ✓ Automatic exploit generation");
        println!("  ✓ Crash analysis and triage");
        println!("  ✓ Input generation and minimization");
        println!("  ✓ Taint analysis");
        println!("\nPhase 4 analysis techniques are fully operational!");
    }
}
