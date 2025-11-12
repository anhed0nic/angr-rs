//! Phase 5 API Examples
//!
//! Comprehensive examples demonstrating the angr-rs high-level API,
//! including project loading, analysis, exploration, vulnerability detection,
//! and exploit generation.

use angr_api::prelude::*;

/// Example 1: Basic project usage
unsafe fn example_basic_project() {
    println!("=== Example 1: Basic Project Usage ===\n");
    
    // Load a binary (in real usage, replace with actual binary path)
    // let project = Project::new("./test_binary").unwrap();
    
    // For demonstration, we'll show the API
    println!("Loading project:");
    println!("  let project = Project::new(\"./binary\")?;");
    println!("  println!(\"Entry: {{:#x}}\", project.entry_point());");
    println!("  println!(\"Arch:  {{:?}}\", project.architecture());\n");
}

/// Example 2: Using the state factory
unsafe fn example_state_factory() {
    println!("=== Example 2: State Factory ===\n");
    
    println!("Creating different types of states:");
    println!("  // Entry state");
    println!("  let entry = project.factory.entry_state();");
    println!();
    println!("  // Blank state at arbitrary address");
    println!("  let blank = project.factory.blank_state(0x400000);");
    println!();
    println!("  // Call state with arguments");
    println!("  let call = project.factory.call_state(0x400500, vec![1, 2, 3]);");
    println!();
    println!("  // Fully initialized state");
    println!("  let full = project.factory.full_init_state();\n");
}

/// Example 3: Symbolic exploration
unsafe fn example_exploration() {
    println!("=== Example 3: Symbolic Exploration ===\n");
    
    println!("Simple exploration to target:");
    println!("  let found = project.explore_to(0x400800)?;");
    println!("  for state in found {{");
    println!("    println!(\"Found path at {{:#x}}\", state.pc());");
    println!("  }}\n");
    
    println!("Exploration with find and avoid:");
    println!("  let found = project.explore(");
    println!("    |state| state.pc() == 0x400800,  // find");
    println!("    |state| state.pc() == 0x400900,  // avoid");
    println!("  )?;\n");
    
    println!("Manual simulation manager:");
    println!("  let entry = project.factory.entry_state();");
    println!("  let mut simgr = project.simulation_manager(entry);");
    println!("  ");
    println!("  simgr.explore(");
    println!("    |s| s.pc() == target,");
    println!("    |s| avoid_addrs.contains(&s.pc()),");
    println!("  )?;");
    println!("  ");
    println!("  if !simgr.found().is_empty() {{");
    println!("    println!(\"Success!\");");
    println!("  }}\n");
}

/// Example 4: CFG analysis
unsafe fn example_cfg_analysis() {
    println!("=== Example 4: CFG Analysis ===\n");
    
    println!("Fast CFG recovery:");
    println!("  let cfg = project.analyses().cfg_fast()?;");
    println!("  println!(\"Blocks:    {{}}\", cfg.blocks.len());");
    println!("  println!(\"Functions: {{}}\", cfg.functions.len());\n");
    
    println!("Emulated CFG (more precise):");
    println!("  let cfg = project.analyses().cfg_emulated()?;\n");
    
    println!("Function enumeration:");
    println!("  let functions = project.functions();");
    println!("  for addr in functions {{");
    println!("    let name = project.function_name(addr)");
    println!("      .unwrap_or_else(|| format!(\"sub_{{:x}}\", addr));");
    println!("    println!(\"{{:#x}}: {{}}\", addr, name);");
    println!("  }}\n");
}

/// Example 5: Vulnerability detection
unsafe fn example_vulnerability_detection() {
    println!("=== Example 5: Vulnerability Detection ===\n");
    
    println!("Quick vulnerability scan:");
    println!("  let vulns = project.find_vulnerabilities()?;");
    println!("  println!(\"Found {{}} vulnerabilities\", vulns.len());\n");
    
    println!("Detailed vulnerability analysis:");
    println!("  let analyses = project.analyses();");
    println!("  let all_vulns = analyses.vulnerability_scan()?;");
    println!("  let exploitable = analyses.exploitable_vulnerabilities()?;");
    println!("  ");
    println!("  for vuln in exploitable {{");
    println!("    println!(\"{{:?}} at {{:#x}}\", vuln.vuln_type, vuln.address);");
    println!("    println!(\"  Severity: {{:?}}\", vuln.severity);");
    println!("    println!(\"  Exploitability: {{:?}}\", vuln.exploitability);");
    println!("  }}\n");
}

/// Example 6: Exploit generation
unsafe fn example_exploit_generation() {
    println!("=== Example 6: Exploit Generation ===\n");
    
    println!("Generate all exploits:");
    println!("  let exploits = project.generate_exploits()?;");
    println!("  for exploit in exploits {{");
    println!("    println!(\"Type: {{:?}}\", exploit.exploit_type);");
    println!("    println!(\"Payload: {{}} bytes\", exploit.payload.len());");
    println!("  }}\n");
    
    println!("Generate exploit for specific vulnerability:");
    println!("  let vulns = project.find_vulnerabilities()?;");
    println!("  if let Some(vuln) = vulns.first() {{");
    println!("    let exploit = project.analyses().generate_exploit(vuln)?;");
    println!("    ");
    println!("    // Generate Python script");
    println!("    let script = exploit.to_python();");
    println!("    std::fs::write(\"exploit.py\", script)?;");
    println!("  }}\n");
}

/// Example 7: Taint analysis
unsafe fn example_taint_analysis() {
    println!("=== Example 7: Taint Analysis ===\n");
    
    println!("Detect command injection:");
    println!("  let flows = project.analyses().detect_command_injection()?;");
    println!("  for flow in flows {{");
    println!("    println!(\"Taint flow to {{:?}} at {{:#x}}\", flow.sink, flow.pc);");
    println!("  }}\n");
    
    println!("Detect path traversal:");
    println!("  let flows = project.analyses().detect_path_traversal()?;\n");
    
    println!("Manual taint tracking:");
    println!("  let taint = project.analyses().taint_analysis();");
    println!("  ");
    println!("  // Taint user input");
    println!("  taint.taint_value(1, TaintSource::UserInput, 0, 100);");
    println!("  ");
    println!("  // Check dangerous sinks");
    println!("  taint.check_sink(1, TaintSink::CommandExec, 0x400500);");
    println!("  ");
    println!("  // Get detected flows");
    println!("  let flows = taint.flows();\n");
}

/// Example 8: Comprehensive analysis
unsafe fn example_comprehensive_analysis() {
    println!("=== Example 8: Comprehensive Analysis ===\n");
    
    println!("Run all analyses at once:");
    println!("  let analysis = project.analyze_all()?;");
    println!("  ");
    println!("  println!(\"CFG Complete: {{}}\", analysis.cfg_complete);");
    println!("  println!(\"Vulnerabilities: {{}}\", analysis.vulnerabilities_found);");
    println!("  println!(\"Exploitable: {{}}\", analysis.exploitable_count);");
    println!("  println!(\"Severity: {{}}\", analysis.severity());");
    println!("  ");
    println!("  if analysis.has_security_issues() {{");
    println!("    println!(\"⚠ Security issues detected!\");");
    println!("  }}\n");
}

/// Example 9: Symbol and segment access
unsafe fn example_symbols_segments() {
    println!("=== Example 9: Symbols & Segments ===\n");
    
    println!("Access symbols:");
    println!("  let symbols = project.symbols();");
    println!("  for sym in symbols {{");
    println!("    if let Some(addr) = project.symbol_address(&sym) {{");
    println!("      println!(\"{{:#x}}: {{}}\", addr, sym);");
    println!("    }}");
    println!("  }}\n");
    
    println!("Check segment permissions:");
    println!("  if let Some(seg) = project.segment_at(0x400000) {{");
    println!("    println!(\"Segment: {{}}\", seg.name);");
    println!("    println!(\"Permissions: {{}}\", seg.perms_string());");
    println!("    println!(\"Executable: {{}}\", project.is_executable(0x400000));");
    println!("  }}\n");
}

/// Example 10: Complete workflow
unsafe fn example_complete_workflow() {
    println!("=== Example 10: Complete Workflow ===\n");
    
    println!("Full analysis and exploitation workflow:");
    println!("  // 1. Load binary");
    println!("  let project = Project::new(\"./vulnerable_binary\")?;");
    println!("  ");
    println!("  // 2. Run comprehensive scan");
    println!("  let analysis = project.analyze_all()?;");
    println!("  println!(\"Severity: {{}}\", analysis.severity());");
    println!("  ");
    println!("  // 3. Find exploitable vulnerabilities");
    println!("  let vulns = project.find_vulnerabilities()?;");
    println!("  println!(\"Found {{}} exploitable bugs\", vulns.len());");
    println!("  ");
    println!("  // 4. Generate exploits");
    println!("  let exploits = project.generate_exploits()?;");
    println!("  ");
    println!("  // 5. Save exploit scripts");
    println!("  for (i, exploit) in exploits.iter().enumerate() {{");
    println!("    let script = exploit.to_python();");
    println!("    std::fs::write(format!(\"exploit_{{}}.py\", i), script)?;");
    println!("  }}");
    println!("  ");
    println!("  // 6. Verify with symbolic execution");
    println!("  if let Some(vuln) = vulns.first() {{");
    println!("    let found = project.explore_to(vuln.address)?;");
    println!("    if !found.is_empty() {{");
    println!("      println!(\"✓ Vulnerability confirmed!\");");
    println!("    }}");
    println!("  }}");
    println!("  ");
    println!("  println!(\"Analysis complete!\");\n");
}

/// Example 11: Knowledge base usage
unsafe fn example_knowledge_base() {
    println!("=== Example 11: Knowledge Base ===\n");
    
    println!("Store and retrieve function information:");
    println!("  let kb = project.knowledge_base();");
    println!("  ");
    println!("  // Get function info");
    println!("  if let Some(func) = kb.function(0x400000) {{");
    println!("    println!(\"Name: {{:?}}\", func.name);");
    println!("    println!(\"Size: {{}} bytes\", func.size);");
    println!("  }}");
    println!("  ");
    println!("  // Enumerate all functions");
    println!("  for addr in kb.functions() {{");
    println!("    println!(\"Function at {{:#x}}\", addr);");
    println!("  }}\n");
}

/// Example 12: Custom project options
unsafe fn example_project_options() {
    println!("=== Example 12: Custom Project Options ===\n");
    
    println!("Load with custom options:");
    println!("  let opts = ProjectOptions::new()");
    println!("    .with_entry(0x401000)");
    println!("    .with_arch(Architecture::AMD64);");
    println!("  ");
    println!("  let project = Project::with_options(\"./binary\", opts)?;\n");
}

fn main() {
    unsafe {
        println!("\n{}\n", "=".repeat(70));
        println!("       ANGR-RS API EXAMPLES - Phase 5");
        println!("{}\n", "=".repeat(70));
        
        example_basic_project();
        example_state_factory();
        example_exploration();
        example_cfg_analysis();
        example_vulnerability_detection();
        example_exploit_generation();
        example_taint_analysis();
        example_comprehensive_analysis();
        example_symbols_segments();
        example_complete_workflow();
        example_knowledge_base();
        example_project_options();
        
        println!("{}", "=".repeat(70));
        println!("All examples demonstrated!");
        println!("{}\n", "=".repeat(70));
        
        println!("\nTo use these APIs in your code:");
        println!("  use angr_api::prelude::*;");
        println!("\nFor more information, see the documentation:");
        println!("  cargo doc --open\n");
    }
}
