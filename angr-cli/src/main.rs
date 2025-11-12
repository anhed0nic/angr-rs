//! Angr CLI - Command-Line Tools
//!
//! Comprehensive command-line interface for angr-rs binary analysis.
//! Provides subcommands for analysis, exploration, vulnerability detection,
//! and exploit generation.

use anyhow::{Result, Context};
use clap::{Parser, Subcommand, Args};
use angr_api::prelude::*;
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "angr")]
#[command(author, version, about = "Rust-based binary analysis framework")]
#[command(long_about = "
angr-rs - A powerful binary analysis framework in Rust

EXAMPLES:
    # Get binary information
    angr info binary.exe

    # Analyze binary for vulnerabilities
    angr analyze binary.exe --vulnerabilities

    # Explore to a target address
    angr explore binary.exe --find 0x400800

    # Generate exploits
    angr exploit binary.exe --generate

    # Run complete security analysis
    angr scan binary.exe
")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
    
    /// Output format (text, json)
    #[arg(short, long, global = true, default_value = "text")]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Show binary information
    Info(InfoArgs),
    
    /// Analyze binary with various techniques
    Analyze(AnalyzeArgs),
    
    /// Explore program paths symbolically
    Explore(ExploreArgs),
    
    /// Scan for vulnerabilities and generate exploits
    Exploit(ExploitArgs),
    
    /// Run comprehensive security scan
    Scan(ScanArgs),
    
    /// Disassemble binary functions
    Disasm(DisasmArgs),
    
    /// Run taint analysis
    Taint(TaintArgs),
    
    /// Show version information
    Version,
}

#[derive(Args)]
struct InfoArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    file: PathBuf,
    
    /// Show architecture info
    #[arg(long)]
    arch: bool,
    
    /// Show entry point
    #[arg(long)]
    entry: bool,
    
    /// Show segments
    #[arg(long)]
    segments: bool,
    
    /// Show symbols
    #[arg(long)]
    symbols: bool,
    
    /// Show all info (default)
    #[arg(long)]
    all: bool,
}

#[derive(Args)]
struct AnalyzeArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    file: PathBuf,
    
    /// Generate control flow graph
    #[arg(long)]
    cfg: bool,
    
    /// List functions
    #[arg(long)]
    functions: bool,
    
    /// Scan for vulnerabilities
    #[arg(long)]
    vulnerabilities: bool,
    
    /// Run all analyses
    #[arg(long)]
    all: bool,
}

#[derive(Args)]
struct ExploreArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    file: PathBuf,
    
    /// Target address to find (hex)
    #[arg(long, value_parser = parse_hex)]
    find: Option<u64>,
    
    /// Address to avoid (hex)
    #[arg(long, value_parser = parse_hex)]
    avoid: Option<u64>,
    
    /// Maximum steps
    #[arg(long, default_value = "10000")]
    max_steps: usize,
    
    /// Start from custom address (hex)
    #[arg(long, value_parser = parse_hex)]
    start: Option<u64>,
}

#[derive(Args)]
struct ExploitArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    file: PathBuf,
    
    /// Scan for vulnerabilities
    #[arg(long)]
    scan: bool,
    
    /// Generate exploits
    #[arg(long)]
    generate: bool,
    
    /// Generate Python exploit scripts
    #[arg(long)]
    python: bool,
    
    /// Output directory for exploits
    #[arg(short, long, default_value = ".")]
    output: PathBuf,
}

#[derive(Args)]
struct ScanArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    file: PathBuf,
    
    /// Show detailed vulnerability info
    #[arg(long)]
    detailed: bool,
}

#[derive(Args)]
struct DisasmArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    file: PathBuf,
    
    /// Function name or address (hex)
    #[arg(short, long)]
    function: Option<String>,
    
    /// Address to disassemble (hex)
    #[arg(short, long, value_parser = parse_hex)]
    address: Option<u64>,
    
    /// Number of instructions
    #[arg(short, long, default_value = "20")]
    count: usize,
}

#[derive(Args)]
struct TaintArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    file: PathBuf,
    
    /// Check for command injection
    #[arg(long)]
    command_injection: bool,
    
    /// Check for path traversal
    #[arg(long)]
    path_traversal: bool,
    
    /// Check for code injection
    #[arg(long)]
    code_injection: bool,
    
    /// Check all taint vulnerabilities
    #[arg(long)]
    all: bool,
}

fn main() -> Result<()> {
    unsafe {
        let cli = Cli::parse();
        
        // Initialize logging
        if cli.verbose {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .init();
        } else {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .init();
        }

        match cli.command {
            Commands::Info(args) => cmd_info(args)?,
            Commands::Analyze(args) => cmd_analyze(args)?,
            Commands::Explore(args) => cmd_explore(args)?,
            Commands::Exploit(args) => cmd_exploit(args)?,
            Commands::Scan(args) => cmd_scan(args)?,
            Commands::Disasm(args) => cmd_disasm(args)?,
            Commands::Taint(args) => cmd_taint(args)?,
            Commands::Version => cmd_version()?,
        }

        Ok(())
    }
}

/// Show binary information
fn cmd_info(args: InfoArgs) -> Result<()> {
    unsafe {
        println!("{}", "Binary Information".bold().cyan());
        println!("{}", "=".repeat(60));
        
        let project = Project::new(&args.file)
            .context("Failed to load binary")?;
        
        let show_all = args.all || (!args.arch && !args.entry && !args.segments && !args.symbols);
        
        // Basic info (always show)
        println!("File:         {}", args.file.display());
        println!("Format:       {:?}", project.binary.format);
        
        if show_all || args.arch {
            println!("Architecture: {:?}", project.architecture());
        }
        
        if show_all || args.entry {
            println!("Entry Point:  {:#x}", project.entry_point());
        }
        
        // Segments
        if show_all || args.segments {
            println!("\n{}", "Segments:".bold());
            for segment in &project.binary.segments {
                println!("  {:#010x} - {:#010x}  {}  {}",
                    segment.vaddr,
                    segment.vaddr + segment.size,
                    segment.perms_string(),
                    segment.name
                );
            }
        }
        
        // Symbols
        if show_all || args.symbols {
            let symbols = project.symbols();
            println!("\n{}", format!("Symbols: ({} total)", symbols.len()).bold());
            for (i, sym) in symbols.iter().enumerate().take(20) {
                if let Some(addr) = project.symbol_address(sym) {
                    println!("  {:#010x}  {}", addr, sym);
                }
                if i == 19 && symbols.len() > 20 {
                    println!("  ... and {} more", symbols.len() - 20);
                    break;
                }
            }
        }
        
        Ok(())
    }
}

/// Analyze binary
fn cmd_analyze(args: AnalyzeArgs) -> Result<()> {
    unsafe {
        println!("{}", "Binary Analysis".bold().cyan());
        println!("{}", "=".repeat(60));
        
        let project = Project::new(&args.file)
            .context("Failed to load binary")?;
        
        let analyses = project.analyses();
        let run_all = args.all || (!args.cfg && !args.functions && !args.vulnerabilities);
        
        // CFG Analysis
        if run_all || args.cfg {
            println!("\n{}", "Control Flow Graph:".bold().green());
            let cfg = analyses.cfg_fast()
                .context("CFG generation failed")?;
            println!("  Basic blocks: {}", cfg.blocks.len());
            println!("  Functions:    {}", cfg.functions.len());
        }
        
        // Function Analysis
        if run_all || args.functions {
            println!("\n{}", "Functions:".bold().green());
            let funcs = project.functions();
            println!("  Found {} functions", funcs.len());
            for (i, &addr) in funcs.iter().enumerate().take(10) {
                let name = project.function_name(addr)
                    .unwrap_or_else(|| format!("sub_{:x}", addr));
                println!("    {:#010x}  {}", addr, name);
                if i == 9 && funcs.len() > 10 {
                    println!("    ... and {} more", funcs.len() - 10);
                    break;
                }
            }
        }
        
        // Vulnerability Analysis
        if run_all || args.vulnerabilities {
            println!("\n{}", "Vulnerability Scan:".bold().yellow());
            match analyses.vulnerability_scan() {
                Ok(vulns) => {
                    println!("  Found {} vulnerabilities", vulns.len());
                    let exploitable = vulns.iter().filter(|v| v.is_exploitable()).count();
                    if exploitable > 0 {
                        println!("  {} are exploitable!", exploitable.to_string().red().bold());
                    }
                    
                    for vuln in vulns.iter().take(5) {
                        println!("\n  {}", format!("{:?}", vuln.vuln_type).yellow());
                        println!("    Severity:      {:?}", vuln.severity);
                        println!("    Exploitability: {:?}", vuln.exploitability);
                        println!("    Location:      {:#x}", vuln.address);
                    }
                }
                Err(e) => println!("  {}", format!("Scan failed: {}", e).red()),
            }
        }
        
        Ok(())
    }
}

/// Explore program paths
fn cmd_explore(args: ExploreArgs) -> Result<()> {
    unsafe {
        println!("{}", "Symbolic Exploration".bold().cyan());
        println!("{}", "=".repeat(60));
        
        let project = Project::new(&args.file)
            .context("Failed to load binary")?;
        
        if let Some(target) = args.find {
            println!("Exploring to find: {:#x}", target);
            
            match project.explore_to(target) {
                Ok(found) => {
                    if found.is_empty() {
                        println!("{}", "No paths found to target".yellow());
                    } else {
                        println!("{}", format!("Found {} paths!", found.len()).green().bold());
                        for (i, state) in found.iter().enumerate() {
                            println!("\nPath {}:", i + 1);
                            println!("  PC: {:#x}", state.pc());
                            // TODO: Print constraints and solution
                        }
                    }
                }
                Err(e) => println!("{}", format!("Exploration failed: {}", e).red()),
            }
        } else {
            println!("{}", "Please specify --find address".yellow());
        }
        
        Ok(())
    }
}

/// Exploit generation
fn cmd_exploit(args: ExploitArgs) -> Result<()> {
    unsafe {
        println!("{}", "Exploit Generation".bold().cyan());
        println!("{}", "=".repeat(60));
        
        let project = Project::new(&args.file)
            .context("Failed to load binary")?;
        
        if args.scan || args.generate {
            // Scan for vulnerabilities
            println!("\n{}", "Scanning for vulnerabilities...".bold());
            let vulns = project.find_vulnerabilities()
                .context("Vulnerability scan failed")?;
            
            println!("Found {} exploitable vulnerabilities", vulns.len());
            
            if args.generate && !vulns.is_empty() {
                println!("\n{}", "Generating exploits...".bold().green());
                
                match project.generate_exploits() {
                    Ok(exploits) => {
                        println!("Generated {} exploits!", exploits.len());
                        
                        for (i, exploit) in exploits.iter().enumerate() {
                            println!("\nExploit {}:", i + 1);
                            println!("  Type:    {:?}", exploit.exploit_type);
                            println!("  Target:  {:?}", exploit.target);
                            println!("  Payload: {} bytes", exploit.payload.len());
                            
                            if args.python {
                                let script_path = args.output.join(format!("exploit_{}.py", i));
                                std::fs::write(&script_path, exploit.to_python())?;
                                println!("  Script:  {}", script_path.display().to_string().green());
                            }
                        }
                    }
                    Err(e) => println!("{}", format!("Exploit generation failed: {}", e).red()),
                }
            }
        }
        
        Ok(())
    }
}

/// Comprehensive security scan
fn cmd_scan(args: ScanArgs) -> Result<()> {
    unsafe {
        println!("{}", "Security Scan".bold().cyan());
        println!("{}", "=".repeat(60));
        
        let project = Project::new(&args.file)
            .context("Failed to load binary")?;
        
        println!("Running comprehensive analysis...\n");
        
        match project.analyze_all() {
            Ok(analysis) => {
                println!("{}", "Analysis Complete!".bold().green());
                println!("\n{}", "Results:".bold());
                println!("  CFG:                  {}", if analysis.cfg_complete { "✓".green() } else { "✗".red() });
                println!("  Vulnerabilities:      {}", analysis.vulnerabilities_found);
                println!("  Exploitable:          {}", 
                    if analysis.exploitable_count > 0 {
                        format!("{} ⚠", analysis.exploitable_count).red().bold()
                    } else {
                        "0".green()
                    }
                );
                println!("  Command Injection:    {}", 
                    if analysis.command_injection_flows > 0 {
                        format!("{} ⚠", analysis.command_injection_flows).red()
                    } else {
                        "0".green()
                    }
                );
                println!("  Path Traversal:       {}", 
                    if analysis.path_traversal_flows > 0 {
                        format!("{} ⚠", analysis.path_traversal_flows).red()
                    } else {
                        "0".green()
                    }
                );
                
                println!("\n{}", format!("Overall Severity: {}", analysis.severity()).bold());
                
                if analysis.has_security_issues() {
                    println!("\n{}", "⚠ SECURITY ISSUES DETECTED ⚠".red().bold());
                } else {
                    println!("\n{}", "✓ No critical issues found".green().bold());
                }
            }
            Err(e) => println!("{}", format!("Analysis failed: {}", e).red()),
        }
        
        Ok(())
    }
}

/// Disassemble binary
fn cmd_disasm(_args: DisasmArgs) -> Result<()> {
    unsafe {
        println!("{}", "Disassembly".bold().cyan());
        println!("{}", "=".repeat(60));
        println!("Disassembly feature coming soon!");
        Ok(())
    }
}

/// Taint analysis
fn cmd_taint(args: TaintArgs) -> Result<()> {
    unsafe {
        println!("{}", "Taint Analysis".bold().cyan());
        println!("{}", "=".repeat(60));
        
        let project = Project::new(&args.file)
            .context("Failed to load binary")?;
        let analyses = project.analyses();
        
        let check_all = args.all || (!args.command_injection && !args.path_traversal && !args.code_injection);
        
        if check_all || args.command_injection {
            println!("\n{}", "Command Injection:".bold().yellow());
            match analyses.detect_command_injection() {
                Ok(flows) => {
                    if flows.is_empty() {
                        println!("  {}", "No flows detected".green());
                    } else {
                        println!("  {} suspicious flows detected", flows.len().to_string().red());
                        for flow in flows.iter().take(5) {
                            println!("    Flow to {:?} at {:#x}", flow.sink, flow.pc);
                        }
                    }
                }
                Err(e) => println!("  {}", format!("Analysis failed: {}", e).red()),
            }
        }
        
        if check_all || args.path_traversal {
            println!("\n{}", "Path Traversal:".bold().yellow());
            match analyses.detect_path_traversal() {
                Ok(flows) => {
                    if flows.is_empty() {
                        println!("  {}", "No flows detected".green());
                    } else {
                        println!("  {} suspicious flows detected", flows.len().to_string().red());
                    }
                }
                Err(e) => println!("  {}", format!("Analysis failed: {}", e).red()),
            }
        }
        
        Ok(())
    }
}

/// Show version
fn cmd_version() -> Result<()> {
    unsafe {
        println!("angr-rs version {}", env!("CARGO_PKG_VERSION"));
        println!("Rust-based binary analysis framework");
        Ok(())
    }
}

/// Parse hexadecimal address
fn parse_hex(s: &str) -> Result<u64, std::num::ParseIntError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16)
}

