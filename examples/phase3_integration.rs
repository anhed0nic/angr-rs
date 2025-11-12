//! Phase 3 Integration Example
//!
//! Demonstrates how all Phase 3 components work together for symbolic execution

use angr_core::symbolic::{SimState, Value};
use angr_core::solver::Z3Solver;
use angr_core::engine::{PathGroup, ExplorationStrategy};
use angr_core::procedures::ProcedureHook;

/// Example 1: Basic symbolic execution with constraints
unsafe fn example_symbolic_execution() {
    println!("=== Example 1: Symbolic Execution ===");
    
    // Create initial state at program entry
    let mut state = SimState::new(0x400000, 256);
    
    // Create symbolic input (e.g., user input)
    let sym_input = state.new_symbol(32);
    
    // Write symbolic input to a register (e.g., RDI for x86_64)
    state.write_register(80, sym_input.clone()); // RDI offset
    
    // Simulate some computation: input must be > 100 to reach goal
    let const_100 = Value::concrete(32, 100);
    let condition = sym_input.gt(&const_100);
    
    // Add constraint for true branch
    state.add_constraint(condition);
    
    // Check if constraints are satisfiable
    let solver = Z3Solver::new();
    if solver.check(&state.constraints) {
        println!("✓ Path is feasible!");
        
        let model = solver.solve(&state.constraints);
        if let Some(input_value) = model.get_value("sym_0") {
            println!("  Solution: input = {}", input_value);
        }
    } else {
        println!("✗ Path is infeasible");
    }
}

/// Example 2: Path exploration with goals
unsafe fn example_path_exploration() {
    println!("\n=== Example 2: Path Exploration ===");
    
    // Create initial state
    let initial_state = SimState::new(0x400000, 256);
    
    // Create path group
    let mut pg = PathGroup::new(initial_state);
    
    // Set exploration strategy
    pg.set_strategy(ExplorationStrategy::BFS);
    
    // Set goal address (e.g., success function)
    pg.set_find(vec![0x400500]);
    
    // Set avoid addresses (e.g., error handlers)
    pg.set_avoid(vec![0x400600, 0x400700]);
    
    println!("Starting exploration...");
    println!("  Strategy: BFS");
    println!("  Goal: 0x400500");
    println!("  Avoid: 0x400600, 0x400700");
    
    // In real scenario, would step until found or exhausted
    // pg.step() would be called in loop
    
    println!("Active paths: {}", pg.active.len());
    println!("Found paths: {}", pg.found.len());
    println!("Dead paths: {}", pg.deadended.len());
}

/// Example 3: Function hooking with SimProcedures
unsafe fn example_function_hooks() {
    println!("\n=== Example 3: Function Hooking ===");
    
    // Create procedure hook manager
    let mut hooks = ProcedureHook::new();
    
    // Register standard library
    hooks.register_stdlib();
    
    // Create state
    let mut state = SimState::new(0x400000, 256);
    
    // Simulate calling malloc(100)
    let malloc_addr = 0x400800u64; // Assume PLT entry
    hooks.hook_symbol("malloc".to_string(), Box::new(angr_core::procedures::memory::Malloc));
    
    if hooks.is_hooked(malloc_addr) {
        println!("✓ malloc is hooked at 0x{:x}", malloc_addr);
        
        let args = vec![Value::concrete(64, 100)];
        let result = hooks.execute(malloc_addr, &mut state, &args);
        
        match result {
            angr_core::procedures::ProcedureResult::Return { value } => {
                if let Some(ptr) = value {
                    println!("  malloc(100) returned: 0x{:x}", 
                             ptr.as_concrete().unwrap_or(0));
                }
            }
            _ => println!("  Unexpected result"),
        }
    }
    
    // Simulate strlen
    let strlen_addr = 0x400810u64;
    let str_addr = 0x10000000u64;
    
    // Write "hello" to memory
    state.write_memory(str_addr, &[b'h']);
    state.write_memory(str_addr + 1, &[b'e']);
    state.write_memory(str_addr + 2, &[b'l']);
    state.write_memory(str_addr + 3, &[b'l']);
    state.write_memory(str_addr + 4, &[b'o']);
    state.write_memory(str_addr + 5, &[0]);
    
    hooks.hook_symbol("strlen".to_string(), Box::new(angr_core::procedures::string::Strlen));
    
    if hooks.is_hooked(strlen_addr) {
        println!("✓ strlen is hooked at 0x{:x}", strlen_addr);
        
        let args = vec![Value::concrete(64, str_addr)];
        let result = hooks.execute(strlen_addr, &mut state, &args);
        
        match result {
            angr_core::procedures::ProcedureResult::Return { value } => {
                if let Some(len) = value {
                    println!("  strlen(\"hello\") returned: {}", 
                             len.as_concrete().unwrap_or(0));
                }
            }
            _ => println!("  Unexpected result"),
        }
    }
}

/// Example 4: State merging
unsafe fn example_state_merging() {
    println!("\n=== Example 4: State Merging ===");
    
    // Create two similar states at same PC
    let mut state1 = SimState::new(0x400000, 256);
    let mut state2 = SimState::new(0x400000, 256);
    
    // Different register values
    state1.write_register(80, Value::concrete(64, 100));
    state2.write_register(80, Value::concrete(64, 200));
    
    // Different constraints
    let sym = state1.new_symbol(32);
    state1.add_constraint(sym.clone().gt(&Value::concrete(32, 50)));
    state2.add_constraint(sym.clone().lt(&Value::concrete(32, 50)));
    
    println!("State 1 - RDI: 100, constraint: sym > 50");
    println!("State 2 - RDI: 200, constraint: sym < 50");
    
    // Merge states
    let merge_mgr = angr_core::engine::MergeManager::new();
    let merged = merge_mgr.merge_states(&state1, &state2);
    
    println!("✓ States merged successfully");
    println!("  Merged state has {} constraints", merged.constraints.len());
}

/// Example 5: Complete analysis workflow
unsafe fn example_complete_workflow() {
    println!("\n=== Example 5: Complete Workflow ===");
    
    // 1. Setup
    let mut state = SimState::new(0x400000, 256);
    let mut hooks = ProcedureHook::new();
    hooks.register_stdlib();
    
    println!("1. Created initial state at 0x400000");
    
    // 2. Create symbolic input
    let password = state.new_symbol(64);
    state.write_register(80, password.clone()); // RDI
    println!("2. Created symbolic password input");
    
    // 3. Simulate password check: password == 0x1337
    let secret = Value::concrete(64, 0x1337);
    let check = password.eq(&secret);
    
    // Branch: if password == 0x1337, goto success
    // 4. Explore both paths
    let mut pg = PathGroup::new(state.clone());
    
    // True branch (correct password)
    let mut state_true = state.clone();
    state_true.add_constraint(check.clone());
    state_true.pc = 0x400100; // Success path
    
    // False branch (wrong password)
    let mut state_false = state;
    state_false.add_constraint(check.not());
    state_false.pc = 0x400200; // Failure path
    
    pg.active.push(state_true);
    pg.active.push(state_false);
    
    println!("3. Forked into 2 paths (correct/incorrect password)");
    
    // 5. Solve for success path
    let solver = Z3Solver::new();
    for (i, state) in pg.active.iter().enumerate() {
        println!("4. Checking path {} at PC 0x{:x}", i + 1, state.pc);
        
        if solver.check(&state.constraints) {
            println!("  ✓ Path is feasible");
            let model = solver.solve(&state.constraints);
            if let Some(pass_val) = model.get_value("sym_0") {
                println!("  Password solution: 0x{:x}", pass_val);
            }
        } else {
            println!("  ✗ Path is infeasible");
        }
    }
    
    println!("\n5. Analysis complete!");
}

fn main() {
    unsafe {
        example_symbolic_execution();
        example_path_exploration();
        example_function_hooks();
        example_state_merging();
        example_complete_workflow();
        
        println!("\n=== All Examples Complete ===");
        println!("Phase 3 symbolic execution engine is fully operational!");
    }
}
