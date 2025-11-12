# SimProcedure Framework

Function summaries (SimProcedures) for symbolic execution of library functions.

## Overview

When performing symbolic execution on binaries, actually executing library functions like `malloc`, `strlen`, or `printf` can be expensive or impractical. Instead, we replace these functions with **summaries** that model their behavior symbolically.

This module provides:
- **SimProcedure trait**: Interface for function summaries
- **ProcedureHook**: Manager for hooking functions at addresses or by symbol
- **Standard library procedures**: Pre-built summaries for common libc functions
- **ArgumentExtractor**: Platform-specific argument extraction (x86_64 System V ABI)

## Quick Start

```rust
use angr_core::procedures::{ProcedureHook, ProcedureResult};
use angr_core::symbolic::{SimState, Value};

unsafe {
    // Create hook manager
    let mut hooks = ProcedureHook::new();
    
    // Register all standard library procedures
    hooks.register_stdlib();
    
    // Check if address is hooked
    if hooks.is_hooked(0x400800) {
        // Execute the hooked procedure
        let args = vec![Value::concrete(64, 100)];
        let mut state = SimState::new(0x400000, 256);
        
        let result = hooks.execute(0x400800, &mut state, &args);
        match result {
            ProcedureResult::Return { value } => {
                println!("Returned: {:?}", value);
            }
            _ => {}
        }
    }
}
```

## Architecture

### SimProcedure Trait

All procedure summaries implement this trait:

```rust
pub trait SimProcedure: Send + Sync {
    fn name(&self) -> &str;
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) -> ProcedureResult;
    fn num_args(&self) -> usize;
    fn returns_value(&self) -> bool { true }
}
```

### ProcedureResult

Procedures can return different results:

```rust
pub enum ProcedureResult {
    Return { value: Option<Value> },  // Normal return
    Jump { target: u64 },              // Jump to address
    Continue,                          // Continue execution
    Error { message: String },         // Error occurred
}
```

## Implemented Procedures

### Memory Management (`memory.rs`)

| Function | Description | Arguments | Returns |
|----------|-------------|-----------|---------|
| `Malloc` | Allocate heap memory | size | pointer |
| `Free` | Free heap memory | ptr | - |
| `Calloc` | Allocate zeroed memory | nmemb, size | pointer |
| `Realloc` | Reallocate memory | ptr, size | pointer |

**Heap allocator**: Starts at `0x10000000`, thread-safe atomic counter.

### String Operations (`string.rs`)

| Function | Description | Arguments | Returns |
|----------|-------------|-----------|---------|
| `Strlen` | Get string length | str | length |
| `Strcmp` | Compare strings | s1, s2 | -1/0/1 |
| `Strcpy` | Copy string | dst, src | dst |
| `Strncpy` | Copy string (bounded) | dst, src, n | dst |
| `Memcpy` | Copy memory | dst, src, n | dst |
| `Memset` | Fill memory | ptr, val, n | ptr |

### LibC I/O (`libc.rs`)

| Function | Description | Arguments | Returns |
|----------|-------------|-----------|---------|
| `Printf` | Print formatted (stub) | fmt, ... | chars printed |
| `Puts` | Print string (stub) | str | chars printed |
| `Putchar` | Print char (stub) | c | c |
| `Getchar` | Read char (stub) | - | symbolic |
| `Fopen` | Open file (stub) | path, mode | FILE* |
| `Fclose` | Close file (stub) | file | 0 |
| `Fread` | Read file (stub) | buf, sz, n, file | items read |
| `Fwrite` | Write file (stub) | buf, sz, n, file | items written |

**Note**: I/O procedures are stubs that don't perform actual I/O but maintain analysis soundness.

## Hooking Mechanisms

### By Address

```rust
unsafe {
    let mut hooks = ProcedureHook::new();
    hooks.hook_at(0x400800, Box::new(memory::Malloc));
}
```

### By Symbol Name

```rust
unsafe {
    let mut hooks = ProcedureHook::new();
    hooks.hook_symbol("malloc".to_string(), Box::new(memory::Malloc));
}
```

### Standard Library

```rust
unsafe {
    let mut hooks = ProcedureHook::new();
    hooks.register_stdlib();  // Registers all stdlib procedures
}
```

## Symbolic Handling

### Concrete Arguments

When arguments are concrete (known values):
```rust
// malloc(100) - concrete size
let ptr_addr = 0x10000000;  // Allocate from heap
```

### Symbolic Arguments

When arguments are symbolic (unknown):
```rust
// malloc(sym_size) - symbolic size
// Allocate fixed size (0x1000) as conservative estimate
// Return symbolic pointer
```

### Symbolic Results

Some procedures return symbolic values:
```rust
// getchar() - always returns symbolic value
let sym_char = state.new_symbol(32);
```

## Custom Procedures

Create custom procedure summaries:

```rust
use angr_core::procedures::{SimProcedure, ProcedureResult};
use angr_core::symbolic::{SimState, Value};

struct MyCustomProc;

impl SimProcedure for MyCustomProc {
    fn name(&self) -> &str {
        "my_custom_proc"
    }
    
    unsafe fn execute(&self, state: &mut SimState, args: &[Value]) 
        -> ProcedureResult 
    {
        // Your implementation here
        ProcedureResult::Return {
            value: Some(Value::concrete(64, 42))
        }
    }
    
    fn num_args(&self) -> usize {
        unsafe { 2 }
    }
}
```

Then register it:

```rust
unsafe {
    let mut hooks = ProcedureHook::new();
    hooks.hook_symbol("my_func".to_string(), Box::new(MyCustomProc));
}
```

## Calling Conventions

### x86_64 System V ABI

Arguments are extracted from registers:
1. RDI (offset 80)
2. RSI (offset 72)
3. RDX (offset 64)
4. RCX (offset 56)
5. R8 (offset 48)
6. R9 (offset 40)

Additional arguments on stack (not yet implemented).

```rust
unsafe {
    let extractor = ArgumentExtractor::x86_64_sysv();
    let args = extractor.extract(&state, 3);  // Extract 3 args
}
```

## Performance Considerations

### Why Use SimProcedures?

1. **Speed**: Avoid executing complex library code
2. **Soundness**: Maintain symbolic analysis without concrete execution
3. **Path explosion**: Reduce branching in library functions
4. **Symbolic I/O**: Handle I/O symbolically without actual operations

### Memory Overhead

- Heap allocator uses atomic counter (8 bytes)
- Each hooked function adds HashMap entry
- Procedure objects are boxed (pointer + vtable)

## Testing

All procedures include comprehensive tests:

```rust
#[test]
fn test_malloc_concrete() {
    unsafe {
        let malloc = Malloc;
        let mut state = SimState::new(0x1000, 256);
        let args = vec![Value::concrete(64, 100)];
        let result = malloc.execute(&mut state, &args);
        // Assert result...
    }
}
```

Run tests:
```bash
cargo test --package angr-core procedures
```

## Future Enhancements

Planned improvements:
- [ ] More standard library functions (atoi, sprintf, etc.)
- [ ] Multiple calling conventions (Windows x64, ARM, etc.)
- [ ] Stack argument extraction
- [ ] Variadic function support
- [ ] Concolic execution integration
- [ ] User-space system calls (read, write, open, etc.)

## Integration with Symbolic Execution

SimProcedures integrate seamlessly with the symbolic stepper:

```rust
unsafe {
    let mut state = SimState::new(0x400000, 256);
    let mut hooks = ProcedureHook::new();
    hooks.register_stdlib();
    
    // During stepping
    if hooks.is_hooked(state.pc) {
        // Extract arguments using calling convention
        let extractor = ArgumentExtractor::x86_64_sysv();
        let proc = hooks.get_by_address(state.pc).unwrap();
        let args = extractor.extract(&state, proc.num_args());
        
        // Execute procedure
        let result = hooks.execute(state.pc, &mut state, &args);
        
        // Handle result
        match result {
            ProcedureResult::Return { value } => {
                if let Some(ret_val) = value {
                    state.write_register(0, ret_val); // RAX
                }
                state.pc += 1; // Continue after call
            }
            _ => {}
        }
    }
}
```

## See Also

- [PHASE3_COMPLETE.md](../PHASE3_COMPLETE.md) - Full Phase 3 documentation
- [examples/phase3_integration.rs](../examples/phase3_integration.rs) - Integration examples
- `angr-core/src/engine/stepper.rs` - Symbolic stepper integration
- `angr-core/src/symbolic/state.rs` - SimState implementation
