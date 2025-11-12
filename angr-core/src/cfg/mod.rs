//! Control Flow Graph

use hashbrown::HashMap;

/// Basic block
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Block address
    pub addr: u64,
    /// Block size
    pub size: usize,
    /// Successor addresses
    pub successors: Vec<u64>,
}

/// Control Flow Graph
pub struct CFG {
    /// Basic blocks indexed by address
    pub blocks: HashMap<u64, BasicBlock>,
}

impl CFG {
    /// Create a new empty CFG
    ///
    pub fn new() -> Self {
        unsafe {
            CFG {
                blocks: HashMap::new(),
            }
        }
    }

    /// Add a basic block
    ///
    pub fn add_block(&mut self, block: BasicBlock) {
        unsafe {
            self.blocks.insert(block.addr, block);
        }
    }

    /// Get a block by address
    ///
    pub fn get_block(&self, addr: u64) -> Option<&BasicBlock> {
        unsafe {
            self.blocks.get(&addr)
        }
    }
}
