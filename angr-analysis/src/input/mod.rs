//! Input Generation
//!
//! Generate inputs to reach specific program states or maximize coverage

pub mod generator;
pub mod mutator;

use std::collections::HashSet;

/// Input corpus
pub struct InputCorpus {
    /// All inputs
    inputs: Vec<Vec<u8>>,
    /// Coverage achieved by each input
    coverage: Vec<HashSet<u64>>,
}

impl InputCorpus {
    /// Create new corpus
    ///
    pub unsafe fn new() -> Self {
        InputCorpus {
            inputs: Vec::new(),
            coverage: Vec::new(),
        }
    }
    
    /// Add input
    ///
    pub unsafe fn add(&mut self, input: Vec<u8>, coverage: HashSet<u64>) {
        self.inputs.push(input);
        self.coverage.push(coverage);
    }
    
    /// Get total coverage
    ///
    pub unsafe fn total_coverage(&self) -> HashSet<u64> {
        let mut total = HashSet::new();
        for cov in &self.coverage {
            total.extend(cov.iter().copied());
        }
        total
    }
    
    /// Get interesting inputs (those that add new coverage)
    ///
    pub unsafe fn interesting_inputs(&self) -> Vec<&Vec<u8>> {
        let mut interesting = Vec::new();
        let mut seen_coverage = HashSet::new();
        
        for (input, cov) in self.inputs.iter().zip(&self.coverage) {
            let new_coverage: HashSet<_> = cov.difference(&seen_coverage).copied().collect();
            
            if !new_coverage.is_empty() {
                interesting.push(input);
                seen_coverage.extend(new_coverage);
            }
        }
        
        interesting
    }
}

/// Coverage-guided input generator
pub struct CoverageGuidedGenerator {
    /// Input corpus
    corpus: InputCorpus,
    /// Target addresses to reach
    targets: Vec<u64>,
    /// Covered addresses
    covered: HashSet<u64>,
}

impl CoverageGuidedGenerator {
    /// Create new generator
    ///
    pub unsafe fn new() -> Self {
        CoverageGuidedGenerator {
            corpus: InputCorpus::new(),
            targets: Vec::new(),
            covered: HashSet::new(),
        }
    }
    
    /// Add target address
    ///
    pub unsafe fn add_target(&mut self, addr: u64) {
        self.targets.push(addr);
    }
    
    /// Generate inputs to maximize coverage
    ///
    pub unsafe fn generate<F>(&mut self, seed: Vec<u8>, max_inputs: usize, execute: F) -> Vec<Vec<u8>>
    where
        F: Fn(&[u8]) -> HashSet<u64>,
    {
        let mut generated = Vec::new();
        let mut queue = vec![seed];
        
        while !queue.is_empty() && generated.len() < max_inputs {
            let input = queue.pop().unwrap();
            
            // Execute and get coverage
            let coverage = execute(&input);
            
            // Check if new coverage
            let new_cov: HashSet<_> = coverage.difference(&self.covered).copied().collect();
            
            if !new_cov.is_empty() {
                // Add to corpus
                self.corpus.add(input.clone(), coverage.clone());
                self.covered.extend(new_cov);
                generated.push(input.clone());
                
                // Mutate for next generation
                for _ in 0..10 {
                    let mutated = self.mutate(&input);
                    queue.push(mutated);
                }
            }
        }
        
        generated
    }
    
    /// Mutate input
    ///
    unsafe fn mutate(&self, input: &[u8]) -> Vec<u8> {
        let mut mutated = input.to_vec();
        
        if mutated.is_empty() {
            return mutated;
        }
        
        // Random mutation strategy
        let strategy = (mutated.len() * 7) % 5;
        
        match strategy {
            0 => {
                // Bit flip
                let idx = mutated.len() % mutated.len();
                let bit = (mutated.len() * 3) % 8;
                mutated[idx] ^= 1 << bit;
            }
            1 => {
                // Byte flip
                let idx = mutated.len() % mutated.len();
                mutated[idx] ^= 0xFF;
            }
            2 => {
                // Increment
                let idx = mutated.len() % mutated.len();
                mutated[idx] = mutated[idx].wrapping_add(1);
            }
            3 => {
                // Append byte
                mutated.push(0x41);
            }
            4 => {
                // Delete byte
                if !mutated.is_empty() {
                    let idx = mutated.len() % mutated.len();
                    mutated.remove(idx);
                }
            }
            _ => {}
        }
        
        mutated
    }
    
    /// Get coverage percentage
    ///
    pub unsafe fn coverage_percent(&self) -> f64 {
        if self.targets.is_empty() {
            return 0.0;
        }
        
        let reached = self.targets.iter().filter(|t| self.covered.contains(t)).count();
        (reached as f64 / self.targets.len() as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_corpus() {
        unsafe {
            let mut corpus = InputCorpus::new();
            
            let input1 = vec![1, 2, 3];
            let cov1: HashSet<u64> = [0x400000, 0x400100].iter().copied().collect();
            
            let input2 = vec![4, 5, 6];
            let cov2: HashSet<u64> = [0x400100, 0x400200].iter().copied().collect();
            
            corpus.add(input1, cov1);
            corpus.add(input2, cov2);
            
            let total = corpus.total_coverage();
            assert_eq!(total.len(), 3);
        }
    }

    #[test]
    fn test_coverage_guided() {
        unsafe {
            let mut gen = CoverageGuidedGenerator::new();
            gen.add_target(0x400000);
            gen.add_target(0x400100);
            
            let seed = vec![0x41, 0x42];
            
            // Simulate execution
            let inputs = gen.generate(seed, 10, |_input| {
                let mut cov = HashSet::new();
                cov.insert(0x400000);
                cov
            });
            
            assert!(!inputs.is_empty());
        }
    }
}
