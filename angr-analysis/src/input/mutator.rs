//! Input Mutator
//!
//! Smart mutation strategies for input generation

/// Mutation strategy
#[derive(Debug, Clone, Copy)]
pub enum MutationStrategy {
    /// Flip random bit
    BitFlip,
    /// Flip random byte
    ByteFlip,
    /// Increment/decrement
    Arithmetic,
    /// Insert interesting value
    InterestingValue,
    /// Splice two inputs
    Splice,
    /// Havoc (multiple random mutations)
    Havoc,
}

/// Input mutator
pub struct InputMutator {
    /// Interesting values to try
    interesting_values: Vec<Vec<u8>>,
}

impl InputMutator {
    /// Create new mutator
    ///
    pub unsafe fn new() -> Self {
        let mut interesting = Vec::new();
        
        // Add common interesting values
        interesting.push(vec![0x00]); // NULL
        interesting.push(vec![0xFF]); // -1
        interesting.push(vec![0x00, 0x00]); // 0 (16-bit)
        interesting.push(vec![0xFF, 0xFF]); // -1 (16-bit)
        interesting.push(vec![0x00, 0x00, 0x00, 0x00]); // 0 (32-bit)
        interesting.push(vec![0xFF, 0xFF, 0xFF, 0xFF]); // -1 (32-bit)
        interesting.push(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // 0 (64-bit)
        
        InputMutator {
            interesting_values: interesting,
        }
    }
    
    /// Mutate input
    ///
    pub unsafe fn mutate(&self, input: &[u8], strategy: MutationStrategy) -> Vec<u8> {
        match strategy {
            MutationStrategy::BitFlip => self.bit_flip(input),
            MutationStrategy::ByteFlip => self.byte_flip(input),
            MutationStrategy::Arithmetic => self.arithmetic(input),
            MutationStrategy::InterestingValue => self.interesting_value(input),
            MutationStrategy::Splice => input.to_vec(), // Would splice with another input
            MutationStrategy::Havoc => self.havoc(input),
        }
    }
    
    /// Flip random bit
    ///
    unsafe fn bit_flip(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        
        let mut mutated = input.to_vec();
        let byte_idx = (input.len() * 17) % input.len();
        let bit_idx = (input.len() * 13) % 8;
        
        mutated[byte_idx] ^= 1 << bit_idx;
        mutated
    }
    
    /// Flip random byte
    ///
    unsafe fn byte_flip(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        
        let mut mutated = input.to_vec();
        let idx = (input.len() * 23) % input.len();
        mutated[idx] ^= 0xFF;
        mutated
    }
    
    /// Arithmetic mutation
    ///
    unsafe fn arithmetic(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return input.to_vec();
        }
        
        let mut mutated = input.to_vec();
        let idx = (input.len() * 29) % input.len();
        let delta = (input.len() % 35) as i8;
        
        mutated[idx] = mutated[idx].wrapping_add(delta as u8);
        mutated
    }
    
    /// Insert interesting value
    ///
    unsafe fn interesting_value(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() || self.interesting_values.is_empty() {
            return input.to_vec();
        }
        
        let mut mutated = input.to_vec();
        let value_idx = (input.len() * 31) % self.interesting_values.len();
        let insert_idx = (input.len() * 37) % input.len();
        
        let value = &self.interesting_values[value_idx];
        
        // Replace bytes with interesting value
        for (i, &byte) in value.iter().enumerate() {
            if insert_idx + i < mutated.len() {
                mutated[insert_idx + i] = byte;
            }
        }
        
        mutated
    }
    
    /// Havoc mutation (multiple random changes)
    ///
    unsafe fn havoc(&self, input: &[u8]) -> Vec<u8> {
        let mut mutated = input.to_vec();
        
        // Apply multiple mutations
        let num_mutations = 1 + (input.len() % 5);
        
        for i in 0..num_mutations {
            let strategy_idx = (i * 41) % 4;
            let strategy = match strategy_idx {
                0 => MutationStrategy::BitFlip,
                1 => MutationStrategy::ByteFlip,
                2 => MutationStrategy::Arithmetic,
                _ => MutationStrategy::InterestingValue,
            };
            
            mutated = self.mutate(&mutated, strategy);
        }
        
        mutated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_flip() {
        unsafe {
            let mutator = InputMutator::new();
            let input = vec![0x00, 0x00, 0x00];
            let mutated = mutator.mutate(&input, MutationStrategy::BitFlip);
            
            assert_ne!(input, mutated);
        }
    }

    #[test]
    fn test_havoc() {
        unsafe {
            let mutator = InputMutator::new();
            let input = vec![0x41; 10];
            let mutated = mutator.mutate(&input, MutationStrategy::Havoc);
            
            // Should have some differences
            assert_ne!(input, mutated);
        }
    }
}
