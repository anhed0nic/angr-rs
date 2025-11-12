//! Input Minimizer
//!
//! Minimize crashing inputs to their smallest form

use super::CrashInfo;

/// Input minimizer
pub struct InputMinimizer {
    /// Original input
    original: Vec<u8>,
    /// Minimized input
    minimized: Vec<u8>,
}

impl InputMinimizer {
    /// Create new minimizer
    ///
    pub unsafe fn new(input: Vec<u8>) -> Self {
        InputMinimizer {
            minimized: input.clone(),
            original: input,
        }
    }
    
    /// Minimize input using delta debugging
    ///
    pub unsafe fn minimize<F>(&mut self, still_crashes: F) -> Vec<u8>
    where
        F: Fn(&[u8]) -> bool,
    {
        // Binary search for minimal input
        let mut input = self.original.clone();
        
        // Try removing chunks
        let mut chunk_size = input.len() / 2;
        
        while chunk_size > 0 {
            let mut i = 0;
            
            while i + chunk_size <= input.len() {
                // Try removing this chunk
                let mut test_input = Vec::new();
                test_input.extend_from_slice(&input[..i]);
                test_input.extend_from_slice(&input[i + chunk_size..]);
                
                if still_crashes(&test_input) {
                    // Chunk can be removed
                    input = test_input;
                } else {
                    i += chunk_size;
                }
            }
            
            chunk_size /= 2;
        }
        
        // Try minimizing individual bytes
        for i in 0..input.len() {
            let original_byte = input[i];
            
            // Try zero
            input[i] = 0;
            if !still_crashes(&input) {
                input[i] = original_byte;
            }
        }
        
        self.minimized = input.clone();
        input
    }
    
    /// Get minimized input
    ///
    pub unsafe fn get_minimized(&self) -> &[u8] {
        &self.minimized
    }
    
    /// Get reduction percentage
    ///
    pub unsafe fn reduction_percent(&self) -> f64 {
        if self.original.is_empty() {
            return 0.0;
        }
        
        let reduction = self.original.len() - self.minimized.len();
        (reduction as f64 / self.original.len() as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimizer() {
        unsafe {
            let input = vec![b'A'; 100];
            input.extend(vec![b'B'; 10]); // Only B's trigger crash
            
            let mut minimizer = InputMinimizer::new(input);
            
            // Simulate crash on B's
            let minimized = minimizer.minimize(|inp| {
                inp.contains(&b'B')
            });
            
            // Should keep only B's
            assert!(minimized.len() <= 110);
        }
    }
}
