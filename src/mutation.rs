//! Mutation strategies for fuzzing.

/// Simple deterministic PRNG (xorshift64) for reproducible mutations.
#[derive(Debug, Clone)]
pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }
    
    /// Next random u64
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
    
    /// Random value in range [0, max)
    pub fn gen_range(&mut self, max: usize) -> usize {
        if max == 0 { return 0; }
        (self.next_u64() % max as u64) as usize
    }
    
    /// Random byte
    pub fn gen_u8(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
    
    /// Random value in [-35, 36)
    pub fn gen_arith(&mut self) -> i32 {
        (self.gen_range(71) as i32) - 35
    }
}

/// Mutation strategy
#[derive(Debug, Clone, PartialEq)]
pub enum MutationStrategy {
    /// Bit flip mutation
    BitFlip,
    /// Byte flip mutation
    ByteFlip,
    /// Arithmetic mutation
    Arithmetic,
    /// Dictionary mutation
    Dictionary,
    /// Splice mutation
    Splice,
    /// Havoc mutation
    Havoc,
}

/// Mutation operation
#[derive(Debug, Clone, PartialEq)]
pub enum MutationOp {
    /// Flip bit
    FlipBit { offset: usize, bit: u8 },
    /// Flip byte
    FlipByte { offset: usize, value: u8 },
    /// Add value
    Add { offset: usize, value: i32 },
    /// Subtract value
    Subtract { offset: usize, value: i32 },
    /// Insert bytes
    Insert { offset: usize, data: Vec<u8> },
    /// Delete bytes
    Delete { offset: usize, len: usize },
    /// Clone bytes
    Clone { src_offset: usize, dst_offset: usize, len: usize },
    /// Dictionary insert
    DictionaryInsert { offset: usize, word: Vec<u8> },
}

/// Mutator
#[derive(Debug, Clone)]
pub struct Mutator {
    /// Mutation strategies
    pub strategies: Vec<MutationStrategy>,
    /// Dictionary words
    pub dictionary: Vec<Vec<u8>>,
    /// Max mutation count
    pub max_mutations: usize,
    /// Created timestamp
    pub created_at: u64,
}

impl Mutator {
    /// Create new mutator
    pub fn new() -> Self {
        Self {
            strategies: vec![],
            dictionary: vec![],
            max_mutations: 8,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Add strategy
    pub fn add_strategy(&mut self, strategy: MutationStrategy) {
        if !self.strategies.contains(&strategy) {
            self.strategies.push(strategy);
        }
    }
    
    /// Remove strategy
    pub fn remove_strategy(&mut self, strategy: &MutationStrategy) -> bool {
        if let Some(pos) = self.strategies.iter().position(|s| s == strategy) {
            self.strategies.remove(pos);
            return true;
        }
        false
    }
    
    /// Add dictionary word
    pub fn add_dictionary_word(&mut self, word: Vec<u8>) {
        if !self.dictionary.contains(&word) {
            self.dictionary.push(word);
        }
    }
    
    /// Set max mutations
    pub fn set_max_mutations(&mut self, max: usize) {
        self.max_mutations = max;
    }
    
    /// Mutate input (deterministic, seeded)
    pub fn mutate(&self, input: &[u8], count: usize) -> Vec<Vec<u8>> {
        self.mutate_seeded(input, count, 0x9E3779B97F4A7C15)
    }
    
    /// Mutate input with explicit seed for reproducibility
    pub fn mutate_seeded(&self, input: &[u8], count: usize, seed: u64) -> Vec<Vec<u8>> {
        let mut results = Vec::new();
        let mut rng = SimpleRng::new(seed);
        
        for _ in 0..count {
            let mut mutated = input.to_vec();
            let num_mutations = 1 + rng.gen_range(self.max_mutations);
            
            for _ in 0..num_mutations {
                if self.strategies.is_empty() || mutated.is_empty() {
                    break;
                }
                
                let strategy = &self.strategies[rng.gen_range(self.strategies.len())];
                self.apply_mutation(&mut mutated, strategy, &mut rng);
            }
            
            results.push(mutated);
        }
        
        results
    }
    
    /// Apply single mutation
    fn apply_mutation(&self, data: &mut Vec<u8>, strategy: &MutationStrategy, rng: &mut SimpleRng) {
        match strategy {
            MutationStrategy::BitFlip => {
                if !data.is_empty() {
                    let offset = rng.gen_range(data.len());
                    let bit = rng.gen_range(8);
                    data[offset] ^= 1u8 << bit;
                }
            }
            MutationStrategy::ByteFlip => {
                if !data.is_empty() {
                    let offset = rng.gen_range(data.len());
                    data[offset] = rng.gen_u8();
                }
            }
            MutationStrategy::Arithmetic => {
                if !data.is_empty() {
                    let offset = rng.gen_range(data.len());
                    let value = rng.gen_arith() as i8;
                    data[offset] = data[offset].wrapping_add(value as u8);
                }
            }
            MutationStrategy::Dictionary => {
                if !self.dictionary.is_empty() && !data.is_empty() {
                    let word = &self.dictionary[rng.gen_range(self.dictionary.len())];
                    let offset = rng.gen_range(data.len() + 1);
                    let end = (offset + word.len()).min(data.len());
                    data.splice(offset..end, word.iter().cloned());
                }
            }
            MutationStrategy::Splice => {
                if data.len() > 1 {
                    let src_start = rng.gen_range(data.len());
                    let src_end = src_start + rng.gen_range(data.len() - src_start + 1);
                    let dst_offset = rng.gen_range(data.len() + 1);
                    let segment: Vec<u8> = data[src_start..src_end].to_vec();
                    data.splice(dst_offset..dst_offset, segment);
                }
            }
            MutationStrategy::Havoc => {
                // Multiple random mutations
                let num = 1 + rng.gen_range(4);
                for _ in 0..num {
                    if data.is_empty() {
                        break;
                    }
                    let offset = rng.gen_range(data.len());
                    match rng.gen_range(3) {
                        0 => data[offset] ^= 1u8 << rng.gen_range(8),
                        1 => data[offset] = rng.gen_u8(),
                        _ => {
                            if data.len() > 1 {
                                data.remove(offset);
                            }
                        }
                    }
                }
            }
        }
    }
    
    /// Get strategy count
    pub fn get_strategy_count(&self) -> usize {
        self.strategies.len()
    }
    
    /// Get dictionary size
    pub fn get_dictionary_size(&self) -> usize {
        self.dictionary.len()
    }
    
    /// Check if has strategies
    pub fn has_strategies(&self) -> bool {
        !self.strategies.is_empty()
    }
    
    /// Get mutator age in seconds
    pub fn get_age_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.created_at
    }
}

impl Default for Mutator {
    fn default() -> Self {
        Self::new()
    }
}
