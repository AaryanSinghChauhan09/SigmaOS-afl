//! Crash detection and deduplication for fuzzing.

/// Crash type
#[derive(Debug, Clone, PartialEq)]
pub enum CrashType {
    /// Segmentation fault
    Segfault,
    /// Abort
    Abort,
    /// Timeout
    Timeout,
    /// Out of memory
    OOM,
    /// Assertion failure
    Assert,
    /// Memory leak
    Leak,
}

/// Crash severity
#[derive(Debug, Clone, PartialEq)]
pub enum CrashSeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Crash
#[derive(Debug, Clone)]
pub struct Crash {
    /// Crash ID
    pub id: String,
    /// Crash type
    pub crash_type: CrashType,
    /// Crash severity
    pub severity: CrashSeverity,
    /// Crash input data
    pub input: Vec<u8>,
    /// Crash stack trace
    pub stack_trace: String,
    /// Crash registers
    pub registers: std::collections::HashMap<String, String>,
    /// Crash signal
    pub signal: Option<String>,
    /// Crash reproducible
    pub reproducible: bool,
    /// Crash found timestamp
    pub found_at: u64,
    /// Crash dedup key
    pub dedup_key: String,
}

impl Crash {
    /// Create new crash
    pub fn new(id: String, crash_type: CrashType) -> Self {
        let dedup_key = format!("{:?}", crash_type);
        Self {
            id,
            crash_type,
            severity: CrashSeverity::Medium,
            input: vec![],
            stack_trace: String::new(),
            registers: std::collections::HashMap::new(),
            signal: None,
            reproducible: false,
            found_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            dedup_key,
        }
    }
    
    /// Set severity
    pub fn set_severity(&mut self, severity: CrashSeverity) {
        self.severity = severity;
    }
    
    /// Set input
    pub fn set_input(&mut self, input: Vec<u8>) {
        self.input = input;
        self.update_dedup_key();
    }
    
    /// Set stack trace
    pub fn set_stack_trace(&mut self, stack_trace: String) {
        self.stack_trace = stack_trace;
    }
    
    /// Set signal
    pub fn set_signal(&mut self, signal: String) {
        self.signal = Some(signal);
    }
    
    /// Set reproducible
    pub fn set_reproducible(&mut self, reproducible: bool) {
        self.reproducible = reproducible;
    }
    
    /// Add register
    pub fn add_register(&mut self, name: String, value: String) {
        self.registers.insert(name, value);
    }
    
    /// Update dedup key
    fn update_dedup_key(&mut self) {
        // Simple dedup: crash type + input hash (FNV-1a)
        let mut hash: u64 = 0xcbf29ce484222325;
        for b in format!("{:?}", self.crash_type).bytes().chain(self.input.iter().copied()) {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        self.dedup_key = format!("{:016x}", hash);
    }
    
    /// Check if crash is critical
    pub fn is_critical(&self) -> bool {
        self.severity == CrashSeverity::Critical
    }
    
    /// Check if crash is high severity
    pub fn is_high(&self) -> bool {
        self.severity == CrashSeverity::High
    }
    
    /// Check if crash is reproducible
    pub fn is_reproducible(&self) -> bool {
        self.reproducible
    }
    
    /// Get crash age in seconds
    pub fn get_age_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.found_at
    }
    
    /// Get input size
    pub fn get_input_size(&self) -> usize {
        self.input.len()
    }
    
    /// Get register count
    pub fn get_register_count(&self) -> usize {
        self.registers.len()
    }
}

/// Crash dedup
#[derive(Debug, Clone)]
pub struct CrashDedup {
    /// Seen crash keys
    pub seen_keys: std::collections::HashSet<String>,
    /// Crash counts per key
    pub crash_counts: std::collections::HashMap<String, u64>,
}

impl CrashDedup {
    /// Create new crash dedup
    pub fn new() -> Self {
        Self {
            seen_keys: std::collections::HashSet::new(),
            crash_counts: std::collections::HashMap::new(),
        }
    }
    
    /// Check if crash is duplicate
    pub fn is_duplicate(&self, crash1: &Crash, crash2: &Crash) -> bool {
        crash1.dedup_key == crash2.dedup_key
    }
    
    /// Check if crash key is seen
    pub fn is_seen(&self, key: &str) -> bool {
        self.seen_keys.contains(key)
    }
    
    /// Record crash
    pub fn record_crash(&mut self, crash: &Crash) -> bool {
        if self.seen_keys.contains(&crash.dedup_key) {
            *self.crash_counts.entry(crash.dedup_key.clone()).or_insert(0) += 1;
            false
        } else {
            self.seen_keys.insert(crash.dedup_key.clone());
            self.crash_counts.insert(crash.dedup_key.clone(), 1);
            true
        }
    }
    
    /// Get crash count for key
    pub fn get_crash_count(&self, key: &str) -> u64 {
        self.crash_counts.get(key).copied().unwrap_or(0)
    }
    
    /// Get total unique crashes
    pub fn get_unique_count(&self) -> usize {
        self.seen_keys.len()
    }
    
    /// Get total crash count
    pub fn get_total_count(&self) -> u64 {
        self.crash_counts.values().sum()
    }
    
    /// Clear dedup
    pub fn clear(&mut self) {
        self.seen_keys.clear();
        self.crash_counts.clear();
    }
}

impl Default for CrashDedup {
    fn default() -> Self {
        Self::new()
    }
}
