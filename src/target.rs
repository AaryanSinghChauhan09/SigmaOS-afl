//! Fuzz target definitions.

/// Target state
#[derive(Debug, Clone, PartialEq)]
pub enum TargetState {
    /// Idle target
    Idle,
    /// Fuzzing target
    Fuzzing,
    /// Paused target
    Paused,
    /// Completed target
    Completed,
    /// Error target
    Error,
}

/// Target config
#[derive(Debug, Clone)]
pub struct TargetConfig {
    /// Timeout in milliseconds
    pub timeout_ms: u64,
    /// Max input length
    pub max_len: usize,
    /// Memory limit in MB
    pub memory_limit_mb: u64,
    /// Enable ASAN
    pub enable_asan: bool,
    /// Enable UBSAN
    pub enable_ubsan: bool,
    /// Enable MSAN
    pub enable_msan: bool,
    /// Enable coverage
    pub enable_coverage: bool,
    /// Custom args
    pub custom_args: Vec<String>,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 1000,
            max_len: 1024,
            memory_limit_mb: 512,
            enable_asan: true,
            enable_ubsan: false,
            enable_msan: false,
            enable_coverage: true,
            custom_args: vec![],
        }
    }
}

/// Fuzz target
#[derive(Debug, Clone)]
pub struct FuzzTarget {
    /// Target ID
    pub id: String,
    /// Target name
    pub name: String,
    /// Binary path
    pub binary_path: String,
    /// Target state
    pub state: TargetState,
    /// Target config
    pub config: TargetConfig,
    /// Target corpus IDs
    pub corpus_ids: Vec<String>,
    /// Target created timestamp
    pub created_at: u64,
    /// Target last fuzzed timestamp
    pub last_fuzzed: Option<u64>,
    /// Target exec count
    pub exec_count: u64,
    /// Target crash count
    pub crash_count: u64,
}

impl FuzzTarget {
    /// Create new fuzz target
    pub fn new(id: String, binary_path: String) -> Self {
        Self {
            id,
            name: String::new(),
            binary_path,
            state: TargetState::Idle,
            config: TargetConfig::default(),
            corpus_ids: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_fuzzed: None,
            exec_count: 0,
            crash_count: 0,
        }
    }
    
    /// Set name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }
    
    /// Set config
    pub fn set_config(&mut self, config: TargetConfig) {
        self.config = config;
    }
    
    /// Add corpus
    pub fn add_corpus(&mut self, corpus_id: String) {
        if !self.corpus_ids.contains(&corpus_id) {
            self.corpus_ids.push(corpus_id);
        }
    }
    
    /// Remove corpus
    pub fn remove_corpus(&mut self, corpus_id: &str) -> bool {
        if let Some(pos) = self.corpus_ids.iter().position(|c| c == corpus_id) {
            self.corpus_ids.remove(pos);
            return true;
        }
        false
    }
    
    /// Set fuzzing state
    pub fn set_fuzzing(&mut self) {
        self.state = TargetState::Fuzzing;
        self.last_fuzzed = Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());
    }
    
    /// Set idle state
    pub fn set_idle(&mut self) {
        self.state = TargetState::Idle;
    }
    
    /// Set paused state
    pub fn set_paused(&mut self) {
        self.state = TargetState::Paused;
    }
    
    /// Set completed state
    pub fn set_completed(&mut self) {
        self.state = TargetState::Completed;
    }
    
    /// Set error state
    pub fn set_error(&mut self) {
        self.state = TargetState::Error;
    }
    
    /// Increment exec count
    pub fn increment_exec_count(&mut self) {
        self.exec_count += 1;
    }
    
    /// Increment crash count
    pub fn increment_crash_count(&mut self) {
        self.crash_count += 1;
    }
    
    /// Check if target is fuzzing
    pub fn is_fuzzing(&self) -> bool {
        self.state == TargetState::Fuzzing
    }
    
    /// Check if target is idle
    pub fn is_idle(&self) -> bool {
        self.state == TargetState::Idle
    }
    
    /// Get target age in seconds
    pub fn get_age_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.created_at
    }
    
    /// Get corpus count
    pub fn get_corpus_count(&self) -> usize {
        self.corpus_ids.len()
    }
}
