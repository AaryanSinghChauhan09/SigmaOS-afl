//! Corpus management for fuzzing.

/// Corpus entry
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    /// Entry data
    pub data: Vec<u8>,
    /// Entry ID
    pub id: String,
    /// Execution count
    pub exec_count: u64,
    /// Coverage edges hit
    pub coverage_edges: Vec<u64>,
    /// Interesting flag
    pub interesting: bool,
    /// Crash flag
    pub crash: bool,
    /// Created timestamp
    pub created_at: u64,
    /// Last executed timestamp
    pub last_executed: Option<u64>,
}

impl CorpusEntry {
    /// Create new corpus entry
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            id: format!("entry-{}", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()),
            exec_count: 0,
            coverage_edges: vec![],
            interesting: true,
            crash: false,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_executed: None,
        }
    }
    
    /// Record execution
    pub fn record_execution(&mut self, coverage_edges: Vec<u64>) {
        self.exec_count += 1;
        self.coverage_edges = coverage_edges;
        self.last_executed = Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());
    }
    
    /// Mark as crash
    pub fn mark_crash(&mut self) {
        self.crash = true;
    }
    
    /// Mark as interesting
    pub fn mark_interesting(&mut self) {
        self.interesting = true;
    }
    
    /// Get data length
    pub fn get_data_len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if entry has coverage
    pub fn has_coverage(&self) -> bool {
        !self.coverage_edges.is_empty()
    }
    
    /// Get entry age in seconds
    pub fn get_age_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.created_at
    }
}

/// Corpus stats
#[derive(Debug, Clone)]
pub struct CorpusStats {
    /// Total entries
    pub total_entries: usize,
    /// Interesting entries
    pub interesting_entries: usize,
    /// Crash entries
    pub crash_entries: usize,
    /// Total executions
    pub total_executions: u64,
    /// Total coverage edges
    pub total_coverage_edges: usize,
    /// Corpus size in bytes
    pub corpus_size_bytes: usize,
}

/// Corpus
#[derive(Debug, Clone)]
pub struct Corpus {
    /// Corpus ID
    pub id: String,
    /// Corpus name
    pub name: String,
    /// Corpus entries
    pub entries: Vec<CorpusEntry>,
    /// Corpus created timestamp
    pub created_at: u64,
    /// Corpus modified timestamp
    pub modified_at: u64,
}

impl Corpus {
    /// Create new corpus
    pub fn new(id: String) -> Self {
        Self {
            id,
            name: String::new(),
            entries: vec![],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            modified_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Set name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Add entry
    pub fn add_entry(&mut self, entry: CorpusEntry) -> String {
        let id = entry.id.clone();
        self.entries.push(entry);
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        id
    }
    
    /// Get entry
    pub fn get_entry(&self, entry_id: &str) -> Option<&CorpusEntry> {
        self.entries.iter().find(|e| e.id == entry_id)
    }
    
    /// Get entry mutably
    pub fn get_entry_mut(&mut self, entry_id: &str) -> Option<&mut CorpusEntry> {
        self.entries.iter_mut().find(|e| e.id == entry_id)
    }
    
    /// Remove entry
    pub fn remove_entry(&mut self, entry_id: &str) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.id == entry_id) {
            self.entries.remove(pos);
            self.modified_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            return true;
        }
        false
    }
    
    /// Get interesting entries
    pub fn get_interesting_entries(&self) -> Vec<&CorpusEntry> {
        self.entries.iter().filter(|e| e.interesting).collect()
    }
    
    /// Get crash entries
    pub fn get_crash_entries(&self) -> Vec<&CorpusEntry> {
        self.entries.iter().filter(|e| e.crash).collect()
    }
    
    /// Get stats
    pub fn get_stats(&self) -> CorpusStats {
        CorpusStats {
            total_entries: self.entries.len(),
            interesting_entries: self.entries.iter().filter(|e| e.interesting).count(),
            crash_entries: self.entries.iter().filter(|e| e.crash).count(),
            total_executions: self.entries.iter().map(|e| e.exec_count).sum(),
            total_coverage_edges: self.entries.iter()
                .map(|e| e.coverage_edges.len())
                .sum(),
            corpus_size_bytes: self.entries.iter()
                .map(|e| e.data.len())
                .sum(),
        }
    }
    
    /// Clear corpus
    pub fn clear(&mut self) {
        self.entries.clear();
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Get corpus age in seconds
    pub fn get_age_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.created_at
    }
    
    /// Get time since modification in seconds
    pub fn get_time_since_modification(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.modified_at
    }
}
