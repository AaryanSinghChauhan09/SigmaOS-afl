//! Fuzzing campaign definitions.

use crate::coverage::CoverageMap;

/// Campaign state
#[derive(Debug, Clone, PartialEq)]
pub enum CampaignState {
    /// Idle campaign
    Idle,
    /// Running campaign
    Running,
    /// Paused campaign
    Paused,
    /// Completed campaign
    Completed,
    /// Failed campaign
    Failed,
}

/// Campaign config
#[derive(Debug, Clone)]
pub struct CampaignConfig {
    /// Max iterations
    pub max_iterations: u64,
    /// Max time in seconds
    pub max_time_seconds: u64,
    /// Target coverage percentage
    pub target_coverage: f64,
    /// Enable crash dedup
    pub enable_crash_dedup: bool,
    /// Enable corpus minimization
    pub enable_corpus_minimization: bool,
    /// Mutation depth
    pub mutation_depth: usize,
    /// Custom dictionary path
    pub dictionary_path: Option<String>,
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            max_iterations: 100000,
            max_time_seconds: 3600,
            target_coverage: 0.9,
            enable_crash_dedup: true,
            enable_corpus_minimization: true,
            mutation_depth: 8,
            dictionary_path: None,
        }
    }
}

/// Campaign stats
#[derive(Debug, Clone)]
pub struct CampaignStats {
    /// Total iterations
    pub total_iterations: u64,
    /// Total executions
    pub total_executions: u64,
    /// Total crashes
    pub total_crashes: u64,
    /// Unique crashes
    pub unique_crashes: u64,
    /// Coverage percentage
    pub coverage_percent: f64,
    /// Corpus size
    pub corpus_size: usize,
    /// Exec speed (exec/sec)
    pub exec_speed: f64,
    /// Campaign duration in seconds
    pub duration_seconds: u64,
}

/// Campaign
#[derive(Debug, Clone)]
pub struct Campaign {
    /// Campaign ID
    pub id: String,
    /// Campaign name
    pub name: String,
    /// Campaign state
    pub state: CampaignState,
    /// Campaign config
    pub config: CampaignConfig,
    /// Campaign target ID
    pub target_id: String,
    /// Campaign corpus IDs
    pub corpus_ids: Vec<String>,
    /// Campaign coverage map
    pub coverage: CoverageMap,
    /// Campaign stats
    pub stats: CampaignStats,
    /// Campaign created timestamp
    pub created_at: u64,
    /// Campaign started timestamp
    pub started_at: Option<u64>,
    /// Campaign completed timestamp
    pub completed_at: Option<u64>,
}

impl Campaign {
    /// Create new campaign
    pub fn new(id: String) -> Self {
        Self {
            id,
            name: String::new(),
            state: CampaignState::Idle,
            config: CampaignConfig::default(),
            target_id: String::new(),
            corpus_ids: vec![],
            coverage: CoverageMap::new(),
            stats: CampaignStats {
                total_iterations: 0,
                total_executions: 0,
                total_crashes: 0,
                unique_crashes: 0,
                coverage_percent: 0.0,
                corpus_size: 0,
                exec_speed: 0.0,
                duration_seconds: 0,
            },
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            started_at: None,
            completed_at: None,
        }
    }
    
    /// Set name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }
    
    /// Set target
    pub fn set_target(&mut self, target_id: String) {
        self.target_id = target_id;
    }
    
    /// Set config
    pub fn set_config(&mut self, config: CampaignConfig) {
        self.config = config;
    }
    
    /// Add corpus
    pub fn add_corpus(&mut self, corpus_id: String) {
        if !self.corpus_ids.contains(&corpus_id) {
            self.corpus_ids.push(corpus_id);
        }
    }
    
    /// Start campaign
    pub fn start(&mut self) -> bool {
        if self.state == CampaignState::Idle {
            self.state = CampaignState::Running;
            self.started_at = Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs());
            return true;
        }
        false
    }
    
    /// Stop campaign
    pub fn stop(&mut self) -> bool {
        if self.state == CampaignState::Running {
            self.state = CampaignState::Completed;
            self.completed_at = Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs());
            self.update_stats();
            return true;
        }
        false
    }
    
    /// Pause campaign
    pub fn pause(&mut self) -> bool {
        if self.state == CampaignState::Running {
            self.state = CampaignState::Paused;
            return true;
        }
        false
    }
    
    /// Resume campaign
    pub fn resume(&mut self) -> bool {
        if self.state == CampaignState::Paused {
            self.state = CampaignState::Running;
            return true;
        }
        false
    }
    
    /// Fail campaign
    pub fn fail(&mut self) {
        self.state = CampaignState::Failed;
        self.completed_at = Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());
    }
    
    /// Record iteration
    pub fn record_iteration(&mut self) {
        self.stats.total_iterations += 1;
        self.stats.total_executions += 1;
        self.update_exec_speed();
    }
    
    /// Record crash
    pub fn record_crash(&mut self, unique: bool) {
        self.stats.total_crashes += 1;
        if unique {
            self.stats.unique_crashes += 1;
        }
    }
    
    /// Update coverage
    pub fn update_coverage(&mut self) {
        let stats = self.coverage.get_stats();
        self.stats.coverage_percent = stats.coverage_percent;
    }
    
    /// Update corpus size
    pub fn update_corpus_size(&mut self, size: usize) {
        self.stats.corpus_size = size;
    }
    
    /// Update exec speed
    fn update_exec_speed(&mut self) {
        let duration = self.get_duration();
        if duration > 0 {
            self.stats.exec_speed = self.stats.total_executions as f64 / duration as f64;
        }
    }
    
    /// Update stats
    fn update_stats(&mut self) {
        self.stats.duration_seconds = self.get_duration();
        self.update_exec_speed();
        self.update_coverage();
    }
    
    /// Get duration in seconds
    pub fn get_duration(&self) -> u64 {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => end - start,
            (Some(start), None) => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - start,
            _ => 0,
        }
    }
    
    /// Check if campaign is running
    pub fn is_running(&self) -> bool {
        self.state == CampaignState::Running
    }
    
    /// Check if campaign is completed
    pub fn is_completed(&self) -> bool {
        self.state == CampaignState::Completed
    }
    
    /// Check if campaign is failed
    pub fn is_failed(&self) -> bool {
        self.state == CampaignState::Failed
    }
    
    /// Check if campaign reached target coverage
    pub fn reached_target_coverage(&self) -> bool {
        self.stats.coverage_percent >= self.config.target_coverage * 100.0
    }
    
    /// Check if campaign exceeded max iterations
    pub fn exceeded_max_iterations(&self) -> bool {
        self.stats.total_iterations >= self.config.max_iterations
    }
    
    /// Check if campaign exceeded max time
    pub fn exceeded_max_time(&self) -> bool {
        self.get_duration() >= self.config.max_time_seconds
    }
    
    /// Get campaign age in seconds
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
