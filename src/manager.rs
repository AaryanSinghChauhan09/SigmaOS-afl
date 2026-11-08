//! Fuzzing manager.

use std::collections::HashMap;
use crate::target::{FuzzTarget, TargetState};
use crate::corpus::{Corpus, CorpusEntry};
use crate::mutation::Mutator;
use crate::coverage::CoverageMap;
use crate::crash::{Crash, CrashDedup};
use crate::campaign::{Campaign, CampaignState};

/// Manager options
#[derive(Debug, Clone)]
pub struct ManagerOptions {
    /// Max targets
    pub max_targets: usize,
    /// Max campaigns
    pub max_campaigns: usize,
    /// Max crashes stored
    pub max_crashes: usize,
    /// Enable crash dedup
    pub enable_crash_dedup: bool,
    /// Enable coverage tracking
    pub enable_coverage: bool,
    /// Default mutation strategies
    pub default_strategies: Vec<crate::mutation::MutationStrategy>,
}

impl Default for ManagerOptions {
    fn default() -> Self {
        Self {
            max_targets: 100,
            max_campaigns: 50,
            max_crashes: 1000,
            enable_crash_dedup: true,
            enable_coverage: true,
            default_strategies: vec![
                crate::mutation::MutationStrategy::BitFlip,
                crate::mutation::MutationStrategy::ByteFlip,
                crate::mutation::MutationStrategy::Arithmetic,
                crate::mutation::MutationStrategy::Havoc,
            ],
        }
    }
}

/// Manager statistics
#[derive(Debug, Clone)]
pub struct ManagerStatistics {
    /// Total targets
    pub total_targets: usize,
    /// Total campaigns
    pub total_campaigns: usize,
    /// Running campaigns
    pub running_campaigns: usize,
    /// Total corpora
    pub total_corpora: usize,
    /// Total corpus entries
    pub total_corpus_entries: usize,
    /// Total crashes
    pub total_crashes: usize,
    /// Unique crashes
    pub unique_crashes: usize,
    /// Total executions
    pub total_executions: u64,
    /// Manager uptime in seconds
    pub uptime: u64,
}

/// Fuzz manager
#[derive(Debug, Clone)]
pub struct FuzzManager {
    /// Targets
    targets: HashMap<String, FuzzTarget>,
    /// Corpora
    corpora: HashMap<String, Corpus>,
    /// Campaigns
    campaigns: HashMap<String, Campaign>,
    /// Crashes
    crashes: Vec<Crash>,
    /// Crash dedup
    crash_dedup: CrashDedup,
    /// Mutator
    mutator: Mutator,
    /// Options
    options: ManagerOptions,
    /// Statistics
    statistics: ManagerStatistics,
    /// Manager created timestamp
    pub created_at: u64,
}

impl Default for FuzzManager {
    fn default() -> Self {
        Self {
            targets: HashMap::new(),
            corpora: HashMap::new(),
            campaigns: HashMap::new(),
            crashes: vec![],
            crash_dedup: CrashDedup::new(),
            mutator: Mutator::new(),
            options: ManagerOptions::default(),
            statistics: ManagerStatistics {
                total_targets: 0,
                total_campaigns: 0,
                running_campaigns: 0,
                total_corpora: 0,
                total_corpus_entries: 0,
                total_crashes: 0,
                unique_crashes: 0,
                total_executions: 0,
                uptime: 0,
            },
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

impl FuzzManager {
    /// Create new fuzz manager
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create manager with options
    pub fn with_options(options: ManagerOptions) -> Self {
        let mut mutator = Mutator::new();
        for strategy in &options.default_strategies {
            mutator.add_strategy(strategy.clone());
        }
        
        Self {
            targets: HashMap::new(),
            corpora: HashMap::new(),
            campaigns: HashMap::new(),
            crashes: vec![],
            crash_dedup: CrashDedup::new(),
            mutator,
            options,
            statistics: ManagerStatistics {
                total_targets: 0,
                total_campaigns: 0,
                running_campaigns: 0,
                total_corpora: 0,
                total_corpus_entries: 0,
                total_crashes: 0,
                unique_crashes: 0,
                total_executions: 0,
                uptime: 0,
            },
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Initialize manager
    pub fn initialize(&mut self) {
        self.update_statistics();
    }
    
    // Target methods
    
    /// Add target
    pub fn add_target(&mut self, name: String, binary_path: String) -> String {
        let target = FuzzTarget::new(format!("target-{}", self.targets.len() + 1), binary_path);
        let id = target.id.clone();
        
        let mut target = target;
        target.set_name(name);
        
        self.targets.insert(id.clone(), target);
        self.update_statistics();
        id
    }
    
    /// Get target
    pub fn get_target(&self, target_id: &str) -> Option<&FuzzTarget> {
        self.targets.get(target_id)
    }
    
    /// Get target mutably
    pub fn get_target_mut(&mut self, target_id: &str) -> Option<&mut FuzzTarget> {
        self.targets.get_mut(target_id)
    }
    
    /// Get all targets
    pub fn list_targets(&self) -> Vec<&FuzzTarget> {
        self.targets.values().collect()
    }
    
    /// Remove target
    pub fn remove_target(&mut self, target_id: &str) -> bool {
        // Remove associated campaigns
        let campaign_ids: Vec<String> = self.campaigns.values()
            .filter(|c| c.target_id == target_id)
            .map(|c| c.id.clone())
            .collect();
        for cid in campaign_ids {
            self.campaigns.remove(&cid);
        }
        
        if self.targets.remove(target_id).is_some() {
            self.update_statistics();
            return true;
        }
        false
    }
    
    /// Set target state
    pub fn set_target_state(&mut self, target_id: &str, state: TargetState) -> bool {
        if let Some(target) = self.targets.get_mut(target_id) {
            target.state = state;
            self.update_statistics();
            return true;
        }
        false
    }
    
    /// Get targets by state
    pub fn get_targets_by_state(&self, state: &TargetState) -> Vec<&FuzzTarget> {
        self.targets.values()
            .filter(|t| t.state == *state)
            .collect()
    }
    
    /// Search targets
    pub fn search_targets(&self, query: &str) -> Vec<&FuzzTarget> {
        let query_lower = query.to_lowercase();
        self.targets.values()
            .filter(|t| t.name.to_lowercase().contains(&query_lower) ||
                       t.binary_path.to_lowercase().contains(&query_lower))
            .collect()
    }
    
    // Corpus methods
    
    /// Create corpus
    pub fn create_corpus(&mut self, name: String) -> String {
        let corpus = Corpus::new(format!("corpus-{}", self.corpora.len() + 1));
        let id = corpus.id.clone();
        
        let mut corpus = corpus;
        corpus.set_name(name);
        
        self.corpora.insert(id.clone(), corpus);
        self.update_statistics();
        id
    }
    
    /// Get corpus
    pub fn get_corpus(&self, corpus_id: &str) -> Option<&Corpus> {
        self.corpora.get(corpus_id)
    }
    
    /// Get corpus mutably
    pub fn get_corpus_mut(&mut self, corpus_id: &str) -> Option<&mut Corpus> {
        self.corpora.get_mut(corpus_id)
    }
    
    /// Get all corpora
    pub fn list_corpora(&self) -> Vec<&Corpus> {
        self.corpora.values().collect()
    }
    
    /// Remove corpus
    pub fn remove_corpus(&mut self, corpus_id: &str) -> bool {
        if self.corpora.remove(corpus_id).is_some() {
            self.update_statistics();
            return true;
        }
        false
    }
    
    /// Add entry to corpus
    pub fn add_corpus_entry(&mut self, corpus_id: &str, data: Vec<u8>) -> Option<String> {
        if let Some(corpus) = self.corpora.get_mut(corpus_id) {
            let entry = CorpusEntry::new(data);
            let entry_id = entry.id.clone();
            corpus.add_entry(entry);
            self.update_statistics();
            return Some(entry_id);
        }
        None
    }
    
    /// Get corpus entries
    pub fn get_corpus_entries(&self, corpus_id: &str) -> Vec<&CorpusEntry> {
        self.corpora.get(corpus_id)
            .map(|c| c.entries.iter().collect())
            .unwrap_or_default()
    }
    
    // Campaign methods
    
    /// Create campaign
    pub fn create_campaign(&mut self, target_id: &str, name: String) -> Option<String> {
        if !self.targets.contains_key(target_id) {
            return None;
        }
        
        let campaign = Campaign::new(format!("campaign-{}", self.campaigns.len() + 1));
        let id = campaign.id.clone();
        
        let mut campaign = campaign;
        campaign.set_name(name);
        campaign.set_target(target_id.to_string());
        
        self.campaigns.insert(id.clone(), campaign);
        self.update_statistics();
        Some(id)
    }
    
    /// Get campaign
    pub fn get_campaign(&self, campaign_id: &str) -> Option<&Campaign> {
        self.campaigns.get(campaign_id)
    }
    
    /// Get campaign mutably
    pub fn get_campaign_mut(&mut self, campaign_id: &str) -> Option<&mut Campaign> {
        self.campaigns.get_mut(campaign_id)
    }
    
    /// Get all campaigns
    pub fn list_campaigns(&self) -> Vec<&Campaign> {
        self.campaigns.values().collect()
    }
    
    /// Remove campaign
    pub fn remove_campaign(&mut self, campaign_id: &str) -> bool {
        if self.campaigns.remove(campaign_id).is_some() {
            self.update_statistics();
            return true;
        }
        false
    }
    
    /// Start campaign
    pub fn start_campaign(&mut self, campaign_id: &str) -> bool {
        if let Some(campaign) = self.campaigns.get_mut(campaign_id) {
            if campaign.start() {
                // Set target to fuzzing
                if let Some(target) = self.targets.get_mut(&campaign.target_id) {
                    target.set_fuzzing();
                }
                self.update_statistics();
                return true;
            }
        }
        false
    }
    
    /// Stop campaign
    pub fn stop_campaign(&mut self, campaign_id: &str) -> bool {
        if let Some(campaign) = self.campaigns.get_mut(campaign_id) {
            if campaign.stop() {
                // Set target to idle
                if let Some(target) = self.targets.get_mut(&campaign.target_id) {
                    target.set_idle();
                }
                self.update_statistics();
                return true;
            }
        }
        false
    }
    
    /// Pause campaign
    pub fn pause_campaign(&mut self, campaign_id: &str) -> bool {
        if let Some(campaign) = self.campaigns.get_mut(campaign_id) {
            return campaign.pause();
        }
        false
    }
    
    /// Resume campaign
    pub fn resume_campaign(&mut self, campaign_id: &str) -> bool {
        if let Some(campaign) = self.campaigns.get_mut(campaign_id) {
            return campaign.resume();
        }
        false
    }
    
    /// Get campaigns by state
    pub fn get_campaigns_by_state(&self, state: &CampaignState) -> Vec<&Campaign> {
        self.campaigns.values()
            .filter(|c| c.state == *state)
            .collect()
    }
    
    /// Get running campaigns
    pub fn get_running_campaigns(&self) -> Vec<&Campaign> {
        self.get_campaigns_by_state(&CampaignState::Running)
    }
    
    /// Get completed campaigns
    pub fn get_completed_campaigns(&self) -> Vec<&Campaign> {
        self.get_campaigns_by_state(&CampaignState::Completed)
    }
    
    /// Record campaign iteration
    pub fn record_campaign_iteration(&mut self, campaign_id: &str) -> bool {
        if let Some(campaign) = self.campaigns.get_mut(campaign_id) {
            campaign.record_iteration();
            return true;
        }
        false
    }
    
    /// Record campaign crash
    pub fn record_campaign_crash(&mut self, campaign_id: &str, unique: bool) -> bool {
        if let Some(campaign) = self.campaigns.get_mut(campaign_id) {
            campaign.record_crash(unique);
            return true;
        }
        false
    }
    
    // Crash methods
    
    /// Add crash
    pub fn add_crash(&mut self, crash: Crash) -> bool {
        // Check dedup
        if self.options.enable_crash_dedup {
            if !self.crash_dedup.record_crash(&crash) {
                return false; // Duplicate
            }
        }
        
        if self.crashes.len() >= self.options.max_crashes {
            // Remove oldest crash
            self.crashes.remove(0);
        }
        
        // Update target crash count
        if let Some(campaign) = self.campaigns.values().find(|c| c.is_running()) {
            if let Some(target) = self.targets.get_mut(&campaign.target_id) {
                target.increment_crash_count();
            }
        }
        
        self.crashes.push(crash);
        self.update_statistics();
        true
    }
    
    /// Get crash
    pub fn get_crash(&self, index: usize) -> Option<&Crash> {
        self.crashes.get(index)
    }
    
    /// Get all crashes
    pub fn list_crashes(&self) -> &[Crash] {
        &self.crashes
    }
    
    /// Remove crash
    pub fn remove_crash(&mut self, index: usize) -> bool {
        if index < self.crashes.len() {
            self.crashes.remove(index);
            self.update_statistics();
            return true;
        }
        false
    }
    
    /// Get crashes by type
    pub fn get_crashes_by_type(&self, crash_type: &crate::crash::CrashType) -> Vec<&Crash> {
        self.crashes.iter()
            .filter(|c| c.crash_type == *crash_type)
            .collect()
    }
    
    /// Get critical crashes
    pub fn get_critical_crashes(&self) -> Vec<&Crash> {
        self.crashes.iter()
            .filter(|c| c.is_critical())
            .collect()
    }
    
    /// Get reproducible crashes
    pub fn get_reproducible_crashes(&self) -> Vec<&Crash> {
        self.crashes.iter()
            .filter(|c| c.is_reproducible())
            .collect()
    }
    
    /// Clear crashes
    pub fn clear_crashes(&mut self) {
        self.crashes.clear();
        self.crash_dedup.clear();
        self.update_statistics();
    }
    
    // Mutation methods
    
    /// Get mutator
    pub fn get_mutator(&self) -> &Mutator {
        &self.mutator
    }
    
    /// Get mutator mutably
    pub fn get_mutator_mut(&mut self) -> &mut Mutator {
        &mut self.mutator
    }
    
    /// Mutate input
    pub fn mutate_input(&self, input: &[u8], count: usize) -> Vec<Vec<u8>> {
        self.mutator.mutate(input, count)
    }
    
    // Coverage methods
    
    /// Get coverage map for campaign
    pub fn get_campaign_coverage(&self, campaign_id: &str) -> Option<&CoverageMap> {
        self.campaigns.get(campaign_id)
            .map(|c| &c.coverage)
    }
    
    /// Update campaign coverage
    pub fn update_campaign_coverage(&mut self, campaign_id: &str, edge: crate::coverage::CoverageEdge) -> bool {
        if let Some(campaign) = self.campaigns.get_mut(campaign_id) {
            campaign.coverage.record_hit(&edge);
            campaign.update_coverage();
            return true;
        }
        false
    }
    
    // Statistics methods
    
    /// Get manager uptime
    pub fn get_uptime(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.created_at
    }
    
    /// Update statistics
    fn update_statistics(&mut self) {
        self.statistics.total_targets = self.targets.len();
        self.statistics.total_campaigns = self.campaigns.len();
        self.statistics.running_campaigns = self.campaigns.values()
            .filter(|c| c.state == CampaignState::Running)
            .count();
        self.statistics.total_corpora = self.corpora.len();
        self.statistics.total_corpus_entries = self.corpora.values()
            .map(|c| c.entries.len())
            .sum();
        self.statistics.total_crashes = self.crashes.len();
        self.statistics.unique_crashes = self.crash_dedup.get_unique_count();
        self.statistics.total_executions = self.campaigns.values()
            .map(|c| c.stats.total_executions)
            .sum();
        self.statistics.uptime = self.get_uptime();
    }
    
    /// Get statistics
    pub fn get_statistics(&self) -> &ManagerStatistics {
        &self.statistics
    }
    
    /// Export manager data
    pub fn export_data(&self) -> ManagerExport {
        ManagerExport {
            targets: self.targets.values().cloned().collect(),
            corpora: self.corpora.values().cloned().collect(),
            campaigns: self.campaigns.values().cloned().collect(),
            crashes: self.crashes.clone(),
        }
    }
    
    /// Import manager data
    pub fn import_data(&mut self, export: ManagerExport) {
        self.targets.clear();
        for target in export.targets {
            self.targets.insert(target.id.clone(), target);
        }
        
        self.corpora.clear();
        for corpus in export.corpora {
            self.corpora.insert(corpus.id.clone(), corpus);
        }
        
        self.campaigns.clear();
        for campaign in export.campaigns {
            self.campaigns.insert(campaign.id.clone(), campaign);
        }
        
        self.crashes = export.crashes;
        self.update_statistics();
    }
}

/// Manager export data
#[derive(Debug, Clone)]
pub struct ManagerExport {
    /// Targets
    pub targets: Vec<FuzzTarget>,
    /// Corpora
    pub corpora: Vec<Corpus>,
    /// Campaigns
    pub campaigns: Vec<Campaign>,
    /// Crashes
    pub crashes: Vec<Crash>,
}
