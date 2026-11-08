//! SigmaOS-afl — American Fuzzy Lop fuzzing component.
//!
//! Models fuzz targets, input corpora, mutation strategies, coverage
//! tracking, crash deduplication, and fuzzing campaign management.

pub mod target;
pub mod corpus;
pub mod mutation;
pub mod coverage;
pub mod crash;
pub mod campaign;
pub mod manager;
pub mod options;

pub use target::{FuzzTarget, TargetConfig, TargetState};
pub use corpus::{Corpus, CorpusEntry, CorpusStats};
pub use mutation::{Mutator, MutationStrategy, MutationOp};
pub use coverage::{CoverageMap, CoverageEdge, CoverageStats};
pub use crash::{Crash, CrashType, CrashSeverity, CrashDedup};
pub use campaign::{Campaign, CampaignState, CampaignConfig, CampaignStats};
pub use manager::{FuzzManager, ManagerOptions, ManagerStatistics};
pub use options::{Mode, Options};

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_target_state() {
        let states = vec![
            TargetState::Idle,
            TargetState::Fuzzing,
            TargetState::Paused,
            TargetState::Completed,
            TargetState::Error,
        ];
        assert_eq!(states.len(), 5);
    }
    
    #[test]
    fn test_mutation_strategy() {
        let strategies = vec![
            MutationStrategy::BitFlip,
            MutationStrategy::ByteFlip,
            MutationStrategy::Arithmetic,
            MutationStrategy::Dictionary,
            MutationStrategy::Splice,
            MutationStrategy::Havoc,
        ];
        assert_eq!(strategies.len(), 6);
    }
    
    #[test]
    fn test_crash_type() {
        let types = vec![
            CrashType::Segfault,
            CrashType::Abort,
            CrashType::Timeout,
            CrashType::OOM,
            CrashType::Assert,
            CrashType::Leak,
        ];
        assert_eq!(types.len(), 6);
    }
    
    #[test]
    fn test_campaign_state() {
        let states = vec![
            CampaignState::Idle,
            CampaignState::Running,
            CampaignState::Paused,
            CampaignState::Completed,
            CampaignState::Failed,
        ];
        assert_eq!(states.len(), 5);
    }
    
    #[test]
    fn test_target_creation() {
        let target = FuzzTarget::new("target-1".into(), "/bin/test".into());
        assert_eq!(target.id, "target-1");
        assert_eq!(target.binary_path, "/bin/test");
        assert_eq!(target.state, TargetState::Idle);
    }
    
    #[test]
    fn test_target_config() {
        let mut config = TargetConfig::default();
        config.timeout_ms = 1000;
        config.max_len = 4096;
        config.memory_limit_mb = 512;
        
        assert_eq!(config.timeout_ms, 1000);
        assert_eq!(config.max_len, 4096);
    }
    
    #[test]
    fn test_corpus_creation() {
        let corpus = Corpus::new("corpus-1".into());
        assert_eq!(corpus.id, "corpus-1");
        assert!(corpus.entries.is_empty());
    }
    
    #[test]
    fn test_corpus_entry() {
        let entry = CorpusEntry::new(vec![0x41, 0x42, 0x43]);
        assert_eq!(entry.data, vec![0x41, 0x42, 0x43]);
        assert_eq!(entry.exec_count, 0);
        assert!(entry.interesting);
    }
    
    #[test]
    fn test_mutator_creation() {
        let mutator = Mutator::new();
        assert!(mutator.strategies.is_empty());
    }
    
    #[test]
    fn test_mutation() {
        let mut mutator = Mutator::new();
        mutator.add_strategy(MutationStrategy::BitFlip);
        
        let input = vec![0xFF, 0x00, 0xAA];
        let mutations = mutator.mutate(&input, 5);
        
        assert_eq!(mutations.len(), 5);
        assert!(mutations.iter().all(|m| m.len() <= input.len() + 4));
    }
    
    #[test]
    fn test_coverage_map() {
        let mut coverage = CoverageMap::new();
        coverage.add_edge(CoverageEdge::new(0x1000, 0x2000));
        coverage.add_edge(CoverageEdge::new(0x2000, 0x3000));
        
        assert_eq!(coverage.edges.len(), 2);
        assert!(coverage.has_edge(&CoverageEdge::new(0x1000, 0x2000)));
    }
    
    #[test]
    fn test_crash_creation() {
        let crash = Crash::new("crash-1".into(), CrashType::Segfault);
        assert_eq!(crash.id, "crash-1");
        assert_eq!(crash.crash_type, CrashType::Segfault);
        assert_eq!(crash.severity, CrashSeverity::Medium);
    }
    
    #[test]
    fn test_crash_dedup() {
        let mut dedup = CrashDedup::new();
        let crash1 = Crash::new("c1".into(), CrashType::Segfault);
        let crash2 = Crash::new("c2".into(), CrashType::Segfault);
        
        // Same crash type with same input should deduplicate
        let is_dup = dedup.is_duplicate(&crash1, &crash2);
        assert!(is_dup);
    }
    
    #[test]
    fn test_campaign_creation() {
        let campaign = Campaign::new("campaign-1".into());
        assert_eq!(campaign.id, "campaign-1");
        assert_eq!(campaign.state, CampaignState::Idle);
    }
    
    #[test]
    fn test_campaign_config() {
        let mut config = CampaignConfig::default();
        config.max_iterations = 10000;
        config.max_time_seconds = 3600;
        config.target_coverage = 0.8;
        
        assert_eq!(config.max_iterations, 10000);
        assert_eq!(config.max_time_seconds, 3600);
        assert_eq!(config.target_coverage, 0.8);
    }
    
    #[test]
    fn test_manager_creation() {
        let mut manager = FuzzManager::new();
        assert!(manager.list_targets().is_empty());
        assert!(manager.list_campaigns().is_empty());
    }
    
    #[test]
    fn test_add_target() {
        let mut manager = FuzzManager::new();
        let target_id = manager.add_target("test".into(), "/bin/test".into());
        
        assert!(manager.get_target(&target_id).is_some());
        assert_eq!(manager.list_targets().len(), 1);
    }
    
    #[test]
    fn test_create_campaign() {
        let mut manager = FuzzManager::new();
        let target_id = manager.add_target("test".into(), "/bin/test".into());
        let campaign_id = manager.create_campaign(&target_id, "campaign".into());
        
        assert!(campaign_id.is_some());
        assert!(manager.get_campaign(campaign_id.as_ref().unwrap()).is_some());
    }
    
    #[test]
    fn test_start_campaign() {
        let mut manager = FuzzManager::new();
        let target_id = manager.add_target("test".into(), "/bin/test".into());
        let campaign_id = manager.create_campaign(&target_id, "camp".into()).unwrap();
        
        assert!(manager.start_campaign(&campaign_id));
        assert_eq!(manager.get_campaign(&campaign_id).unwrap().state, CampaignState::Running);
    }
    
    #[test]
    fn test_stop_campaign() {
        let mut manager = FuzzManager::new();
        let target_id = manager.add_target("test".into(), "/bin/test".into());
        let campaign_id = manager.create_campaign(&target_id, "camp".into()).unwrap();
        manager.start_campaign(&campaign_id);
        
        assert!(manager.stop_campaign(&campaign_id));
        assert_eq!(manager.get_campaign(&campaign_id).unwrap().state, CampaignState::Completed);
    }
    
    #[test]
    fn test_add_crash() {
        let mut manager = FuzzManager::new();
        let crash = Crash::new("crash-1".into(), CrashType::Segfault);
        
        assert!(manager.add_crash(crash));
        assert_eq!(manager.list_crashes().len(), 1);
    }
    
    #[test]
    fn test_crash_deduplication() {
        let mut manager = FuzzManager::new();
        let crash1 = Crash::new("c1".into(), CrashType::Segfault);
        let mut crash2 = Crash::new("c2".into(), CrashType::Segfault);
        crash2.input = crash1.input.clone();
        
        manager.add_crash(crash1);
        // Duplicate should be rejected
        assert!(!manager.add_crash(crash2));
        assert_eq!(manager.list_crashes().len(), 1);
    }
    
    #[test]
    fn test_export_import() {
        let mut manager = FuzzManager::new();
        manager.add_target("t1".into(), "/bin/t1".into());
        
        let export = manager.export_data();
        
        let mut manager2 = FuzzManager::new();
        manager2.import_data(export);
        
        assert_eq!(manager2.list_targets().len(), 1);
    }
    
    #[test]
    fn test_manager_statistics() {
        let mut manager = FuzzManager::new();
        let target_id = manager.add_target("t1".into(), "/bin/t1".into());
        manager.create_campaign(&target_id, "c1".into());
        manager.add_crash(Crash::new("crash".into(), CrashType::Segfault));
        
        let stats = manager.get_statistics();
        assert_eq!(stats.total_targets, 1);
        assert_eq!(stats.total_campaigns, 1);
        assert_eq!(stats.total_crashes, 1);
    }
}
