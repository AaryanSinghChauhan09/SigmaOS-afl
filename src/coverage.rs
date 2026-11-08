//! Coverage tracking for fuzzing.

use std::collections::HashSet;

/// Coverage edge
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct CoverageEdge {
    /// Source address
    pub src: u64,
    /// Destination address
    pub dst: u64,
}

impl CoverageEdge {
    /// Create new coverage edge
    pub fn new(src: u64, dst: u64) -> Self {
        Self { src, dst }
    }
}

/// Coverage stats
#[derive(Debug, Clone)]
pub struct CoverageStats {
    /// Total edges
    pub total_edges: usize,
    /// Covered edges
    pub covered_edges: usize,
    /// Coverage percentage
    pub coverage_percent: f64,
    /// Unique edges hit
    pub unique_edges: usize,
}

/// Coverage map
#[derive(Debug, Clone)]
pub struct CoverageMap {
    /// Coverage edges
    pub edges: HashSet<CoverageEdge>,
    /// Hit counts per edge
    pub hit_counts: std::collections::HashMap<CoverageEdge, u64>,
    /// Total possible edges
    pub total_possible: usize,
    /// Created timestamp
    pub created_at: u64,
}

impl CoverageMap {
    /// Create new coverage map
    pub fn new() -> Self {
        Self {
            edges: HashSet::new(),
            hit_counts: std::collections::HashMap::new(),
            total_possible: 0,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Add edge
    pub fn add_edge(&mut self, edge: CoverageEdge) {
        self.edges.insert(edge.clone());
        self.hit_counts.entry(edge).or_insert(0);
    }
    
    /// Record edge hit
    pub fn record_hit(&mut self, edge: &CoverageEdge) {
        *self.hit_counts.entry(edge.clone()).or_insert(0) += 1;
        self.edges.insert(edge.clone());
    }
    
    /// Check if edge exists
    pub fn has_edge(&self, edge: &CoverageEdge) -> bool {
        self.edges.contains(edge)
    }
    
    /// Get hit count for edge
    pub fn get_hit_count(&self, edge: &CoverageEdge) -> u64 {
        self.hit_counts.get(edge).copied().unwrap_or(0)
    }
    
    /// Set total possible edges
    pub fn set_total_possible(&mut self, total: usize) {
        self.total_possible = total;
    }
    
    /// Get stats
    pub fn get_stats(&self) -> CoverageStats {
        let covered = self.edges.len();
        let coverage_percent = if self.total_possible > 0 {
            (covered as f64 / self.total_possible as f64) * 100.0
        } else {
            0.0
        };
        
        CoverageStats {
            total_edges: self.total_possible,
            covered_edges: covered,
            coverage_percent,
            unique_edges: covered,
        }
    }
    
    /// Clear coverage
    pub fn clear(&mut self) {
        self.edges.clear();
        self.hit_counts.clear();
    }
    
    /// Get edge count
    pub fn get_edge_count(&self) -> usize {
        self.edges.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }
    
    /// Get coverage map age in seconds
    pub fn get_age_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - self.created_at
    }
}

impl Default for CoverageMap {
    fn default() -> Self {
        Self::new()
    }
}
