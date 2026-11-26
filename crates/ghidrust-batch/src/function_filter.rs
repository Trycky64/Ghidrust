//! Function filtering and quality analysis for batch decompilation.

use ghidrust_core::program::FunctionInfo;

/// Filters for selecting which functions to decompile.
#[derive(Debug, Clone)]
pub struct FunctionFilter {
    /// Minimum function size in bytes (entry..end). Functions smaller than this
    /// are skipped. Useful for filtering false positives from function-start search.
    pub min_function_size: u64,
    /// Maximum number of functions to process (0 = unlimited).
    pub max_functions: usize,
    /// When non-empty, only these exact function entry addresses are selected.
    pub addresses: Vec<u64>,
}

impl Default for FunctionFilter {
    fn default() -> Self {
        Self {
            min_function_size: 0,
            max_functions: 0,
            addresses: Vec::new(),
        }
    }
}

impl FunctionFilter {
    /// Apply filter to a list of functions, returning those that pass.
    pub fn apply<'a>(&self, functions: &'a [FunctionInfo]) -> Vec<&'a FunctionInfo> {
        let mut result: Vec<&FunctionInfo> = functions
            .iter()
            .filter(|f| {
                let size = f.end.saturating_sub(f.entry);
                size >= self.min_function_size
                    && (self.addresses.is_empty() || self.addresses.contains(&f.entry))
            })
            .collect();
        if self.max_functions > 0 {
            result.truncate(self.max_functions);
        }
        result
    }
}

/// Analyze function-start quality: detect suspiciously close or overlapping entries.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionStartAnalysis {
    pub total_functions: usize,
    pub min_size_bytes: u64,
    pub max_size_bytes: u64,
    pub median_size_bytes: u64,
    pub mean_size_bytes: f64,
    /// Functions with size < 2 bytes (likely false positives or padding).
    pub sub_2byte_count: usize,
    /// Functions with size < 5 bytes (single-instruction stubs or padding).
    pub sub_5byte_count: usize,
    /// Functions with size < 16 bytes.
    pub sub_16byte_count: usize,
    /// Pairs of functions whose entries are <= 1 byte apart.
    pub overlapping_pairs: usize,
    /// Size distribution buckets: [0-1], [2-4], [5-15], [16-63], [64-255],
    /// [256-1023], [1024-4095], [4096+].
    pub size_buckets: [usize; 8],
}

impl FunctionStartAnalysis {
    /// Analyze a function list for start-search quality.
    pub fn analyze(functions: &[FunctionInfo]) -> Self {
        if functions.is_empty() {
            return Self {
                total_functions: 0,
                min_size_bytes: 0,
                max_size_bytes: 0,
                median_size_bytes: 0,
                mean_size_bytes: 0.0,
                sub_2byte_count: 0,
                sub_5byte_count: 0,
                sub_16byte_count: 0,
                overlapping_pairs: 0,
                size_buckets: [0; 8],
            };
        }

        let mut sizes: Vec<u64> = functions
            .iter()
            .map(|f| f.end.saturating_sub(f.entry))
            .collect();
        sizes.sort_unstable();

        let total = sizes.len();
        let min_size = sizes[0];
        let max_size = sizes[total - 1];
        let median = sizes[total / 2];
        let mean = sizes.iter().sum::<u64>() as f64 / total as f64;

        let sub_2 = sizes.iter().filter(|&&s| s < 2).count();
        let sub_5 = sizes.iter().filter(|&&s| s < 5).count();
        let sub_16 = sizes.iter().filter(|&&s| s < 16).count();

        // Check for overlapping/adjacent entries.
        let mut entries: Vec<u64> = functions.iter().map(|f| f.entry).collect();
        entries.sort_unstable();
        let overlapping = entries.windows(2).filter(|w| w[1] - w[0] <= 1).count();

        let mut buckets = [0usize; 8];
        for &s in &sizes {
            let idx = match s {
                0..=1 => 0,
                2..=4 => 1,
                5..=15 => 2,
                16..=63 => 3,
                64..=255 => 4,
                256..=1023 => 5,
                1024..=4095 => 6,
                _ => 7,
            };
            buckets[idx] += 1;
        }

        Self {
            total_functions: total,
            min_size_bytes: min_size,
            max_size_bytes: max_size,
            median_size_bytes: median,
            mean_size_bytes: mean,
            sub_2byte_count: sub_2,
            sub_5byte_count: sub_5,
            sub_16byte_count: sub_16,
            overlapping_pairs: overlapping,
            size_buckets: buckets,
        }
    }

    /// Human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "Function Start Analysis: {} functions\n\
             Size range: {} - {} bytes, median={}, mean={:.1}\n\
             Sub-2-byte (likely FP): {} ({:.1}%)\n\
             Sub-5-byte (stubs/padding): {} ({:.1}%)\n\
             Sub-16-byte: {} ({:.1}%)\n\
             Overlapping pairs (<=1 byte apart): {}\n\
             Buckets [0-1] [2-4] [5-15] [16-63] [64-255] [256-1K] [1K-4K] [4K+]:\n\
             {:?}",
            self.total_functions,
            self.min_size_bytes,
            self.max_size_bytes,
            self.median_size_bytes,
            self.mean_size_bytes,
            self.sub_2byte_count,
            pct(self.sub_2byte_count, self.total_functions),
            self.sub_5byte_count,
            pct(self.sub_5byte_count, self.total_functions),
            self.sub_16byte_count,
            pct(self.sub_16byte_count, self.total_functions),
            self.overlapping_pairs,
            self.size_buckets,
        )
    }
}

fn pct(n: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        n as f64 / total as f64 * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_exact_entry_addresses_and_composes_with_size_filter() {
        let functions = vec![
            FunctionInfo::new(0x1000, 0x1010, "small"),
            FunctionInfo::new(0x2000, 0x2100, "selected"),
            FunctionInfo::new(0x3000, 0x3100, "other"),
        ];
        let filter = FunctionFilter {
            min_function_size: 0x20,
            max_functions: 0,
            addresses: vec![0x1000, 0x2000],
        };
        let selected = filter.apply(&functions);
        assert_eq!(
            selected.iter().map(|f| f.entry).collect::<Vec<_>>(),
            [0x2000]
        );
    }
}
