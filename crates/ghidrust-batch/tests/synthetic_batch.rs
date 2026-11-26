use ghidrust_batch::BatchEngine;
use std::path::PathBuf;

#[test]
fn progressive_synthetic_batches_stream_to_disk() {
    let root = tempfile::tempdir().unwrap();
    let worker = PathBuf::from(env!("CARGO_BIN_EXE_ghidrust-batch-worker"));
    for count in [1usize, 8, 32] {
        let output = root.path().join(format!("run-{count}"));
        let result =
            BatchEngine::run_synthetic_benchmark(worker.clone(), output.clone(), count, 2, 4.0)
                .expect("protected synthetic batch run");
        assert_eq!(result.attempted, count);
        assert_eq!(result.succeeded, count);
        assert_eq!(result.failed, 0);
        let rows = std::fs::read_to_string(output.join("synthetic.jsonl")).unwrap();
        assert_eq!(rows.lines().count(), count);
        println!(
            "synthetic_count={count} elapsed_ms={:.2} peak_private_commit_mb={:.1} workers={}",
            result.total_wall_ms, result.peak_committed_mb, result.workers
        );
    }
}
