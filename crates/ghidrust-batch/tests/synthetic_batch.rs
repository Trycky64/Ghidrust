use ghidrust_batch::FunctionFilter;
use ghidrust_batch::{BatchConfig, BatchEngine};
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
        assert!(
            result.peak_committed_mb > 1.0,
            "private commit measurement unavailable"
        );
        let rows = std::fs::read_to_string(output.join("synthetic.jsonl")).unwrap();
        assert_eq!(rows.lines().count(), count);
        println!(
            "synthetic_count={count} elapsed_ms={:.2} peak_private_commit_mb={:.1} workers={}",
            result.total_wall_ms, result.peak_committed_mb, result.workers
        );
    }
}

#[test]
fn full_pipeline_filters_by_address_and_resumes_matching_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("synthetic-pe.exe");
    std::fs::write(&input, synthetic_pe()).unwrap();
    let worker = PathBuf::from(env!("CARGO_BIN_EXE_ghidrust-batch-worker"));
    let mut config = BatchConfig {
        binary_path: input.clone(),
        workers: 1,
        output_dir: root.path().join("out"),
        worker_executable: Some(worker.clone()),
        filter: FunctionFilter {
            min_function_size: 0,
            max_functions: 0,
            addresses: vec![0x1400_01000],
        },
        resume: false,
        ..BatchConfig::default()
    };
    let first = BatchEngine::new(config.clone())
        .run()
        .expect("full synthetic PE pipeline");
    assert!(first.total_functions >= 1);
    assert_eq!(first.attempted, 1);
    assert_eq!(first.succeeded, 1);
    assert_eq!(first.failed, 0);
    let output_path = config.output_dir.join("synthetic-pe_exe.jsonl");
    assert_eq!(
        std::fs::read_to_string(output_path)
            .unwrap()
            .lines()
            .count(),
        1
    );

    config.resume = true;
    let resumed = BatchEngine::new(config)
        .run()
        .expect("resume synthetic PE pipeline");
    assert_eq!(resumed.skipped_checkpoint, 1);
    assert_eq!(resumed.attempted, 0);
}

fn synthetic_pe() -> Vec<u8> {
    let mut data = vec![0u8; 0x800];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
    let opt = coff + 20;
    data[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    data[opt + 24..opt + 32].copy_from_slice(&0x1400_00000u64.to_le_bytes());
    data[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
    let exception = opt + 112 + 3 * 8;
    data[exception..exception + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    data[exception + 4..exception + 8].copy_from_slice(&12u32.to_le_bytes());
    let section = opt + 0xf0;
    write_section(
        &mut data,
        section,
        b".text\0\0\0",
        0x1000,
        0x1000,
        0x200,
        0x400,
        0x6000_0020,
    );
    write_section(
        &mut data,
        section + 40,
        b".pdata\0\0",
        0x1000,
        0x2000,
        0x200,
        0x600,
        0x4000_0040,
    );
    data[0x400..0x408].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3]);
    data[0x600..0x604].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0x604..0x608].copy_from_slice(&0x1008u32.to_le_bytes());
    data[0x608..0x60c].copy_from_slice(&0x200cu32.to_le_bytes());
    data[0x60c] = 1;
    data[0x60d] = 4;
    data
}

fn write_section(
    data: &mut [u8],
    offset: usize,
    name: &[u8; 8],
    vsize: u32,
    va: u32,
    raw_size: u32,
    file_offset: u32,
    characteristics: u32,
) {
    data[offset..offset + 8].copy_from_slice(name);
    data[offset + 8..offset + 12].copy_from_slice(&vsize.to_le_bytes());
    data[offset + 12..offset + 16].copy_from_slice(&va.to_le_bytes());
    data[offset + 16..offset + 20].copy_from_slice(&raw_size.to_le_bytes());
    data[offset + 20..offset + 24].copy_from_slice(&file_offset.to_le_bytes());
    data[offset + 36..offset + 40].copy_from_slice(&characteristics.to_le_bytes());
}

#[test]
#[cfg(feature = "test-worker-crash")]
fn crashed_worker_is_reported_and_replaced() {
    let root = tempfile::tempdir().unwrap();
    let result = BatchEngine::run_synthetic_worker_crash_test(
        PathBuf::from(env!("CARGO_BIN_EXE_ghidrust-batch-worker")),
        root.path().to_path_buf(),
        5,
        1,
        4.0,
    )
    .expect("worker crash recovery run");
    assert_eq!(result.attempted, 5);
    assert_eq!(result.failed, 1);
    assert_eq!(result.succeeded, 4);
    let rows = std::fs::read_to_string(root.path().join("synthetic.jsonl")).unwrap();
    assert_eq!(rows.lines().count(), 5);
}
