//! Bounded, streaming batch decompilation with persistent isolated workers.

use crate::checkpoint::Checkpoint;
use crate::function_filter::{FunctionFilter, FunctionStartAnalysis};
use crate::job::{self, WorkerJob};
use crate::memory;
use crate::output::{OutputFormat, OutputWriter};
use crate::worker::{WorkerRequest, WorkerResponse};
use crossbeam_channel::{bounded, Receiver};
use ghidrust_core::{
    disassemble_range, load_path, run_analyzers, FunctionInfo, Instruction, Program,
};
use ghidrust_decomp::{structure_hints_from, EmitHints};
use ghidrust_structure::StructureHints;
use ghidrust_types::CallConv;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

const DEFAULT_BUDGET_GIB: f64 = 4.0;
const MIN_WORKER_RESERVE: u64 = 512 * 1024 * 1024;
const MAX_WORKERS: usize = 16;

/// Configuration for a protected batch run.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub binary_path: PathBuf,
    /// 0 selects a memory-aware count. The hard budget is shared by every worker.
    pub workers: usize,
    pub memory_budget_gb: f64,
    pub output_dir: PathBuf,
    pub checkpoint_path: Option<PathBuf>,
    pub format: OutputFormat,
    /// Resume automatically when a matching checkpoint exists.
    pub resume: bool,
    pub filter: FunctionFilter,
    pub max_insns_per_fn: usize,
    pub conv: CallConv,
    /// Override used by integration tests; production resolves the sibling worker binary.
    pub worker_executable: Option<PathBuf>,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            binary_path: PathBuf::new(),
            workers: 0,
            memory_budget_gb: DEFAULT_BUDGET_GIB,
            output_dir: PathBuf::from("batch_output"),
            checkpoint_path: None,
            format: OutputFormat::Jsonl,
            resume: true,
            filter: FunctionFilter::default(),
            max_insns_per_fn: 4096,
            conv: CallConv::Windows,
            worker_executable: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionOutcome {
    pub address: u64,
    pub name: String,
    pub pseudo_c: Option<String>,
    pub error: Option<String>,
    pub insn_count: usize,
    pub decompile_us: u128,
    pub goto_count: usize,
    pub leaf_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    pub binary: String,
    pub total_functions: usize,
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped_checkpoint: usize,
    pub skipped_filter: usize,
    pub total_wall_ms: f64,
    pub total_decompile_us: u128,
    pub throughput_fn_per_sec: f64,
    pub peak_committed_mb: f64,
    pub workers: usize,
    pub function_analysis: Option<FunctionStartAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticTask {
    pub address: u64,
    pub name: String,
    pub instructions: Vec<Instruction>,
}

struct WorkerProcess {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

struct BatchTask {
    function: FunctionInfo,
    prepared: Option<Vec<Instruction>>,
}

impl WorkerProcess {
    fn spawn(path: &Path, job: &WorkerJob) -> Result<Self, String> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start batch worker {}: {e}", path.display()))?;
        if let Err(e) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        let input = child.stdin.take().ok_or("worker stdin unavailable")?;
        let output = child.stdout.take().ok_or("worker stdout unavailable")?;
        Ok(Self {
            child,
            input,
            output: BufReader::new(output),
        })
    }

    fn execute(&mut self, request: &WorkerRequest) -> Result<WorkerResponse, String> {
        serde_json::to_writer(&mut self.input, request).map_err(|e| e.to_string())?;
        self.input.write_all(b"\n").map_err(|e| e.to_string())?;
        self.input.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        if self
            .output
            .read_line(&mut line)
            .map_err(|e| e.to_string())?
            == 0
        {
            let status = self.child.try_wait().ok().flatten();
            return Err(format!("worker exited before response ({status:?})"));
        }
        serde_json::from_str(&line).map_err(|e| format!("invalid worker response: {e}"))
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        let _ = self.input.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct BatchEngine {
    config: BatchConfig,
}

impl BatchEngine {
    pub fn new(config: BatchConfig) -> Self {
        Self { config }
    }

    pub fn run(&self) -> Result<BatchResult, String> {
        let started = Instant::now();
        validate_budget(self.config.memory_budget_gb)?;
        job::verify_supervisor_budget(self.config.memory_budget_gb)?;

        let fingerprint = fingerprint_file(&self.config.binary_path)?;
        let mut program = load_path(&self.config.binary_path).map_err(|e| format!("load: {e}"))?;
        run_analyzers(&mut program, &[]).map_err(|e| format!("analysis: {e}"))?;
        let analysis = FunctionStartAnalysis::analyze(&program.analysis.functions);
        let all_functions = program.analysis.functions.len();
        let selected = self.config.filter.apply(&program.analysis.functions);
        let skipped_filter = all_functions.saturating_sub(selected.len());
        let hints = structure_hints_from(&program);
        let emit_hints = EmitHints::from_program(&program);

        let checkpoint_path = self
            .config
            .checkpoint_path
            .clone()
            .unwrap_or_else(|| self.config.output_dir.join("batch_checkpoint.txt"));
        let resume_existing = checkpoint_path.exists();
        let mut checkpoint = Checkpoint::new(&checkpoint_path, fingerprint.clone());
        if self.config.resume || resume_existing {
            checkpoint
                .load()
                .map_err(|e| format!("checkpoint does not match input or is corrupt: {e}"))?;
        }
        let skipped_checkpoint = checkpoint.completed_count();
        checkpoint
            .open_for_append()
            .map_err(|e| format!("checkpoint open: {e}"))?;
        let targets: Vec<FunctionInfo> = selected
            .into_iter()
            .filter(|f| !checkpoint.is_completed(f.entry))
            .cloned()
            .collect();
        let attempted = targets.len();
        let output_path = self.output_path(&program.name);
        let mut output = if resume_existing && self.config.resume {
            OutputWriter::open_append(&output_path, self.config.format)
        } else {
            OutputWriter::open(&output_path, self.config.format)
        }
        .map_err(|e| format!("output open: {e}"))?;

        let workers = choose_workers(self.config.workers, self.config.memory_budget_gb)?;
        if attempted == 0 {
            output.finish().map_err(|e| e.to_string())?;
            return Ok(self.result(
                program.name,
                all_functions,
                0,
                0,
                skipped_checkpoint,
                skipped_filter,
                started,
                0,
                0,
                0,
                analysis,
                workers,
            ));
        }

        let worker_path = self.worker_path()?;
        let worker_job = WorkerJob::create(self.config.memory_budget_gb)?;
        let program = Arc::new(program);
        let target_rx = {
            let (tx, rx) = bounded::<BatchTask>(workers * 2);
            std::thread::spawn(move || {
                for target in targets {
                    if tx
                        .send(BatchTask {
                            function: target,
                            prepared: None,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            });
            rx
        };
        let (result_tx, result_rx) = bounded::<FunctionOutcome>(workers * 2);
        for _ in 0..workers {
            let rx = target_rx.clone();
            let tx = result_tx.clone();
            let program = Arc::clone(&program);
            let hints = hints.clone();
            let emit_hints = emit_hints.clone();
            let worker_path = worker_path.clone();
            let worker_job = worker_job.clone_handle();
            let max_insns = self.config.max_insns_per_fn;
            let conv = self.config.conv;
            std::thread::Builder::new()
                .name("ghidrust-batch-worker-io".into())
                .spawn(move || {
                    worker_loop(
                        rx,
                        tx,
                        program,
                        hints,
                        emit_hints,
                        worker_path,
                        worker_job,
                        max_insns,
                        conv,
                    )
                })
                .map_err(|e| format!("worker controller thread: {e}"))?;
        }
        drop(result_tx);

        let mut succeeded = 0usize;
        let mut failed = 0usize;
        let mut total_us = 0u128;
        let mut peak_committed = memory::current_committed_bytes();
        for outcome in result_rx {
            total_us = total_us.saturating_add(outcome.decompile_us);
            if outcome.error.is_none() {
                succeeded += 1;
                output
                    .write_outcome(&outcome)
                    .map_err(|e| format!("output write: {e}"))?;
                checkpoint
                    .record(outcome.address)
                    .map_err(|e| format!("checkpoint write: {e}"))?;
            } else {
                failed += 1;
                output
                    .write_outcome(&outcome)
                    .map_err(|e| format!("output write: {e}"))?;
            }
            peak_committed = peak_committed.max(memory::current_committed_bytes());
        }
        output
            .finish()
            .map_err(|e| format!("output finalize: {e}"))?;
        Ok(self.result(
            program.name.clone(),
            all_functions,
            attempted,
            succeeded,
            skipped_checkpoint,
            skipped_filter,
            started,
            total_us,
            peak_committed,
            failed,
            analysis,
            workers,
        ))
    }

    fn result(
        &self,
        binary: String,
        total_functions: usize,
        attempted: usize,
        succeeded: usize,
        skipped_checkpoint: usize,
        skipped_filter: usize,
        started: Instant,
        total_us: u128,
        peak: u64,
        failed: usize,
        analysis: FunctionStartAnalysis,
        workers: usize,
    ) -> BatchResult {
        let ms = started.elapsed().as_secs_f64() * 1000.0;
        BatchResult {
            binary,
            total_functions,
            attempted,
            succeeded,
            failed,
            skipped_checkpoint,
            skipped_filter,
            total_wall_ms: ms,
            total_decompile_us: total_us,
            throughput_fn_per_sec: if ms > 0.0 {
                attempted as f64 / (ms / 1000.0)
            } else {
                0.0
            },
            peak_committed_mb: peak as f64 / 1_048_576.0,
            workers,
            function_analysis: Some(analysis),
        }
    }

    fn output_path(&self, name: &str) -> PathBuf {
        let ext = match self.config.format {
            OutputFormat::Jsonl => "jsonl",
            OutputFormat::CFile => "c",
        };
        self.config
            .output_dir
            .join(format!("{}.{ext}", name.replace('.', "_")))
    }

    fn worker_path(&self) -> Result<PathBuf, String> {
        if let Some(path) = &self.config.worker_executable {
            return Ok(path.clone());
        }
        let current = std::env::current_exe().map_err(|e| format!("current executable: {e}"))?;
        Ok(current.with_file_name(if cfg!(windows) {
            "ghidrust-batch-worker.exe"
        } else {
            "ghidrust-batch-worker"
        }))
    }

    /// Run a small synthetic workload through the same persistent workers and disk writer.
    /// Used for progressive, redistributable memory/performance checks.
    #[doc(hidden)]
    pub fn run_synthetic_benchmark(
        worker: PathBuf,
        output_dir: PathBuf,
        count: usize,
        workers: usize,
        budget_gb: f64,
    ) -> Result<BatchResult, String> {
        validate_budget(budget_gb)?;
        job::verify_supervisor_budget(budget_gb)?;
        let started = Instant::now();
        let worker_job = WorkerJob::create(budget_gb)?;
        let worker_count = choose_workers(workers, budget_gb)?;
        let (task_tx, task_rx) = bounded::<BatchTask>(worker_count * 2);
        let synthetic_program = Arc::new(Program::new("synthetic".into(), "raw"));
        let hints = StructureHints::default();
        let (result_tx, result_rx) = bounded::<FunctionOutcome>(worker_count * 2);
        for _ in 0..worker_count {
            let rx = task_rx.clone();
            let tx = result_tx.clone();
            let program = Arc::clone(&synthetic_program);
            let hints = hints.clone();
            let emit_hints = EmitHints::default();
            let path = worker.clone();
            let job = worker_job.clone_handle();
            std::thread::spawn(move || {
                worker_loop(
                    rx,
                    tx,
                    program,
                    hints,
                    emit_hints,
                    path,
                    job,
                    64,
                    CallConv::Windows,
                )
            });
        }
        drop(result_tx);
        let instructions = vec![Instruction::with_text(0x1000, vec![0xc3], "ret", "", 1)];
        let synthetic_insn_count = instructions.len();
        let tasks: Vec<_> = (0..count)
            .map(|i| {
                FunctionInfo::new(
                    0x1000 + i as u64,
                    0x1001 + i as u64,
                    format!("synthetic_{i}"),
                )
            })
            .collect();
        let producer = std::thread::spawn(move || {
            for task in tasks {
                if task_tx
                    .send(BatchTask {
                        function: task,
                        prepared: Some(instructions.clone()),
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        std::fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
        let mut output =
            OutputWriter::open(output_dir.join("synthetic.jsonl"), OutputFormat::Jsonl)
                .map_err(|e| e.to_string())?;
        let mut succeeded = 0;
        let mut failed = 0;
        let mut total_us = 0u128;
        let mut peak = memory::current_committed_bytes();
        for mut outcome in result_rx {
            if outcome.insn_count == 0 {
                outcome.insn_count = synthetic_insn_count;
            }
            total_us += outcome.decompile_us;
            if outcome.error.is_some() {
                failed += 1;
            } else {
                succeeded += 1;
            }
            output.write_outcome(&outcome).map_err(|e| e.to_string())?;
            peak = peak.max(memory::current_committed_bytes());
        }
        producer
            .join()
            .map_err(|_| "synthetic task producer panicked")?;
        output.finish().map_err(|e| e.to_string())?;
        let ms = started.elapsed().as_secs_f64() * 1000.0;
        Ok(BatchResult {
            binary: "synthetic".into(),
            total_functions: count,
            attempted: count,
            succeeded,
            failed,
            skipped_checkpoint: 0,
            skipped_filter: 0,
            total_wall_ms: ms,
            total_decompile_us: total_us,
            throughput_fn_per_sec: if ms > 0.0 {
                count as f64 / (ms / 1000.0)
            } else {
                0.0
            },
            peak_committed_mb: peak as f64 / 1_048_576.0,
            workers: worker_count,
            function_analysis: None,
        })
    }
}

fn worker_loop(
    rx: Receiver<BatchTask>,
    tx: crossbeam_channel::Sender<FunctionOutcome>,
    program: Arc<Program>,
    hints: StructureHints,
    emit_hints: EmitHints,
    path: PathBuf,
    job: WorkerJob,
    max_insns: usize,
    conv: CallConv,
) {
    let mut child = WorkerProcess::spawn(&path, &job).ok();
    let mut consecutive_failures = 0usize;
    while let Ok(task) = rx.recv() {
        let function = task.function;
        let start = Instant::now();
        let decoded = match task.prepared {
            Some(instructions) => Ok(instructions),
            None => disassemble_range(&program, function.entry, max_insns)
                .map_err(|e| format!("disassembly: {e}")),
        };
        let result = match decoded {
            Ok(instructions) => {
                let count = instructions.len();
                let request = WorkerRequest {
                    entry: function.entry,
                    name: function.name.clone(),
                    instructions,
                    conv,
                    hints: hints.clone(),
                    emit_hints: emit_hints.clone(),
                };
                let response = child
                    .as_mut()
                    .ok_or_else(|| "worker unavailable".to_string())
                    .and_then(|worker| worker.execute(&request));
                response.map(|r| {
                    consecutive_failures = 0;
                    r.into_outcome(count)
                })
            }
            Err(error) => Err(error),
        };
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                consecutive_failures += 1;
                child.take();
                if consecutive_failures <= 3 {
                    child = WorkerProcess::spawn(&path, &job).ok();
                }
                FunctionOutcome {
                    address: function.entry,
                    name: function.name,
                    pseudo_c: None,
                    error: Some(error),
                    insn_count: 0,
                    decompile_us: start.elapsed().as_micros(),
                    goto_count: 0,
                    leaf_count: 0,
                }
            }
        };
        if tx.send(outcome).is_err() {
            break;
        }
    }
}

fn validate_budget(gib: f64) -> Result<(), String> {
    if !gib.is_finite() || !(0.5..=4.0).contains(&gib) {
        return Err("memory budget must be between 0.5 and 4 GiB".into());
    }
    Ok(())
}

fn choose_workers(requested: usize, budget_gib: f64) -> Result<usize, String> {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let system_spare =
        memory::system_commit_spare_bytes().ok_or("cannot read Windows system commit")?;
    let worker_budget = (budget_gib * 1024f64.powi(3)) as u64;
    let by_budget = (worker_budget / MIN_WORKER_RESERVE).max(1) as usize;
    let by_system = (system_spare / MIN_WORKER_RESERVE).max(1) as usize;
    let cap = cores.min(MAX_WORKERS).min(by_budget).min(by_system);
    Ok(if requested == 0 {
        cap.max(1)
    } else {
        requested.min(cap).max(1)
    })
}

fn fingerprint_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("input open: {e}"))?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let read =
            std::io::Read::read(&mut file, &mut buf).map_err(|e| format!("input hash: {e}"))?;
        if read == 0 {
            break;
        }
        hash.update(&buf[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_worker_count_is_capped_by_budget() {
        assert_eq!(validate_budget(4.0), Ok(()));
        assert!(validate_budget(24.0).is_err());
        assert!(validate_budget(f64::NAN).is_err());
    }
}
