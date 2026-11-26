//! Bounded, streaming batch decompilation with persistent isolated workers.

use crate::checkpoint::Checkpoint;
use crate::function_filter::{FunctionFilter, FunctionStartAnalysis};
use crate::job::{self, WorkerJob};
use crate::memory;
use crate::output::{completed_jsonl_addresses, OutputFormat, OutputWriter};
use crate::worker::{WorkerRequest, WorkerResponse, WorkerTelemetry};
use crossbeam_channel::{bounded, Receiver};
use ghidrust_core::disasm::DisasmSession;
use ghidrust_core::{load_path, run_analyzers, FunctionInfo, Instruction, Program};
use ghidrust_decomp::{structure_hints_from, EmitHints};
use ghidrust_structure::StructureHints;
use ghidrust_types::CallConv;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver as StdReceiver};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

const DEFAULT_BUDGET_GIB: f64 = 4.0;
const MIN_WORKER_RESERVE: u64 = 512 * 1024 * 1024;
const MAX_WORKERS: usize = 16;
const MAX_WORKER_FRAME_BYTES: usize = 128 * 1024 * 1024;

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
    pub function_timeout: Duration,
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
            function_timeout: Duration::from_secs(120),
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
    pub requested_workers: usize,
    pub effective_workers: usize,
    pub load_ms: f64,
    pub fingerprint_ms: f64,
    pub analyzer_ms: f64,
    pub enumeration_ms: f64,
    pub disassembly_ms: f64,
    pub decoder_init_ms: f64,
    pub metadata_clone_ms: f64,
    pub ipc_serialize_ms: f64,
    pub ipc_write_ms: f64,
    pub ipc_wait_ms: f64,
    pub ipc_deserialize_ms: f64,
    pub ipc_request_deserialize_ms: f64,
    pub ipc_response_serialize_ms: f64,
    pub export_ms: f64,
    pub checkpoint_ms: f64,
    pub worker_start_ms: f64,
    pub worker_restart_start_ms: f64,
    pub worker_restarts: usize,
    pub system_commit_peak_mb: f64,
    pub cpu_utilization_pct: f64,
    pub function_analysis: Option<FunctionStartAnalysis>,
}

#[derive(Default)]
struct PhaseMetrics {
    disassembly_us: AtomicU64,
    decoder_init_us: AtomicU64,
    metadata_clone_us: AtomicU64,
    ipc_serialize_us: AtomicU64,
    ipc_write_us: AtomicU64,
    ipc_wait_us: AtomicU64,
    ipc_deserialize_us: AtomicU64,
    ipc_request_deserialize_us: AtomicU64,
    ipc_response_serialize_us: AtomicU64,
    worker_start_us: AtomicU64,
    worker_restart_start_us: AtomicU64,
    worker_restarts: AtomicU64,
}

fn add_us(counter: &AtomicU64, duration: std::time::Duration) {
    counter.fetch_add(
        duration.as_micros().min(u64::MAX as u128) as u64,
        Ordering::Relaxed,
    );
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
    output: StdReceiver<Result<(Vec<u8>, Vec<u8>), String>>,
    metadata_sent: bool,
    request_buffer: Vec<u8>,
}

struct BatchTask {
    function: FunctionInfo,
    prepared: Option<Vec<Instruction>>,
}

impl WorkerProcess {
    fn spawn(
        path: &Path,
        job: &WorkerJob,
        metrics: &PhaseMetrics,
        is_restart: bool,
    ) -> Result<Self, String> {
        let started = Instant::now();
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start batch worker {}: {e}", path.display()))?;
        if let Err(e) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        let input = child.stdin.take().ok_or("worker stdin unavailable")?;
        let mut output = child.stdout.take().ok_or("worker stdout unavailable")?;
        let (output_tx, output_rx) = mpsc::channel();
        std::thread::spawn(move || loop {
            let mut header = [0u8; 4];
            if let Err(error) = output.read_exact(&mut header) {
                if error.kind() != std::io::ErrorKind::UnexpectedEof {
                    let _ = output_tx.send(Err(error.to_string()));
                }
                break;
            }
            let len = u32::from_le_bytes(header) as usize;
            if len > MAX_WORKER_FRAME_BYTES {
                let _ = output_tx.send(Err(format!("worker response frame too large: {len}")));
                break;
            }
            let mut bytes = vec![0u8; len];
            if let Err(error) = output.read_exact(&mut bytes) {
                let _ = output_tx.send(Err(error.to_string()));
                break;
            }
            let mut telemetry_header = [0u8; 4];
            if let Err(error) = output.read_exact(&mut telemetry_header) {
                let _ = output_tx.send(Err(error.to_string()));
                break;
            }
            let telemetry_len = u32::from_le_bytes(telemetry_header) as usize;
            if telemetry_len > MAX_WORKER_FRAME_BYTES {
                let _ = output_tx.send(Err(format!(
                    "worker telemetry frame too large: {telemetry_len}"
                )));
                break;
            }
            let mut telemetry = vec![0u8; telemetry_len];
            if let Err(error) = output.read_exact(&mut telemetry) {
                let _ = output_tx.send(Err(error.to_string()));
                break;
            }
            if output_tx.send(Ok((bytes, telemetry))).is_err() {
                break;
            }
        });
        add_us(&metrics.worker_start_us, started.elapsed());
        if is_restart {
            add_us(&metrics.worker_restart_start_us, started.elapsed());
        }
        Ok(Self {
            child,
            input,
            output: output_rx,
            metadata_sent: false,
            request_buffer: Vec::with_capacity(64 * 1024),
        })
    }

    fn execute(
        &mut self,
        request: &WorkerRequest,
        metrics: &PhaseMetrics,
        timeout: Duration,
    ) -> Result<WorkerResponse, String> {
        let execution_started = Instant::now();
        let started = Instant::now();
        self.request_buffer.clear();
        self.request_buffer.extend_from_slice(&[0; 4]);
        bincode::serialize_into(&mut self.request_buffer, request).map_err(|e| e.to_string())?;
        let frame_len = self.request_buffer.len() - 4;
        if frame_len > MAX_WORKER_FRAME_BYTES || frame_len > u32::MAX as usize {
            return Err(format!("worker request frame too large: {frame_len}"));
        }
        self.request_buffer[..4].copy_from_slice(&(frame_len as u32).to_le_bytes());
        add_us(&metrics.ipc_serialize_us, started.elapsed());
        let started = Instant::now();
        self.input
            .write_all(&self.request_buffer)
            .map_err(|e| e.to_string())?;
        self.input.flush().map_err(|e| e.to_string())?;
        add_us(&metrics.ipc_write_us, started.elapsed());
        let started = Instant::now();
        let wait_timeout = timeout.saturating_sub(execution_started.elapsed());
        let (bytes, telemetry_bytes) = match self.output.recv_timeout(wait_timeout) {
            Ok(Ok(reply)) => reply,
            Ok(Err(error)) => return Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(format!(
                    "function timeout after {:.3}s",
                    timeout.as_secs_f64()
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let status = self.child.try_wait().ok().flatten();
                return Err(format!("worker exited before response ({status:?})"));
            }
        };
        add_us(&metrics.ipc_wait_us, started.elapsed());
        let started = Instant::now();
        let response: Result<WorkerResponse, String> =
            bincode::deserialize(&bytes).map_err(|e| format!("invalid worker response: {e}"));
        add_us(&metrics.ipc_deserialize_us, started.elapsed());
        let telemetry: WorkerTelemetry = bincode::deserialize(&telemetry_bytes)
            .map_err(|e| format!("invalid worker telemetry: {e}"))?;
        metrics
            .ipc_response_serialize_us
            .fetch_add(telemetry.response_serialize_us, Ordering::Relaxed);
        if let Ok(response) = &response {
            metrics
                .ipc_request_deserialize_us
                .fetch_add(response.request_deserialize_us, Ordering::Relaxed);
            metrics
                .ipc_deserialize_us
                .fetch_add(response.request_deserialize_us, Ordering::Relaxed);
        }
        if response.is_ok() {
            self.metadata_sent = true;
        }
        response
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
        let config = self.config.clone();
        std::thread::Builder::new()
            .name("ghidrust-batch-controller".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || Self { config }.run_inner())
            .map_err(|e| format!("batch controller thread: {e}"))?
            .join()
            .map_err(|_| "batch controller thread panicked".to_string())?
    }

    fn run_inner(&self) -> Result<BatchResult, String> {
        let started = Instant::now();
        validate_budget(self.config.memory_budget_gb)?;
        if self.config.function_timeout.is_zero() {
            return Err("per-function timeout must be greater than zero".into());
        }
        job::verify_supervisor_budget(self.config.memory_budget_gb)?;
        let job_cpu_start = job::supervisor_cpu_time_ms();
        let mut system_commit_peak = memory::system_commit_used_bytes().unwrap_or(0);

        let fingerprint_started = Instant::now();
        let fingerprint = fingerprint_file(&self.config.binary_path)?;
        let fingerprint_ms = fingerprint_started.elapsed().as_secs_f64() * 1000.0;
        let load_started = Instant::now();
        let mut program = load_path(&self.config.binary_path).map_err(|e| format!("load: {e}"))?;
        let load_ms = load_started.elapsed().as_secs_f64() * 1000.0;
        let analyzer_started = Instant::now();
        let analyzer_report =
            run_analyzers(&mut program, &[]).map_err(|e| format!("analysis: {e}"))?;
        let analyzer_ms = analyzer_started.elapsed().as_secs_f64() * 1000.0;
        eprintln!("[batch] load_ms={load_ms:.2} analyzer_total_ms={analyzer_ms:.2}");
        for result in &analyzer_report.results {
            eprintln!(
                "[batch-phase] analyzer={} status={} elapsed_ms={:.3}",
                result.name,
                result.status,
                result.duration_us as f64 / 1000.0
            );
        }
        let enumeration_started = Instant::now();
        let analysis = FunctionStartAnalysis::analyze(&program.analysis.functions);
        let all_functions = program.analysis.functions.len();
        let selected = self.config.filter.apply(&program.analysis.functions);
        let skipped_filter = all_functions.saturating_sub(selected.len());
        let hints = structure_hints_from(&program);
        let emit_hints = EmitHints::from_program(&program);
        let enumeration_ms = enumeration_started.elapsed().as_secs_f64() * 1000.0;

        let checkpoint_path = self
            .config
            .checkpoint_path
            .clone()
            .unwrap_or_else(|| self.config.output_dir.join("batch_checkpoint.txt"));
        let checkpoint_setup_started = Instant::now();
        let resume_existing = checkpoint_path.exists();
        let mut checkpoint = Checkpoint::new(&checkpoint_path, fingerprint.clone());
        if self.config.resume && resume_existing {
            checkpoint
                .load()
                .map_err(|e| format!("checkpoint does not match input or is corrupt: {e}"))?;
            if self.config.format == OutputFormat::Jsonl {
                let output_path = self.output_path(&program.name);
                for address in completed_jsonl_addresses(&output_path)
                    .map_err(|e| format!("output recovery: {e}"))?
                {
                    checkpoint.mark_completed(address);
                }
            }
        }
        let skipped_checkpoint = checkpoint.completed_count();
        if self.config.resume {
            checkpoint.open_for_append()
        } else {
            checkpoint.reset()
        }
        .map_err(|e| format!("checkpoint open: {e}"))?;
        let mut checkpoint_us = checkpoint_setup_started
            .elapsed()
            .as_micros()
            .min(u64::MAX as u128) as u64;
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
        eprintln!(
            "[batch] workers_requested={} workers_effective={workers}",
            if self.config.workers == 0 {
                "auto".into()
            } else {
                self.config.workers.to_string()
            }
        );
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
                load_ms,
                fingerprint_ms,
                analyzer_ms,
                enumeration_ms,
                None,
                0,
                0,
                0,
                self.config.workers,
                None,
            ));
        }

        let worker_path = self.worker_path()?;
        let worker_job = WorkerJob::create(self.config.memory_budget_gb)?;
        let phase_metrics = Arc::new(PhaseMetrics::default());
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
            let function_timeout = self.config.function_timeout;
            let phase_metrics = Arc::clone(&phase_metrics);
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
                        phase_metrics,
                        function_timeout,
                    )
                })
                .map_err(|e| format!("worker controller thread: {e}"))?;
        }
        drop(result_tx);

        let mut succeeded = 0usize;
        let mut failed = 0usize;
        let mut total_us = 0u128;
        let mut peak_committed = memory::current_committed_bytes();
        let mut export_us = 0u64;
        let mut completed = 0usize;
        let mut io_error = None;
        for outcome in result_rx {
            total_us = total_us.saturating_add(outcome.decompile_us);
            let output_started = Instant::now();
            let written = match output.write_outcome(&outcome) {
                Ok(()) => true,
                Err(e) => {
                    io_error.get_or_insert_with(|| format!("output write: {e}"));
                    false
                }
            };
            export_us = export_us
                .saturating_add(output_started.elapsed().as_micros().min(u64::MAX as u128) as u64);
            if outcome.error.is_none() {
                succeeded += 1;
                if written {
                    let checkpoint_started = Instant::now();
                    if let Err(e) = checkpoint.record(outcome.address) {
                        io_error.get_or_insert_with(|| format!("checkpoint write: {e}"));
                    }
                    checkpoint_us = checkpoint_us.saturating_add(
                        checkpoint_started
                            .elapsed()
                            .as_micros()
                            .min(u64::MAX as u128) as u64,
                    );
                }
            } else {
                failed += 1;
            }
            if completed % 100 == 99 || completed + 1 == attempted {
                let flush_started = Instant::now();
                if let Err(error) = output.flush() {
                    io_error.get_or_insert_with(|| format!("output flush: {error}"));
                }
                if let Err(error) = checkpoint.flush() {
                    io_error.get_or_insert_with(|| format!("checkpoint flush: {error}"));
                }
                checkpoint_us = checkpoint_us.saturating_add(
                    flush_started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                );
            }
            peak_committed = peak_committed.max(memory::current_committed_bytes());
            if completed % 100 == 99 || completed + 1 == attempted {
                system_commit_peak =
                    system_commit_peak.max(memory::system_commit_used_bytes().unwrap_or(0));
            }
            completed += 1;
            if completed % 100 == 0 || completed == attempted {
                let elapsed = started.elapsed().as_secs_f64();
                let rate = completed as f64 / elapsed.max(0.001);
                let eta = (attempted - completed) as f64 / rate.max(0.001);
                eprintln!("[batch-progress] done={completed}/{attempted} rate={rate:.1}_fn/s job_commit_mb={:.1} system_commit_gb={:.2} eta_s={eta:.1}", peak_committed as f64 / 1_048_576.0, system_commit_peak as f64 / 1_073_741_824.0);
            }
        }
        if let Err(e) = output.finish() {
            io_error.get_or_insert_with(|| format!("output finalize: {e}"));
        }
        if let Err(e) = checkpoint.flush() {
            io_error.get_or_insert_with(|| format!("checkpoint finalize: {e}"));
        }
        peak_committed = peak_committed.max(job::supervisor_peak_committed_bytes().unwrap_or(0));
        if let Some(error) = io_error {
            return Err(error);
        }
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
            load_ms,
            fingerprint_ms,
            analyzer_ms,
            enumeration_ms,
            Some(&phase_metrics),
            export_us,
            checkpoint_us,
            system_commit_peak,
            self.config.workers,
            job_cpu_start,
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
        load_ms: f64,
        fingerprint_ms: f64,
        analyzer_ms: f64,
        enumeration_ms: f64,
        phases: Option<&PhaseMetrics>,
        export_us: u64,
        checkpoint_us: u64,
        system_commit_peak_bytes: u64,
        requested_workers: usize,
        job_cpu_start: Option<u64>,
    ) -> BatchResult {
        let ms = started.elapsed().as_secs_f64() * 1000.0;
        let cpu_ms = job_cpu_start
            .zip(job::supervisor_cpu_time_ms())
            .map(|(a, b)| b.saturating_sub(a))
            .unwrap_or(0);
        let logical_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1) as f64;
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
            requested_workers,
            effective_workers: workers,
            load_ms,
            fingerprint_ms,
            analyzer_ms,
            enumeration_ms,
            disassembly_ms: phases.map_or(0.0, |m| {
                m.disassembly_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            decoder_init_ms: phases.map_or(0.0, |m| {
                m.decoder_init_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            metadata_clone_ms: phases.map_or(0.0, |m| {
                m.metadata_clone_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            ipc_serialize_ms: phases.map_or(0.0, |m| {
                m.ipc_serialize_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            ipc_write_ms: phases.map_or(0.0, |m| {
                m.ipc_write_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            ipc_wait_ms: phases.map_or(0.0, |m| {
                m.ipc_wait_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            ipc_deserialize_ms: phases.map_or(0.0, |m| {
                m.ipc_deserialize_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            ipc_request_deserialize_ms: phases.map_or(0.0, |m| {
                m.ipc_request_deserialize_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            ipc_response_serialize_ms: phases.map_or(0.0, |m| {
                m.ipc_response_serialize_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            export_ms: export_us as f64 / 1000.0,
            checkpoint_ms: checkpoint_us as f64 / 1000.0,
            worker_start_ms: phases.map_or(0.0, |m| {
                m.worker_start_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            worker_restart_start_ms: phases.map_or(0.0, |m| {
                m.worker_restart_start_us.load(Ordering::Relaxed) as f64 / 1000.0
            }),
            worker_restarts: phases
                .map_or(0, |m| m.worker_restarts.load(Ordering::Relaxed) as usize),
            system_commit_peak_mb: system_commit_peak_bytes as f64 / 1_048_576.0,
            cpu_utilization_pct: if ms > 0.0 {
                cpu_ms as f64 / ms / logical_cpus * 100.0
            } else {
                0.0
            },
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
        Self::run_synthetic_workload(
            worker,
            output_dir,
            count,
            workers,
            budget_gb,
            false,
            false,
            Duration::from_secs(120),
        )
    }

    #[cfg(feature = "test-worker-crash")]
    #[doc(hidden)]
    pub fn run_synthetic_worker_crash_test(
        worker: PathBuf,
        output_dir: PathBuf,
        count: usize,
        workers: usize,
        budget_gb: f64,
    ) -> Result<BatchResult, String> {
        Self::run_synthetic_workload(
            worker,
            output_dir,
            count,
            workers,
            budget_gb,
            true,
            false,
            Duration::from_secs(120),
        )
    }

    #[cfg(feature = "test-worker-crash")]
    #[doc(hidden)]
    pub fn run_synthetic_worker_timeout_test(
        worker: PathBuf,
        output_dir: PathBuf,
        count: usize,
        workers: usize,
        budget_gb: f64,
    ) -> Result<BatchResult, String> {
        Self::run_synthetic_workload(
            worker,
            output_dir,
            count,
            workers,
            budget_gb,
            false,
            true,
            Duration::from_millis(100),
        )
    }

    fn run_synthetic_workload(
        worker: PathBuf,
        output_dir: PathBuf,
        count: usize,
        workers: usize,
        budget_gb: f64,
        crash_first: bool,
        timeout_first: bool,
        function_timeout: Duration,
    ) -> Result<BatchResult, String> {
        validate_budget(budget_gb)?;
        job::verify_supervisor_budget(budget_gb)?;
        let started = Instant::now();
        let worker_job = WorkerJob::create(budget_gb)?;
        let worker_count = choose_workers(workers, budget_gb)?;
        let phase_metrics = Arc::new(PhaseMetrics::default());
        let job_cpu_start = job::supervisor_cpu_time_ms();
        let mut system_commit_peak = memory::system_commit_used_bytes().unwrap_or(0);
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
            let worker_metrics = Arc::clone(&phase_metrics);
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
                    worker_metrics,
                    function_timeout,
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
                    if crash_first && i == 0 {
                        "__worker_crash_test__".into()
                    } else if timeout_first && i == 0 {
                        "__worker_timeout_test__".into()
                    } else {
                        format!("synthetic_{i}")
                    },
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
        let mut export_us = 0u64;
        let mut completed = 0usize;
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
            let export_started = Instant::now();
            output.write_outcome(&outcome).map_err(|e| e.to_string())?;
            export_us = export_us.saturating_add(export_started.elapsed().as_micros() as u64);
            peak = peak.max(memory::current_committed_bytes());
            completed += 1;
            if completed % 100 == 0 || completed == count {
                system_commit_peak =
                    system_commit_peak.max(memory::system_commit_used_bytes().unwrap_or(0));
                let elapsed = started.elapsed().as_secs_f64();
                let rate = completed as f64 / elapsed.max(0.001);
                eprintln!("[batch-progress] done={completed}/{count} rate={rate:.1}_fn/s job_commit_mb={:.1} system_commit_gb={:.2} eta_s={:.1}", peak as f64 / 1_048_576.0, system_commit_peak as f64 / 1_073_741_824.0, (count - completed) as f64 / rate.max(0.001));
            }
        }
        producer
            .join()
            .map_err(|_| "synthetic task producer panicked")?;
        output.finish().map_err(|e| e.to_string())?;
        peak = peak.max(job::supervisor_peak_committed_bytes().unwrap_or(0));
        let cpu_ms = job_cpu_start
            .zip(job::supervisor_cpu_time_ms())
            .map(|(a, b)| b.saturating_sub(a))
            .unwrap_or(0);
        let logical_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1) as f64;
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
            requested_workers: workers,
            effective_workers: worker_count,
            load_ms: 0.0,
            fingerprint_ms: 0.0,
            analyzer_ms: 0.0,
            enumeration_ms: 0.0,
            disassembly_ms: 0.0,
            decoder_init_ms: 0.0,
            metadata_clone_ms: phase_metrics.metadata_clone_us.load(Ordering::Relaxed) as f64
                / 1000.0,
            ipc_serialize_ms: phase_metrics.ipc_serialize_us.load(Ordering::Relaxed) as f64
                / 1000.0,
            ipc_write_ms: phase_metrics.ipc_write_us.load(Ordering::Relaxed) as f64 / 1000.0,
            ipc_wait_ms: phase_metrics.ipc_wait_us.load(Ordering::Relaxed) as f64 / 1000.0,
            ipc_deserialize_ms: phase_metrics.ipc_deserialize_us.load(Ordering::Relaxed) as f64
                / 1000.0,
            ipc_request_deserialize_ms: phase_metrics
                .ipc_request_deserialize_us
                .load(Ordering::Relaxed) as f64
                / 1000.0,
            ipc_response_serialize_ms: phase_metrics
                .ipc_response_serialize_us
                .load(Ordering::Relaxed) as f64
                / 1000.0,
            export_ms: export_us as f64 / 1000.0,
            checkpoint_ms: 0.0,
            worker_start_ms: phase_metrics.worker_start_us.load(Ordering::Relaxed) as f64 / 1000.0,
            worker_restart_start_ms: phase_metrics
                .worker_restart_start_us
                .load(Ordering::Relaxed) as f64
                / 1000.0,
            worker_restarts: phase_metrics.worker_restarts.load(Ordering::Relaxed) as usize,
            system_commit_peak_mb: system_commit_peak as f64 / 1_048_576.0,
            cpu_utilization_pct: if ms > 0.0 {
                cpu_ms as f64 / ms / logical_cpus * 100.0
            } else {
                0.0
            },
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
    phase_metrics: Arc<PhaseMetrics>,
    function_timeout: Duration,
) {
    let mut child = WorkerProcess::spawn(&path, &job, &phase_metrics, false).ok();
    let mut decoder: Option<DisasmSession> = None;
    let mut consecutive_failures = 0usize;
    while let Ok(task) = rx.recv() {
        let function = task.function;
        let start = Instant::now();
        let disasm_started = Instant::now();
        let decoded = match task.prepared {
            Some(instructions) => Ok(instructions),
            None => {
                if decoder.is_none() {
                    let decoder_started = Instant::now();
                    let opened = DisasmSession::new(&program);
                    add_us(&phase_metrics.decoder_init_us, decoder_started.elapsed());
                    match opened {
                        Ok(session) => decoder = Some(session),
                        Err(error) => {
                            let outcome = FunctionOutcome {
                                address: function.entry,
                                name: function.name,
                                pseudo_c: None,
                                error: Some(format!("decoder init: {error}")),
                                insn_count: 0,
                                decompile_us: start.elapsed().as_micros(),
                                goto_count: 0,
                                leaf_count: 0,
                            };
                            if tx.send(outcome).is_err() {
                                break;
                            }
                            continue;
                        }
                    }
                }
                decoder
                    .as_mut()
                    .unwrap()
                    .disassemble_range(&program, function.entry, max_insns)
                    .map_err(|e| format!("disassembly: {e}"))
            }
        };
        add_us(&phase_metrics.disassembly_us, disasm_started.elapsed());
        let mut worker_failed = false;
        let result = match decoded {
            Ok(instructions) => {
                let count = instructions.len();
                let send_metadata = child
                    .as_ref()
                    .map(|worker| !worker.metadata_sent)
                    .unwrap_or(true);
                let clone_started = Instant::now();
                let request = WorkerRequest {
                    entry: function.entry,
                    name: function.name.clone(),
                    instructions,
                    conv: send_metadata.then_some(conv),
                    hints: send_metadata.then(|| hints.clone()),
                    emit_hints: send_metadata.then(|| emit_hints.clone()),
                    #[cfg(feature = "test-worker-crash")]
                    crash_for_test: function.name == "__worker_crash_test__",
                    #[cfg(feature = "test-worker-crash")]
                    delay_for_test_ms: if function.name == "__worker_timeout_test__" {
                        500
                    } else {
                        0
                    },
                };
                add_us(&phase_metrics.metadata_clone_us, clone_started.elapsed());
                let response = child
                    .as_mut()
                    .ok_or_else(|| "worker unavailable".to_string())
                    .and_then(|worker| {
                        let remaining = function_timeout.saturating_sub(start.elapsed());
                        worker.execute(&request, &phase_metrics, remaining)
                    });
                worker_failed = response.is_err();
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
                if worker_failed {
                    consecutive_failures += 1;
                    phase_metrics
                        .worker_restarts
                        .fetch_add(1, Ordering::Relaxed);
                    child.take();
                    if consecutive_failures <= 3 {
                        child = WorkerProcess::spawn(&path, &job, &phase_metrics, true).ok();
                    }
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
