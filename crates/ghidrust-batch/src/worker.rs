//! Line-oriented protocol for long-lived worker subprocesses.

use crate::engine::FunctionOutcome;
use ghidrust_core::Instruction;
use ghidrust_decomp::{decompile_instructions_stage1_full, EmitHints};
use ghidrust_structure::StructureHints;
use ghidrust_types::CallConv;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::time::Instant;

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub entry: u64,
    pub name: String,
    pub instructions: Vec<Instruction>,
    pub conv: CallConv,
    pub hints: StructureHints,
    pub emit_hints: EmitHints,
    #[cfg(feature = "test-worker-crash")]
    pub crash_for_test: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub address: u64,
    pub name: String,
    pub pseudo_c: Option<String>,
    pub error: Option<String>,
    pub decompile_us: u128,
    pub goto_count: usize,
    pub leaf_count: usize,
}

impl WorkerResponse {
    pub fn into_outcome(self, insn_count: usize) -> FunctionOutcome {
        FunctionOutcome {
            address: self.address,
            name: self.name,
            pseudo_c: self.pseudo_c,
            error: self.error,
            insn_count,
            decompile_us: self.decompile_us,
            goto_count: self.goto_count,
            leaf_count: self.leaf_count,
        }
    }
}

/// Serve requests until EOF. One process is reused for many independent functions.
pub fn run_stdio_worker() -> Result<(), String> {
    crate::job::verify_supervisor_budget(4.0)?;
    crate::job::verify_current_process_in_any_job()?;
    std::thread::Builder::new()
        .name("ghidrust-batch-worker-loop".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(run_stdio_worker_inner)
        .map_err(|e| format!("worker loop thread: {e}"))?
        .join()
        .map_err(|_| "worker loop thread panicked".to_string())?
}

fn run_stdio_worker_inner() -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("worker stdin: {e}"))?;
        if line.is_empty() {
            continue;
        }
        let request: WorkerRequest =
            serde_json::from_str(&line).map_err(|e| format!("invalid worker request: {e}"))?;
        #[cfg(feature = "test-worker-crash")]
        if request.crash_for_test {
            std::process::exit(17);
        }
        let start = Instant::now();
        let response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decompile_instructions_stage1_full(
                &request.name,
                request.entry,
                &request.instructions,
                request.conv,
                &request.hints,
                &request.emit_hints,
            )
        })) {
            Ok((decomp, stage1)) => WorkerResponse {
                address: request.entry,
                name: request.name,
                pseudo_c: Some(decomp.pseudo_c),
                error: None,
                decompile_us: start.elapsed().as_micros(),
                goto_count: ghidrust_structure::goto_count(&stage1.structure.region),
                leaf_count: ghidrust_structure::region_leaf_count(&stage1.structure.region),
            },
            Err(_) => WorkerResponse {
                address: request.entry,
                name: request.name,
                pseudo_c: None,
                error: Some("worker panic caught".into()),
                decompile_us: start.elapsed().as_micros(),
                goto_count: 0,
                leaf_count: 0,
            },
        };
        serde_json::to_writer(&mut stdout, &response).map_err(|e| e.to_string())?;
        stdout.write_all(b"\n").map_err(|e| e.to_string())?;
        stdout.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_keeps_failed_task_metadata() {
        let r = WorkerResponse {
            address: 0x1234,
            name: "f".into(),
            pseudo_c: None,
            error: Some("synthetic failure".into()),
            decompile_us: 3,
            goto_count: 0,
            leaf_count: 0,
        };
        let out = r.into_outcome(2);
        assert_eq!(out.address, 0x1234);
        assert_eq!(out.insn_count, 2);
        assert!(out.error.is_some());
    }
}
