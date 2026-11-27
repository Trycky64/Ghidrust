//! Line-oriented protocol for long-lived worker subprocesses.

use crate::engine::FunctionOutcome;
use ghidrust_core::Instruction;
use ghidrust_decomp::{decompile_instructions_stage1_full, EmitHints};
use ghidrust_structure::StructureHints;
use ghidrust_types::CallConv;
use serde::{Deserialize, Serialize};
use std::io::{self, BufReader, Read, Write};
use std::time::Instant;

/// Bound a single returned function before IPC and JSONL serialization.
/// Oversized text is reported as partial, never silently sliced.
const MAX_PSEUDOCODE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub entry: u64,
    pub name: String,
    pub instructions: Vec<Instruction>,
    #[serde(default)]
    pub conv: Option<CallConv>,
    #[serde(default)]
    pub hints: Option<StructureHints>,
    #[serde(default)]
    pub emit_hints: Option<EmitHints>,
    #[cfg(feature = "test-worker-crash")]
    pub crash_for_test: bool,
    #[cfg(feature = "test-worker-crash")]
    #[serde(default)]
    pub delay_for_test_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub address: u64,
    pub name: String,
    pub pseudo_c: Option<String>,
    pub error: Option<String>,
    #[serde(default)]
    pub partial_reason: Option<String>,
    #[serde(default)]
    pub structure_fallback: bool,
    pub decompile_us: u128,
    pub goto_count: usize,
    pub leaf_count: usize,
    pub request_deserialize_us: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerTelemetry {
    pub response_serialize_us: u64,
}

impl WorkerResponse {
    pub fn into_outcome(self, insn_count: usize) -> FunctionOutcome {
        FunctionOutcome {
            address: self.address,
            name: self.name,
            pseudo_c: self.pseudo_c,
            error: self.error,
            partial_reason: self.partial_reason,
            structure_fallback: self.structure_fallback,
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
    const MAX_WORKER_FRAME_BYTES: usize = 128 * 1024 * 1024;
    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut cached_conv = None;
    let mut cached_hints = None;
    let mut cached_emit_hints = None;
    loop {
        let mut header = [0u8; 4];
        match input.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(format!("worker stdin: {error}")),
        }
        let len = u32::from_le_bytes(header) as usize;
        if len > MAX_WORKER_FRAME_BYTES {
            return Err(format!("worker request frame too large: {len}"));
        }
        let mut bytes = vec![0u8; len];
        input
            .read_exact(&mut bytes)
            .map_err(|e| format!("worker stdin: {e}"))?;
        let deserialize_started = Instant::now();
        let request: WorkerRequest =
            bincode::deserialize(&bytes).map_err(|e| format!("invalid worker request: {e}"))?;
        let request_deserialize_us = deserialize_started
            .elapsed()
            .as_micros()
            .min(u64::MAX as u128) as u64;
        #[cfg(feature = "test-worker-crash")]
        if request.crash_for_test {
            std::process::exit(17);
        }
        #[cfg(feature = "test-worker-crash")]
        if request.delay_for_test_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(request.delay_for_test_ms));
        }
        if let Some(conv) = request.conv {
            cached_conv = Some(conv);
        }
        if let Some(hints) = request.hints {
            cached_hints = Some(hints);
        }
        if let Some(hints) = request.emit_hints {
            cached_emit_hints = Some(hints);
        }
        let conv = cached_conv.ok_or("worker task arrived before metadata initialization")?;
        let hints = cached_hints.as_ref().ok_or("worker hints missing")?;
        let emit_hints = cached_emit_hints
            .as_ref()
            .ok_or("worker emit hints missing")?;
        let start = Instant::now();
        let response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decompile_instructions_stage1_full(
                &request.name,
                request.entry,
                &request.instructions,
                conv,
                hints,
                emit_hints,
            )
        })) {
            Ok((decomp, stage1)) => {
                let oversized = decomp.pseudo_c.len() > MAX_PSEUDOCODE_BYTES;
                WorkerResponse {
                    address: request.entry,
                    name: request.name,
                    pseudo_c: (!oversized).then_some(decomp.pseudo_c),
                    error: None,
                    partial_reason: oversized.then(|| {
                        format!(
                            "pseudocode exceeded the {} byte output limit",
                            MAX_PSEUDOCODE_BYTES
                        )
                    }),
                    structure_fallback: stage1.structure.unstructured_fallback,
                    decompile_us: start.elapsed().as_micros(),
                    goto_count: ghidrust_structure::goto_count(&stage1.structure.region),
                    leaf_count: ghidrust_structure::region_leaf_count(&stage1.structure.region),
                    request_deserialize_us,
                }
            }
            Err(_) => WorkerResponse {
                address: request.entry,
                name: request.name,
                pseudo_c: None,
                error: Some("worker panic caught".into()),
                partial_reason: None,
                structure_fallback: false,
                decompile_us: start.elapsed().as_micros(),
                goto_count: 0,
                leaf_count: 0,
                request_deserialize_us,
            },
        };
        let serialization_started = Instant::now();
        let bytes = bincode::serialize(&response).map_err(|e| e.to_string())?;
        let telemetry = WorkerTelemetry {
            response_serialize_us: serialization_started
                .elapsed()
                .as_micros()
                .min(u64::MAX as u128) as u64,
        };
        let len = u32::try_from(bytes.len()).map_err(|_| "worker response too large")?;
        stdout
            .write_all(&len.to_le_bytes())
            .map_err(|e| e.to_string())?;
        stdout.write_all(&bytes).map_err(|e| e.to_string())?;
        let telemetry_bytes = bincode::serialize(&telemetry).map_err(|e| e.to_string())?;
        let telemetry_len =
            u32::try_from(telemetry_bytes.len()).map_err(|_| "worker telemetry too large")?;
        stdout
            .write_all(&telemetry_len.to_le_bytes())
            .map_err(|e| e.to_string())?;
        stdout
            .write_all(&telemetry_bytes)
            .map_err(|e| e.to_string())?;
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
            partial_reason: None,
            structure_fallback: false,
            decompile_us: 3,
            goto_count: 0,
            leaf_count: 0,
            request_deserialize_us: 0,
        };
        let out = r.into_outcome(2);
        assert_eq!(out.address, 0x1234);
        assert_eq!(out.insn_count, 2);
        assert!(out.error.is_some());
    }
}
