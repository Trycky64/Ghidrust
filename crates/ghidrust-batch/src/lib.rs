//! **Batch decompilation engine** — load a binary once, decompile all functions
//! in parallel with streaming output, checkpointing, and panic isolation.
//!
//! # Architecture
//!
//! 1. **Load phase**: binary loaded once via `ghidrust_core::load_path`, analyzers
//!    run once. The resulting `Program` and `AnalysisState` are shared read-only.
//! 2. **Pre-disassemble phase**: instructions for every target function are decoded
//!    serially (the `Program` decode path isn't thread-safe). This avoids the 7-8s
//!    per-invocation overhead of the old process-per-function architecture.
//! 3. **Parallel decompile phase**: a rayon thread pool with configurable worker
//!    count fans out Stage-1 decompilation across prepared instruction buffers.
//!    Each function is wrapped in `catch_unwind` to isolate panics.
//! 4. **Streaming output**: results are written to JSONL as they complete via a
//!    crossbeam channel, never accumulating all pseudocode in RAM.
//! 5. **Checkpointing**: an append-only checkpoint file records completed function
//!    addresses. On resume, completed functions are skipped.

pub mod checkpoint;
pub mod engine;
pub mod function_filter;
mod job;
pub mod memory;
pub mod output;
pub mod worker;

pub use engine::{BatchConfig, BatchEngine, BatchResult, FunctionOutcome, SyntheticTask};
pub use function_filter::FunctionFilter;
pub use output::OutputFormat;
