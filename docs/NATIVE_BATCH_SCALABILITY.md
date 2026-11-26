# Native batch scalability results

Measurements below were collected on Windows 11 using the redistributable PE
generator in `tools/bench_batch_scalability.py`. Each engine invocation ran
through `tools/memory_guard.py`, which suspended process creation until the
entire process tree was assigned to a Windows Job Object. The Job memory limit
was 4 GiB with 256 MiB reserved as allocator/kernel headroom; the watchdog also
sampled system commit with `GetPerformanceInfo` and enforced a 300-second
per-run timeout. No proprietary binaries or FLEngine were used.

## Findings and changes

The 1,000-function run exposed the largest avoidable costs in the initial
implementation: JSON request serialization and parsing repeated task metadata,
per-function checkpoint flushes added synchronous writes, and opening a decoder
for every function repeated setup. The batch engine now caches immutable worker
metadata once per worker, uses length-framed bincode IPC, reuses decoder sessions,
and flushes checkpoints in batches only after corresponding JSONL output is
durable. It also reports requested and effective worker counts, per-function
timeouts, worker restart costs, phase timings, CPU, Job commit, system commit,
and periodic throughput/ETA.

The first 10,000-function timeout was not reproducible with this optimized
release: all requested worker configurations completed. The throughput and
time columns below show near-linear growth at a fixed worker count through
100,000 functions. The full PE path is dominated by disassembly and per-function
IPC/preparation overhead; direct synthetic dispatch isolates persistent-worker
decompile/export throughput from loading, analyzers, enumeration, and
disassembly.

Against the reported initial single-worker figures, 100 functions fell from
287 ms to 194.5 ms, and 1,000 fell from 17.39 s to 1.60 s (about 10.9x faster).
The original 10,000-function run exceeded its 300-second harness timeout; the
current single-worker run completed in 14.14 s, over 21x faster than that
timeout threshold. These historical baseline numbers came from the supplied
benchmark run; the exact original input fixture was not retained, so treat this
as an indicative before/after comparison rather than a controlled A/B test.

`disassembly_ms`, IPC phase totals, and decompile time are summed across
workers, so these cumulative counters can exceed wall time. `system_commit_peak`
is global Windows commit and can include unrelated processes; `job_peak` is the
aggregate committed-memory high-water mark for the guarded process tree.

## PE end-to-end matrix

All runs succeeded with zero failed functions and exactly one nonempty JSONL
record per generated function. A 16-worker request was capped at 8 by the
4-GiB budget and the 512-MiB per-worker reserve.

| Functions | Requested → effective | Wall time | Functions/s | CPU % of machine | Job peak MiB | System commit peak GiB | Export MiB |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100* | 1 → 1 | 194.50 ms | 514 | 11.41 | — | — |
| 100* | 2 → 2 | 82.27 ms | 1,215 | — | — | — |
| 100* | 4 → 4 | 56.57 ms | 1,767 | — | — | — |
| 100* | 8 → 8 | 44.57 ms | 2,244 | — | — | — |
| 100* | 16 → 8 | 43.41 ms | 2,304 | — | — | — |
| 1,000 | 1 → 1 | 1.60 s | 625 | 3.4 | 11.7 | 35.35 | 0.47 |
| 1,000 | 2 → 2 | 0.87 s | 1,154 | 7.2 | 17.7 | 35.26 | 0.47 |
| 1,000 | 4 → 4 | 0.53 s | 1,882 | 12.0 | 28.7 | 35.26 | 0.47 |
| 1,000 | 8 → 8 | 0.38 s | 2,634 | 21.3 | 47.8 | 35.28 | 0.47 |
| 1,000 | 16 → 8 | 0.39 s | 2,553 | 20.3 | 48.1 | 35.27 | 0.47 |
| 2,000 | 1 → 1 | 2.98 s | 671 | 3.4 | 13.2 | 35.24 | 0.95 |
| 2,000 | 2 → 2 | 1.60 s | 1,253 | 6.7 | 19.0 | 35.24 | 0.95 |
| 2,000 | 4 → 4 | 0.99 s | 2,017 | 13.1 | 29.2 | 35.31 | 0.95 |
| 2,000 | 8 → 8 | 0.81 s | 2,463 | 21.7 | 51.0 | 35.33 | 0.95 |
| 2,000 | 16 → 8 | 0.72 s | 2,768 | 21.1 | 50.2 | 35.23 | 0.95 |
| 5,000 | 1 → 1 | 7.20 s | 695 | 3.4 | 16.6 | 35.20 | 2.38 |
| 5,000 | 2 → 2 | 3.71 s | 1,346 | 7.1 | 23.3 | 35.13 | 2.38 |
| 5,000 | 4 → 4 | 2.19 s | 2,281 | 12.7 | 37.9 | 35.14 | 2.38 |
| 5,000 | 8 → 8 | 1.42 s | 3,511 | 23.6 | 61.5 | 35.15 | 2.38 |
| 5,000 | 16 → 8 | 1.47 s | 3,392 | 23.1 | 61.0 | 35.18 | 2.38 |
| 10,000 | 1 → 1 | 14.14 s | 707 | 3.4 | 22.6 | 35.15 | 4.76 |
| 10,000 | 2 → 2 | 8.11 s | 1,233 | 6.8 | 30.3 | 35.24 | 4.76 |
| 10,000 | 4 → 4 | 4.42 s | 2,260 | 13.1 | 46.3 | 35.24 | 4.76 |
| 10,000 | 8 → 8 | 2.95 s | 3,394 | 25.0 | 74.7 | 35.53 | 4.76 |
| 10,000 | 16 → 8 | 3.38 s | 2,959 | 24.7 | 74.5 | 35.66 | 4.77 |
| 50,000 | 1 → 1 | 68.58 s | 729 | 3.4 | 66.3 | 35.48 | 23.85 |
| 50,000 | 2 → 2 | 43.48 s | 1,150 | 6.7 | 87.7 | 35.58 | 23.86 |
| 50,000 | 4 → 4 | 23.19 s | 2,156 | 12.7 | 122.9 | 35.57 | 23.86 |
| 50,000 | 8 → 8 | 13.76 s | 3,634 | 23.9 | 187.7 | 35.65 | 23.86 |
| 50,000 | 16 → 8 | 13.51 s | 3,702 | 23.8 | 185.0 | 35.66 | 23.86 |
| 100,000 | 1 → 1 | 136.43 s | 733 | 3.4 | 122.1 | 35.67 | 47.80 |
| 100,000 | 2 → 2 | 87.96 s | 1,137 | 6.6 | 158.1 | 35.83 | 47.80 |
| 100,000 | 4 → 4 | 53.79 s | 1,859 | 12.3 | 213.7 | 35.95 | 47.81 |
| 100,000 | 8 → 8 | 32.89 s | 3,041 | 23.0 | 330.4 | 36.05 | 47.82 |
| 100,000 | 16 → 8 | 32.88 s | 3,042 | 23.2 | 328.0 | 36.03 | 47.82 |

`*` The 100-function PE measurements were collected after the final release
rebuild; the compact original 100-function output did not include every memory
and export field.

## Direct synthetic dispatch, 8 workers

| Functions | Wall time | Functions/s | CPU % of machine | Job peak MiB | System commit peak GiB | Export MiB |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 16.48 ms | 6,068 | — | 6.5 | — | 0.03 |
| 1,000 | 22.92 ms | 43,638 | 12.8 | 10.1 | 35.22 | 0.34 |
| 2,000 | 31.53 ms | 63,434 | 23.3 | 10.2 | 35.18 | 0.69 |
| 5,000 | 54.04 ms | 92,520 | 31.6 | 10.9 | 35.13 | 1.73 |
| 10,000 | 114.91 ms | 87,023 | 29.3 | 11.6 | 35.60 | 3.46 |
| 50,000 | 416.07 ms | 120,173 | 28.9 | 17.5 | 35.37 | 17.42 |
| 100,000 | 792.81 ms | 126,133 | 30.3 | 25.1 | 35.67 | 34.91 |

The direct mode has no binary load, analyzer, enumeration, or disassembly phase.
Comparing its 100,000-function time (0.79 s) with the corresponding PE run
(32.89 s) isolates roughly 32 seconds of full-pipeline work. At 100,000
functions and 8 workers, disassembly sums to 104.8 seconds across workers;
function-request serialization and worker request parsing sum to 10.3 and
63.7 seconds respectively. These cumulative figures show that disassembly and
IPC/task preparation are the next optimization targets. Checkpoint and export
flush costs stayed below 0.5 seconds combined.

## Reproduction

From the repository root on Windows:

```powershell
python tools\bench_batch_scalability.py `
  --exe target\release\ghidrust.exe `
  --counts 100,1000,2000,5000,10000 `
  --workers 1,2,4,8,16 `
  --timeout 300 `
  --report batch-scalability-report.json `
  --keep-artifacts batch-scalability-artifacts

python tools\bench_batch_scalability.py `
  --exe target\release\ghidrust.exe `
  --counts 50000,100000 `
  --workers 1,2,4,8,16 `
  --timeout 300 `
  --report batch-scalability-large-report.json `
  --keep-artifacts batch-scalability-large-artifacts
```

The large-scale JSON reports are committed alongside this document. Generated
PEs and JSONL exports are left out of Git; the fixture generator recreates them.

Recommended configuration for this 32-thread, 32-GiB machine is 8 workers for
large PE batches under the 4-GiB cap. Requesting 16 is capped to 8 and did not
produce a consistent improvement. For smaller binaries, 4 workers may be a
better latency/CPU tradeoff. The PE throughput numbers here use intentionally
small functions and should not be treated as forecasts for real binaries.
