# Real-binary operational validation

This validation used only open-source sources and locally compiled PE files.
All builds and batch runs were launched through `tools/memory_guard.py` on
Windows with an aggregate 4-GiB Job Object limit, 256-MiB requested headroom,
8 workers by default, and a 120-second per-function timeout. The watchdog also
enforced a separate wall-clock timeout. No RustStudio files, prior RustStudio
exports/checkpoints, proprietary binaries, or FLEngine were used.

## Sources and build commands

| Project | Source revision | License | Build |
|---|---|---|---|
| zlib | Git `617e19a81f38c15ff04de9f86882f42ad8a8ffd1` | zlib license | `gcc -O0` and `gcc -O2`; `examples/zpipe.c` plus the core deflate/inflate sources |
| SQLite shell | SQLite 3.54.1 official amalgamation; SHA3-256 `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30` | Public domain | `gcc -O0` and `gcc -O2`; `shell.c` plus `sqlite3.c`, FTS5 and RTREE enabled |

The SQLite amalgamation and its release hash are listed on the [official SQLite download page](https://www.sqlite.org/download.html); SQLite documents the source as public domain in its [license information](https://github.com/sqlite/sqlite/blob/master/LICENSE.md). zlib source and its license are in the [upstream repository](https://github.com/madler/zlib). The source checkouts and generated binaries remain local under `validation/`.

Exact compile commands, from the repository root:

```powershell
python tools\memory_guard.py --memory-gib 4 --headroom-mib 256 --timeout 300 -- `
  gcc -O0 -g0 -I validation/sources/zlib -o validation/builds/zpipe-debug.exe `
  validation/sources/zlib/examples/zpipe.c `
  validation/sources/zlib/adler32.c validation/sources/zlib/crc32.c `
  validation/sources/zlib/deflate.c validation/sources/zlib/infback.c `
  validation/sources/zlib/inffast.c validation/sources/zlib/inflate.c `
  validation/sources/zlib/inftrees.c validation/sources/zlib/trees.c `
  validation/sources/zlib/zutil.c

python tools\memory_guard.py --memory-gib 4 --headroom-mib 256 --timeout 300 -- `
  gcc -O2 -g0 -I validation/sources/zlib -o validation/builds/zpipe-release.exe `
  validation/sources/zlib/examples/zpipe.c `
  validation/sources/zlib/adler32.c validation/sources/zlib/crc32.c `
  validation/sources/zlib/deflate.c validation/sources/zlib/infback.c `
  validation/sources/zlib/inffast.c validation/sources/zlib/inflate.c `
  validation/sources/zlib/inftrees.c validation/sources/zlib/trees.c `
  validation/sources/zlib/zutil.c

python tools\memory_guard.py --memory-gib 4 --headroom-mib 256 --timeout 600 -- `
  gcc -O0 -g0 -DSQLITE_THREADSAFE=0 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_RTREE `
  -o validation/builds/sqlite-debug.exe `
  validation/sources/sqlite-amalgamation-3540100/sqlite-amalgamation-3540100/shell.c `
  validation/sources/sqlite-amalgamation-3540100/sqlite-amalgamation-3540100/sqlite3.c

python tools\memory_guard.py --memory-gib 4 --headroom-mib 256 --timeout 600 -- `
  gcc -O2 -g0 -DSQLITE_THREADSAFE=0 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_RTREE `
  -o validation/builds/sqlite-release.exe `
  validation/sources/sqlite-amalgamation-3540100/sqlite-amalgamation-3540100/shell.c `
  validation/sources/sqlite-amalgamation-3540100/sqlite-amalgamation-3540100/sqlite3.c
```

Both zpipe builds passed a source-derived functional round trip: 6,593 bytes
from `zpipe.c` compressed to 1,960 bytes and decompressed byte-for-byte. The
test script is `validation/verify_zpipe_roundtrip.py`.

## Batch results

The first table records the pre-fix baseline. It showed large exports and
worker exits on SQLite:

| Binary | Functions found | Successful | Failed | Wall time | Job peak | JSONL export | Max successful instructions |
|---|---:|---:|---:|---:|---:|---:|---:|
| zlib zpipe `-O0` | 169 | 169 | 0 | 190 ms | 98 MiB | 20.9 MB | 1,258 |
| zlib zpipe `-O2` | 179 | 179 | 0 | 70 ms | 43 MiB | 5.6 MB | 1,977 |
| SQLite shell `-O0` | 4,109 | 4,105 | 4 | 6.67 s | 3,841 MiB | 162.0 MB | 3,847 |
| SQLite shell `-O2` | 3,759 | 3,752 | 7 | 3.89 s | 3,841 MiB | 86.2 MB | 1,868 |

The current CLI supports `--max-insns-per-fn`; a cap hit is emitted as
`partial`, separately from a complete unstructured fallback and an error.

### SQLite after the region and function-bound fixes

| Binary | `.pdata` entries | Structured successes | Unstructured fallbacks | Partial | Failed | Wall time | Job peak | JSONL | Pseudocode |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SQLite shell `-O0` | 3,944 | 3,916 | 28 | 0 | 0 | 0.85 s | 65.8 MiB | 13.19 MiB | 12.01 MiB |
| SQLite shell `-O2` | 2,449 | 2,436 | 12 | 0 | 1 | 0.54 s | 48.8 MiB | 4.25 MiB | 3.60 MiB |

Both full runs used eight effective workers, a 4-GiB aggregate Windows Job Object,
a 120-second per-function timeout, and `--max-insns-per-fn 4096`. No function hit
the instruction cap. The corrected analyzer output contains every `.pdata`
runtime-function entry: 3,944/3,944 at `-O0` and 2,449/2,449 at `-O2`. Every
fallback emitted one `block_N:` label per CFG block, and every goto destination
had a matching label. The remaining `-O2` error at `0x140074510` is a 121-byte
`.pdata` entry whose bytes begin with `66 0F 6E`; the current decoder returns
`no instructions` for this SSE instruction. It is a decoder-coverage failure,
not a worker crash or a region explosion.

## Source-to-output inspection

The zpipe PE files retain MinGW symbols. The functions `def`, `inf`, `zerr` and
`main` were mapped from export JSONL addresses to `nm` symbols and compared with
`examples/zpipe.c`. Both loops in `def` and `inf` were represented as two loops
in emitted structure metadata. The source `switch` in `zerr` appeared as
branch/goto regions rather than a C `switch`; the output retains low-level
register and memory operations and generic `FUN_...` names. Lift ratios on
these four ranged from 99.8% to 100%, but that is not a proof of semantic
equivalence. The byte-for-byte round trip is an application test, not a
per-function semantic oracle.

SQLite's local source is available, but the stripped PE builds do not expose
names for the isolated failing functions; I therefore do not claim a direct
source-to-pseudocode equivalence check for them. No pseudocode was published.

## Region expansion and PE function-bound fixes

The original structuring fix stopped stack growth but still rebuilt shared
switch destinations and convergent subgraphs repeatedly. SQLite exposed the
combinatorial growth: `idxPopulateOneStat1` produced 11,105 region leaves and
21.97 MB of pseudocode. The correction charges a per-function construction
budget before large expansions, shares visited destinations across switch
cases, selects the nearest common post-dominator, and falls back to a complete
block/label/goto listing. Synthetic tests cover successive diamonds, switches
with shared targets, nested loops, irreducible CFGs, and multiple convergences;
they assert reachable-block and outgoing-edge preservation. All 19
`ghidrust-structure` tests passed under the watchdog.

A separate coverage bug was found in the PE function-start pass. It called
`grow_function`, which stops at the first `ret`, even when the PE `.pdata`
runtime-function record supplies an exact later end. This shortened functions
and allowed inferred starts inside real function ranges to appear as separate
functions. `.pdata` ends are now preserved exactly, overlapping authoritative
entries remain visible, and batch disassembly uses exact `.pdata` bounds.
Inferred bounds keep their linear-disassembly behavior. Tests cover early
returns, PDATA end preservation, and overlapping PDATA entries.

The worst isolated SQLite cases now remain small:

| Function | Build | Before | After |
|---|---|---|---|
| `idxPopulateOneStat1` | SQLite `-O0` | 11,105 leaves; 21.97 MB | 85 CFG blocks; 15.4 KB; fallback |
| `pagerPlaybackSavepoint` | SQLite `-O0` | 7,834 leaves; 16.39 MB | 50 CFG blocks; 9.4 KB; fallback |
| `fts5SnippetFunction` | SQLite `-O0` | worker failed under memory pressure | 119 CFG blocks; 21.8 KB; fallback |
| `fts5SetupTokendataIter` | SQLite `-O0` | worker failed under memory pressure | 84 CFG blocks; 16.9 KB; fallback |
| `fts5AsciiTokenize` | SQLite `-O0` | worker failed under memory pressure | 30 CFG blocks; 6.6 KB; fallback |
| `fts5MergePrefixLists` | SQLite `-O2` | worker exited before response | 41 CFG blocks; 7.4 KB; fallback |
| `sqlite3FindFunction` | SQLite `-O2` | worker exited; only 8 instructions after first fix | 181 instructions; 47 CFG blocks; 4.7 KB; fallback |
| `exprSelectUsage` | SQLite `-O2` | worker exited; only 8 instructions after first fix | 162 instructions; 34 CFG blocks; 3.2 KB; fallback |
| `heightOfSelect` | SQLite `-O2` | worker exited before response | 89 instructions; 34 CFG blocks; 3.7 KB; fallback |

The eight-instruction results prompted the PDATA audit; they were not accepted as
coverage. The exact runtime-function ranges now produce 181 and 162 instructions
for `sqlite3FindFunction` and `exprSelectUsage` respectively.

## Ripgrep workload and repeated stability

The open-source input was ripgrep 15.2.0 (`rg --version` reports upstream
revision `e89fff89ac`; [official release](https://github.com/BurntSushi/ripgrep/releases/tag/15.2.0)).
The protected full run found 3,618 `.pdata` entries: 3,611 structured successes,
3 unstructured fallbacks, 4 decode errors, and no partials. The JSONL was 6.11
MiB, pseudocode was 5.17 MiB, and Job peak was 60.1 MiB. The four errors were
identical across the full run and the repeat run.

A ten-run stability sequence processed all 3,618 entries each time. Every run
had 3 fallbacks, 4 deterministic decode errors, and 0 partial results. Job peaks
ranged from 55.9 to 58.6 MiB; system-commit peaks ranged from 39.37 to 39.74
GiB. Each run used eight effective workers, a separate output directory, and
its own watchdog Job Object. This is an operational stability check, not a
per-function semantic oracle for ripgrep.

## Abrupt interruption and resume

The optimized SQLite run was killed by the watchdog after 2 seconds, after
3,699 successful results had been durably written. A resume of the same output
directory reported 3,699 checkpoint skips and attempted only the remaining 60
functions. It retained all 3,699 prior successes, added 53 more, and retried
the seven problematic functions. The final JSONL had 3,759 unique addresses,
zero duplicate rows and no lost previously validated result; the engine exited
with errors for the seven functions that again exceeded worker resources.

This test exposed and fixed a recovery defect: retries previously appended a
second error row for the same address. JSONL resume now atomically compacts stale
error rows and duplicate successes before appending retried outcomes. A unit
test covers this behavior. The abrupt-kill test verifies durable success
preservation; it does not turn the remaining pathological-function failures
into successful results.

## Autonomous PowerShell orchestrator

`scripts/Invoke-GhidrustNativeBatch.ps1` reads one binary path per line from a
manifest, starts each native batch run under `memory_guard.py`, stores every
binary in a deterministic isolated directory, appends watchdog/orchestrator
logs, stops on nonzero exit, and always resumes matching checkpoints. It binds
the output root to the CLI SHA-256 and refuses a different build, so changing
builds requires a new output root and cannot overwrite prior results. It does
not touch the RustStudio worktree or its existing results.

Create `authorized-binaries.txt` with one authorized binary path per line (lines
starting with `#` are ignored), then run in PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  C:\Tools\Reverse\Ghidrust-batch\scripts\Invoke-GhidrustNativeBatch.ps1 `
  -Manifest C:\path\authorized-binaries.txt `
  -ExePath C:\Tools\Reverse\Ghidrust-batch\target\release\ghidrust.exe `
  -OutputRoot C:\path\native-batch-results `
  -Workers 8 -MemoryGiB 4 -HeadroomMiB 256 `
  -FunctionTimeoutSeconds 120 -RunTimeoutSeconds 7200
```

The same command resumes after a process or machine interruption. Each
successful output and checkpoint stays in its per-binary folder. A nonzero
batch result stops the manifest and retains the partial output for inspection
and a later resume. The zlib one-binary manifest was run twice under an outer
watchdog: first run produced 179/179 records; second run skipped all 179 and
did not append duplicates.

## Decision and remaining work

The synthetic CFG tests and corrected SQLite runs validate bounded region
construction and complete fallback rendering for the exercised graphs. The
identified SQLite region explosions and worker crashes are resolved in the
full runs; one optimized SQLite function and four ripgrep entries still fail at
decoding and remain explicitly marked as errors. Ten repeated ripgrep runs
showed no memory growth or output-count drift. These results establish
operational stability for these open-source inputs, not semantic equivalence
for arbitrary binaries. Decoder coverage and direct source mapping for stripped
SQLite functions remain open limitations.
