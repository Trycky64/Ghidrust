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

| Binary | Functions found | Successful | Failed | Wall time | Job peak | Export size | Max successful instructions |
|---|---:|---:|---:|---:|---:|---:|---:|
| zlib zpipe `-O0` | 169 | 169 | 0 | 190 ms | 98 MiB | 20.9 MB | 1,258 |
| zlib zpipe `-O2` | 179 | 179 | 0 | 70 ms | 43 MiB | 5.6 MB | 1,977 |
| SQLite shell `-O0` | 4,109 | 4,105 | 4 | 6.67 s | 3,841 MiB | 162.0 MB | 3,847 |
| SQLite shell `-O2` | 3,759 | 3,752 | 7 | 3.89 s | 3,841 MiB | 86.2 MB | 1,868 |

No successful output reached the default 4,096-instruction cap. Failed functions
have no instruction count because their workers exited before returning a
response. The CLI currently has no `--max-insns-per-fn` override or explicit
truncated flag, so this does not establish that all candidate functions were
complete. The SQLite function-start analyzer reported 239 overlapping pairs in
the optimized build; one candidate entry failed with “no instructions”, so
enumeration coverage includes false-positive starts and needs source-symbol
cross-checking.

### Source-to-output inspection

The zpipe PE files retain MinGW symbols. The functions `def`, `inf`, `zerr` and
`main` were mapped from the export JSONL addresses to `nm` symbols and compared
with `examples/zpipe.c`. Both loops in `def` and `inf` were represented as two
loops in the emitted structure metadata. The source `switch` in `zerr` appeared
as branch/goto regions rather than a C `switch`; the output retains low-level
register and memory operations and generic `FUN_...` names. Lift ratios on these
four ranged from 99.8% to 100%, but that is not equivalent to source-level
readability or proof of semantic equivalence. The byte-for-byte round-trip is
an application test, not a per-function semantic oracle.

The source symbol `fts5SnippetFunction` shows a large optimization effect:

| Build | Result for this function | Function metadata |
|---|---|---|
| SQLite `-O0` | Worker failed from memory exhaustion even when selected alone with one worker | no completed pseudocode |
| SQLite `-O2` | Success; 24 instructions, 3 regions, ~0.4 ms decompile time | 100% lift ratio |

The full SQLite `-O0` run also failed on `piecemealOutput`,
`fts5SetupTokendataIter`, `fts5AsciiTokenize` and `fts5SnippetFunction`. At
`-O2`, worker exits affected `fts5MergePrefixLists`, `sqlite3FindFunction`
(two candidate starts), `exprSelectUsage` (two starts), and `heightOfSelect`;
another false-positive start at `sqlite3VdbeAddOp4Int` had no decodable
instructions. All analyzer passes completed successfully in both builds.

### CFG expansion and pseudocode size

The principal operational blocker is extreme region expansion. A zlib function
with 45 blocks and 936 instructions emitted 2,866 regions and 20.2 MB of
pseudocode. In SQLite `-O0`, `idxPopulateOneStat1` had 54 blocks, 6 loops, 740
IR operations and 11,105 regions; its JSONL pseudocode was 21.97 MB. In SQLite
`-O2`, a 35-block, 307-instruction function produced 8,896 regions and 14.92
MB. These outputs are present and were not truncated by the instruction cap,
but their size and the subsequent memory failures make the current structuring
path unsuitable for unattended real-world batches containing such CFGs.

At the end of SQLite `-O2`, the watchdog observed a Job peak of
4,232,069,120 bytes (3.94 GiB), below the requested 4-GiB ceiling, while a
650-MiB allocation was refused and workers exited. The configured 256-MiB
headroom is not a precise hard stop: the Windows Job peak can overshoot its
lower internal limit during failed allocations. The user-visible 4-GiB ceiling
was respected in this run, but the narrow remaining margin is not suitable for
larger unfiltered jobs.

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

The zlib binaries validate the basic PE pipeline, source symbol mapping,
loop/switch control-flow retention, JSONL streaming and checkpoint resume.
SQLite reveals unresolved memory/CFG expansion and seven optimized-build worker
failures. Testing did not proceed to ripgrep or another more complex project.
No prolonged large-scale real-binary stability claim is made. The native
orchestrator is ready for controlled authorized batches only after these
structuring/memory issues and the remaining SQLite functions are addressed.
