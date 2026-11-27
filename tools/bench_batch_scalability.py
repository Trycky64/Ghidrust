#!/usr/bin/env python3
"""Generate redistributable PE fixtures and run protected native-batch scaling tests."""

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import subprocess
import sys
import time


def make_pe(count: int) -> bytes:
    step, text_rva = 0x40, 0x1000
    helper_size = 0x20
    text_size = count * step + helper_size
    pdata_rva = (text_rva + text_size + 0xFFF) & ~0xFFF
    pdata_size = count * 12 + 16
    text_raw = (text_size + 0x1FF) & ~0x1FF
    pdata_raw = (pdata_size + 0x1FF) & ~0x1FF
    text_ptr, pdata_ptr = 0x400, 0x400 + text_raw
    data = bytearray(pdata_ptr + pdata_raw)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, text_rva)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, opt + 56, max(0x5000, (pdata_rva + pdata_size + 0xFFF) & ~0xFFF))
    struct.pack_into("<I", data, opt + 60, 0x400)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<II", data, opt + 112 + 3 * 8, pdata_rva, pdata_size)

    def section(at: int, name: bytes, size: int, rva: int, raw_size: int, raw_ptr: int, flags: int) -> None:
        data[at : at + 8] = name
        struct.pack_into("<IIII", data, at + 8, size, rva, raw_size, raw_ptr)
        struct.pack_into("<I", data, at + 36, flags)

    table = opt + 0xF0
    section(table, b".text\0\0\0", text_size, text_rva, text_raw, text_ptr, 0x60000020)
    section(table + 40, b".pdata\0\0", pdata_size, pdata_rva, pdata_raw, pdata_ptr, 0x40000040)
    data[text_ptr : text_ptr + text_raw] = b"\xCC" * text_raw
    helper_rva = text_rva + count * step
    for i in range(count):
        rva, kind = text_rva + i * step, i % 5
        if kind == 0:  # arithmetic and return
            code = b"\xB8" + struct.pack("<I", i) + b"\x83\xC0\x01\xC3"
        elif kind == 1:  # conditional branch and two return paths
            code = b"\x85\xC9\x74\x06\xB8" + struct.pack("<I", i) + b"\xC3\x31\xC0\xC3"
        elif kind == 2:  # relative call to a shared helper
            code = b"\xE8" + struct.pack("<i", helper_rva - (rva + 5)) + b"\xC3"
        elif kind == 3:  # switch-like compare/jump tree
            code = bytes([0x83, 0xF9, 0, 0x74, 11, 0x83, 0xF9, 1, 0x74, 12,
                          0xB8, 3, 0, 0, 0, 0xC3, 0xB8, 1, 0, 0, 0, 0xC3,
                          0xB8, 2, 0, 0, 0, 0xC3])
        else:  # def-use chain
            code = b"\xB8" + struct.pack("<I", i) + bytes([0x83, 0xC0, 1]) * 10 + b"\xC3"
        off = text_ptr + i * step
        data[off : off + len(code)] = code
        struct.pack_into("<III", data, pdata_ptr + i * 12, rva, rva + len(code), pdata_rva + count * 12)
    data[text_ptr + count * step] = 0xC3
    data[pdata_ptr + count * 12 : pdata_ptr + count * 12 + 4] = bytes([1, 0, 0, 0])
    return bytes(data)


def guarded_json(guard: pathlib.Path, exe: pathlib.Path, args: list[str], timeout: int) -> tuple[dict, dict, float]:
    cmd = [sys.executable, str(guard), "--memory-gib", "4", "--headroom-mib", "256",
           "--timeout", str(timeout), "--", str(exe), *args]
    started = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
    elapsed_ms = (time.perf_counter() - started) * 1000
    decoder = json.JSONDecoder()
    result, consumed = decoder.raw_decode(proc.stdout.lstrip())
    rest = proc.stdout.lstrip()[consumed:].strip().splitlines()
    guard_result = json.loads(rest[-1])
    if proc.returncode != 0 or guard_result.get("reason") != "completed":
        raise RuntimeError(json.dumps({"exit": proc.returncode, "result": result,
                                       "guard": guard_result, "stderr": proc.stderr[-4000:]}))
    return result, guard_result, elapsed_ms


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=pathlib.Path)
    parser.add_argument("--counts", default="100,1000,2000,5000,10000")
    parser.add_argument("--workers", default="1,2,4,8,16")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--direct-workers", type=int, default=8)
    parser.add_argument("--report", type=pathlib.Path, default=pathlib.Path("batch-scalability-report.json"))
    parser.add_argument("--keep-artifacts", type=pathlib.Path, default=pathlib.Path("batch-scalability-artifacts"))
    args = parser.parse_args()
    exe = args.exe.resolve()
    guard = pathlib.Path(__file__).with_name("memory_guard.py").resolve()
    counts = [int(v) for v in args.counts.split(",")]
    worker_counts = [int(v) for v in args.workers.split(",")]
    report = []
    root = args.keep_artifacts.resolve()
    root.mkdir(parents=True, exist_ok=True)
    report_path = args.report.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    for count in counts:
        image = root / f"synthetic-{count}.exe"
        image.write_bytes(make_pe(count))
        pe_rows = []
        for requested in worker_counts:
            out = root / f"pe-{count}-w{requested}"
            result, guard_result, external_ms = guarded_json(
                guard, exe,
                ["batch-decompile", str(image), "--workers", str(requested),
                 "--memory-budget-gb", "4", "--output", str(out), "--no-resume", "--json"],
                args.timeout,
            )
            output = out / f"synthetic-{count}_exe.jsonl"
            lines = output.read_text(encoding="utf-8").splitlines()
            records = [json.loads(line) for line in lines]
            if (result["total_functions"] != count or result["succeeded"] != count
                    or result["failed"] != 0 or len(records) != count
                    or len({record["address"] for record in records}) != count
                    or any(record["status"] != "ok" or not record.get("pseudo_c") for record in records)):
                raise RuntimeError(f"count {count} failed validation at requested workers {requested}: {result}")
            pe_rows.append({
                "requested_workers": result["requested_workers"],
                "effective_workers": result["effective_workers"],
                "external_ms": round(external_ms, 2),
                "engine_ms": round(result["total_wall_ms"], 2),
                "success": result["succeeded"], "failed": result["failed"],
                "fn_per_sec": round(result["throughput_fn_per_sec"], 2),
                "job_peak_mib": round(guard_result["job_peak_committed_bytes"] / 1048576, 2),
                "system_commit_peak_gib": round(guard_result["peak_system_commit_bytes"] / 1073741824, 2),
                "cpu_machine_pct": round(result["cpu_utilization_pct"], 2),
                "load_ms": round(result["load_ms"], 2),
                "fingerprint_ms": round(result["fingerprint_ms"], 2),
                "analyzer_ms": round(result["analyzer_ms"], 2),
                "enumeration_ms": round(result["enumeration_ms"], 2),
                "disassembly_ms": round(result["disassembly_ms"], 2),
                "decoder_init_ms": round(result["decoder_init_ms"], 2),
                "metadata_clone_ms": round(result["metadata_clone_ms"], 2),
                "ipc_request_serialize_ms": round(result["ipc_serialize_ms"], 2),
                "ipc_request_deserialize_ms": round(result["ipc_request_deserialize_ms"], 2),
                "ipc_response_serialize_ms": round(result["ipc_response_serialize_ms"], 2),
                "ipc_response_deserialize_ms": round(result["ipc_deserialize_ms"] - result["ipc_request_deserialize_ms"], 2),
                "ipc_write_ms": round(result["ipc_write_ms"], 2),
                "ipc_wait_ms_including_decompile": round(result["ipc_wait_ms"], 2),
                "decompile_sum_ms": round(result["total_decompile_us"] / 1000, 2),
                "export_ms": round(result["export_ms"], 2),
                "checkpoint_ms": round(result["checkpoint_ms"], 2),
                "worker_start_ms": round(result["worker_start_ms"], 2),
                "worker_restart_start_ms": round(result["worker_restart_start_ms"], 2),
                "worker_restarts": result["worker_restarts"],
                "export_bytes": output.stat().st_size,
            })
        direct_out = root / f"direct-{count}"
        direct, direct_guard, direct_external_ms = guarded_json(
            guard, exe,
            ["batch-synthetic-bench", str(count), "--workers", str(args.direct_workers),
             "--output", str(direct_out), "--json"], args.timeout,
        )
        direct["external_ms"] = round(direct_external_ms, 2)
        direct["job_peak_mib"] = round(direct_guard["job_peak_committed_bytes"] / 1048576, 2)
        direct["system_commit_peak_gib"] = round(direct_guard["peak_system_commit_bytes"] / 1073741824, 2)
        direct["export_bytes"] = (direct_out / "synthetic.jsonl").stat().st_size
        if direct["succeeded"] != count or direct["failed"] != 0:
            raise RuntimeError(f"direct synthetic count {count} failed: {direct}")
        row = {
            "functions": count,
            "notes": {
                "phase_sum_semantics": "disassembly, IPC wait, and worker decode timings are cumulative across workers and may exceed wall time",
                "global_commit": "GetPerformanceInfo system commit; includes unrelated activity outside the guarded job",
                "job_memory": "Windows Job Object committed-memory peak, aggregate across parent and descendants",
            },
            "pe_runs": pe_rows,
            "direct_synthetic": direct,
        }
        report.append(row)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(row, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"benchmark stopped: {error}", file=sys.stderr)
        raise SystemExit(1)
