"""Initialize the built Ghidrust MCP server and request its tool catalog."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=pathlib.Path)
    args = parser.parse_args()
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "ghidrust-mcp-smoke", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    payload = "".join(json.dumps(item) + "\n" for item in requests)
    proc = subprocess.run(
        [str(args.exe.resolve()), "mcp"],
        input=payload,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    responses = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return proc.returncode
    if not any(item.get("id") == 1 and "result" in item for item in responses):
        raise RuntimeError("MCP initialize response missing")
    catalog = next((item for item in responses if item.get("id") == 2), None)
    if not catalog or "tools" not in catalog.get("result", {}):
        raise RuntimeError("MCP tools/list response missing or malformed")
    print(json.dumps({"initialize": "ok", "tools": len(catalog["result"]["tools"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
