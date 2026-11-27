[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Manifest,
    [string]$ExePath = (Join-Path $PSScriptRoot "..\target\release\ghidrust.exe"),
    [string]$Python = "python",
    [string]$OutputRoot = (Join-Path $PSScriptRoot "..\native-batch-results"),
    [ValidateRange(1, 16)]
    [int]$Workers = 8,
    [ValidateRange(1, 4)]
    [int]$MemoryGiB = 4,
    [ValidateRange(1, 86400)]
    [int]$FunctionTimeoutSeconds = 120,
    [ValidateRange(1, 86400)]
    [int]$RunTimeoutSeconds = 7200,
    [ValidateRange(0, 1024)]
    [int]$HeadroomMiB = 256
)

$ErrorActionPreference = "Stop"
$manifestPath = (Resolve-Path -LiteralPath $Manifest).Path
$exe = (Resolve-Path -LiteralPath $ExePath).Path
$pythonCommand = Get-Command $Python -ErrorAction Stop
$pythonExe = $pythonCommand.Source
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$guard = Join-Path $repoRoot "tools\memory_guard.py"
if (-not (Test-Path -LiteralPath $guard -PathType Leaf)) {
    throw "Watchdog not found: $guard"
}

$outputRootPath = [IO.Path]::GetFullPath($OutputRoot)
[IO.Directory]::CreateDirectory($outputRootPath) | Out-Null
$engineHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$markerPath = Join-Path $outputRootPath "engine-build.json"
if (Test-Path -LiteralPath $markerPath) {
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.exe_sha256 -ne $engineHash) {
        throw "Output root belongs to a different CLI build. Choose a new OutputRoot to preserve old results."
    }
} else {
    $marker = [ordered]@{
        exe_path = $exe
        exe_sha256 = $engineHash
        workers_requested = $Workers
        memory_budget_gib = $MemoryGiB
        function_timeout_seconds = $FunctionTimeoutSeconds
        created_utc = [DateTime]::UtcNow.ToString("o")
    }
    [IO.File]::WriteAllText(
        $markerPath,
        (($marker | ConvertTo-Json -Compress) + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
}

$stateLog = Join-Path $outputRootPath "orchestrator-runs.jsonl"
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$entries = Get-Content -LiteralPath $manifestPath
foreach ($entry in $entries) {
    $binaryText = $entry.Trim()
    if (-not $binaryText -or $binaryText.StartsWith("#")) { continue }
    $binary = (Resolve-Path -LiteralPath $binaryText).Path
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "Manifest entry is not a file: $binaryText"
    }

    $identity = $binary.ToLowerInvariant()
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $identityHash = [BitConverter]::ToString(
            $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity))
        ).Replace("-", "").Substring(0, 12).ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    $leaf = [IO.Path]::GetFileName($binary)
    $runDir = Join-Path $outputRootPath "$leaf.$identityHash"
    [IO.Directory]::CreateDirectory($runDir) | Out-Null

    $started = [DateTime]::UtcNow
    Write-Host "[$($started.ToString('o'))] batch start workers=$Workers/$Workers path=$binary output=$runDir"
    $guardArgs = @(
        $guard,
        "--memory-gib", "$MemoryGiB",
        "--headroom-mib", "$HeadroomMiB",
        "--timeout", "$RunTimeoutSeconds",
        "--log", (Join-Path $runDir "watchdog.jsonl"),
        "--",
        $exe, "batch-decompile", $binary,
        "--workers", "$Workers",
        "--memory-budget-gb", "$MemoryGiB",
        "--function-timeout-seconds", "$FunctionTimeoutSeconds",
        "--output", $runDir,
        "--resume", "--json"
    )
    & $pythonExe @guardArgs
    $exitCode = $LASTEXITCODE
    $finished = [DateTime]::UtcNow
    $record = [ordered]@{
        binary = $binary
        output_dir = $runDir
        started_utc = $started.ToString("o")
        finished_utc = $finished.ToString("o")
        elapsed_seconds = [Math]::Round(($finished - $started).TotalSeconds, 3)
        workers_requested = $Workers
        exit_code = $exitCode
        watchdog_log = Join-Path $runDir "watchdog.jsonl"
    }
    [IO.File]::AppendAllText(
        $stateLog,
        (($record | ConvertTo-Json -Compress) + "`n"),
        $utf8NoBom
    )
    if ($exitCode -ne 0) {
        throw "Batch stopped with exit code $exitCode. Results and checkpoint are preserved in $runDir; rerun the same command to resume."
    }
    Write-Host "[$($finished.ToString('o'))] batch complete elapsed=$($record.elapsed_seconds)s output=$runDir"
}
