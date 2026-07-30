[CmdletBinding()]
param(
    [string]$Environment = "healthcare-lab",
    [int]$IntervalSeconds = 30,
    [int]$WazuhSize = 100,
    [int]$CommandTimeoutSeconds = 120,
    [int]$ScpTimeoutSeconds = 30,
    [string]$ZeekLocalSource = "",
    [switch]$Continuous,
    [switch]$SkipWazuh,
    [switch]$SkipZeek,
    [switch]$SkipZeekCopy,
    [switch]$SkipPublish,
    [switch]$DryRun,
    [switch]$NoRefresh,
    [switch]$StopOnError,
    [switch]$VerboseLogging
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VirtualEnvironmentPython = Join-Path `
    $ProjectRoot `
    "venv\Scripts\python.exe"

if (Test-Path $VirtualEnvironmentPython) {
    $PythonExecutable = $VirtualEnvironmentPython
}
else {
    $PythonExecutable = "python"
}

$PipelineScript = Join-Path `
    $PSScriptRoot `
    "live_pipeline.py"

$PipelineArguments = @(
    $PipelineScript,
    "--environment",
    $Environment,
    "--interval-seconds",
    $IntervalSeconds,
    "--wazuh-size",
    $WazuhSize,
    "--command-timeout-seconds",
    $CommandTimeoutSeconds,
    "--scp-timeout-seconds",
    $ScpTimeoutSeconds
)

if ($Continuous) {
    $PipelineArguments += "--continuous"
}

if ($SkipWazuh) {
    $PipelineArguments += "--skip-wazuh"
}

if ($SkipZeek) {
    $PipelineArguments += "--skip-zeek"
}

if ($SkipZeekCopy) {
    $PipelineArguments += "--skip-zeek-copy"
}

if ($SkipPublish) {
    $PipelineArguments += "--skip-publish"
}

if ($DryRun) {
    $PipelineArguments += "--dry-run"
}

if ($NoRefresh) {
    $PipelineArguments += "--no-refresh"
}

if ($StopOnError) {
    $PipelineArguments += "--stop-on-error"
}

if ($VerboseLogging) {
    $PipelineArguments += "--verbose"
}

if ($ZeekLocalSource) {
    $PipelineArguments += @(
        "--zeek-local-source",
        $ZeekLocalSource
    )
}

& $PythonExecutable @PipelineArguments
exit $LASTEXITCODE