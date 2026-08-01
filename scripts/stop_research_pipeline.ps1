[CmdletBinding()]
param(
    [string]$Environment = "healthcare-lab",
    [string]$ProjectRoot = "",
    [string]$VagrantRoot = "",
    [switch]$HaltVMs,
    [switch]$KeepTunnel
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Join-Path $PSScriptRoot ".."
}
$ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path

if ([string]::IsNullOrWhiteSpace($VagrantRoot)) {
    $VagrantRoot = if ($env:VAGRANT_LAB_ROOT) {
        $env:VAGRANT_LAB_ROOT
    }
    else {
        "D:\vagrant-lab"
    }
}

$taskName = "Healthcare Risk Pipeline - $Environment"
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task -and $task.State -eq "Running") {
    Write-Host "Stopping scheduled task instance: $taskName"
    Stop-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds 2
}

Write-Host "Stopping live pipeline for $Environment ..."
$pipelineProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match '^python(w)?\.exe$' -and
        $_.CommandLine -match 'live_pipeline\.py' -and
        $_.CommandLine -match [regex]::Escape($Environment)
    }

foreach ($process in $pipelineProcesses) {
    Write-Host "Stopping pipeline PID $($process.ProcessId)"
    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
}

$lockFile = Join-Path $ProjectRoot "logs\$Environment\live_pipeline.lock"
Start-Sleep -Seconds 1
Remove-Item -LiteralPath $lockFile -Force -ErrorAction SilentlyContinue

if (-not $KeepTunnel) {
    Write-Host "Stopping OpenSearch SSH tunnel ..."
    $tunnelProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -eq "ssh.exe" -and
            $_.CommandLine -match '127\.0\.0\.1:9200:127\.0\.0\.1:9200'
        }

    foreach ($process in $tunnelProcesses) {
        Write-Host "Stopping tunnel PID $($process.ProcessId)"
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath (Join-Path $ProjectRoot "logs\$Environment\opensearch_tunnel.json") `
        -Force -ErrorAction SilentlyContinue
}

Remove-Item -LiteralPath (Join-Path $ProjectRoot "logs\$Environment\pipeline_process.json") `
    -Force -ErrorAction SilentlyContinue

if ($HaltVMs) {
    if (-not (Test-Path -LiteralPath $VagrantRoot -PathType Container)) {
        throw "VagrantRoot does not exist: $VagrantRoot"
    }

    Write-Host "Halting Vagrant machines safely ..."
    $vmOrder = @(
        "attacker-kali",
        "user-pc-01",
        "admin-pc-01",
        "zeek-sensor-02",
        "ehr-app-server-01",
        "ehr-db-server-01",
        "file-server-01",
        "monitoring-server-01"
    )

    Push-Location $VagrantRoot
    try {
        foreach ($vm in $vmOrder) {
            Write-Host "Halting $vm ..."
            & vagrant halt $vm
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "vagrant halt failed for $vm with code $LASTEXITCODE"
            }
        }
    }
    finally {
        Pop-Location
    }
}

Write-Host "Research pipeline stopped." -ForegroundColor Green
