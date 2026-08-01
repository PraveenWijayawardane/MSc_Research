[CmdletBinding()]
param(
    [string]$Environment = "healthcare-lab",
    [string]$ProjectRoot = "",
    [string]$VagrantRoot = "",
    [string]$PythonExecutable = "",
    [int]$IntervalSeconds = 30,
    [int]$StartupTimeoutSeconds = 600,
    [string]$MonitoringHost = "192.168.100.100",
    [int]$MonitoringSshPort = 22,
    [string]$MonitoringSshUser = "vagrant",
    [string]$MonitoringSshKey = "",
    [string]$ExpectedMonitoringHostname = "monitoring-server-01",
    [switch]$SkipVmStartup,
    [switch]$SkipTunnel,
    [switch]$Detach
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Resolve-ExistingDirectory {
    param(
        [string]$Value,
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Description was not provided."
    }

    $resolved = Resolve-Path -LiteralPath $Value -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $resolved.Path -PathType Container)) {
        throw "$Description is not a directory: $Value"
    }
    return $resolved.Path
}

function Resolve-ExistingFile {
    param(
        [string]$Value,
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Description was not provided."
    }

    $resolved = Resolve-Path -LiteralPath $Value -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $resolved.Path -PathType Leaf)) {
        throw "$Description is not a file: $Value"
    }
    return $resolved.Path
}

function Resolve-PythonExecutable {
    param(
        [string]$Requested,
        [string]$ResolvedProjectRoot
    )

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        $candidates += $Requested
    }
    if (-not [string]::IsNullOrWhiteSpace($env:HEALTHCARE_RISK_PYTHON)) {
        $candidates += $env:HEALTHCARE_RISK_PYTHON
    }

    $projectParent = Split-Path -Parent $ResolvedProjectRoot
    $candidates += (Join-Path $projectParent "venv\Scripts\python.exe")
    $candidates += (Join-Path $ResolvedProjectRoot "venv\Scripts\python.exe")

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and
            (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        return $pythonCommand.Source
    }

    throw "Unable to find Python. Provide -PythonExecutable or set HEALTHCARE_RISK_PYTHON."
}

function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory
    )

    Push-Location $WorkingDirectory
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$FilePath exited with code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

function Wait-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $connection = Test-NetConnection `
            -ComputerName $HostName `
            -Port $Port `
            -WarningAction SilentlyContinue

        if ($connection.TcpTestSucceeded) {
            return
        }
        Start-Sleep -Seconds 5
    }

    throw "Timed out waiting for $HostName`:$Port."
}

function Wait-MonitoringIdentity {
    param(
        [string]$SshExecutable,
        [string]$HostName,
        [int]$Port,
        [string]$User,
        [string]$IdentityFile,
        [string]$KnownHostsFile,
        [string]$ExpectedHostname,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $target = "$User@$HostName"

    while ((Get-Date) -lt $deadline) {
        $output = & $SshExecutable `
            -4 `
            -T `
            -o BatchMode=yes `
            -o ConnectTimeout=10 `
            -o StrictHostKeyChecking=accept-new `
            -o "UserKnownHostsFile=$KnownHostsFile" `
            -i $IdentityFile `
            -p $Port `
            $target `
            "hostname" 2>&1

        $sshExitCode = $LASTEXITCODE
        $reportedHostname = ($output | Select-Object -Last 1).ToString().Trim()

        if ($sshExitCode -eq 0 -and $reportedHostname -eq $ExpectedHostname) {
            Write-Host "Verified monitoring host identity: $reportedHostname"
            return
        }

        if ($sshExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($reportedHostname)) {
            throw "SSH endpoint $HostName`:$Port returned hostname '$reportedHostname', expected '$ExpectedHostname'. Refusing to create the tunnel."
        }

        Write-Host "Monitoring SSH is not ready yet; retrying in 10 seconds ..."
        Start-Sleep -Seconds 10
    }

    throw "Unable to verify $ExpectedHostname through $HostName`:$Port within $TimeoutSeconds seconds. Check the bridge IP and monitoring-server Vagrant key."
}

function Get-LivePipelineProcess {
    param([string]$EnvironmentId)

    return Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^python(w)?\.exe$' -and
            $_.CommandLine -match 'live_pipeline\.py' -and
            $_.CommandLine -match [regex]::Escape($EnvironmentId)
        }
}

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Join-Path $PSScriptRoot ".."
}
$ProjectRoot = Resolve-ExistingDirectory -Value $ProjectRoot -Description "ProjectRoot"

if ([string]::IsNullOrWhiteSpace($VagrantRoot)) {
    if (-not [string]::IsNullOrWhiteSpace($env:VAGRANT_LAB_ROOT)) {
        $VagrantRoot = $env:VAGRANT_LAB_ROOT
    }
    else {
        $VagrantRoot = "D:\vagrant-lab"
    }
}
$VagrantRoot = Resolve-ExistingDirectory -Value $VagrantRoot -Description "VagrantRoot"
$PythonExecutable = Resolve-PythonExecutable -Requested $PythonExecutable -ResolvedProjectRoot $ProjectRoot

if ([string]::IsNullOrWhiteSpace($MonitoringSshKey)) {
    $MonitoringSshKey = Join-Path `
        $VagrantRoot `
        ".vagrant\machines\monitoring-server-01\virtualbox\private_key"
}
$MonitoringSshKey = Resolve-ExistingFile -Value $MonitoringSshKey -Description "MonitoringSshKey"

$logsDirectory = Join-Path $ProjectRoot "logs\$Environment"
New-Item -ItemType Directory -Path $logsDirectory -Force | Out-Null
$tunnelStateFile = Join-Path $logsDirectory "opensearch_tunnel.json"
$pipelineStateFile = Join-Path $logsDirectory "pipeline_process.json"
$knownHostsFile = Join-Path $logsDirectory "monitoring_known_hosts"

Write-Host "Healthcare risk research startup"
Write-Host "Environment       : $Environment"
Write-Host "Project           : $ProjectRoot"
Write-Host "Vagrant lab       : $VagrantRoot"
Write-Host "Python            : $PythonExecutable"
Write-Host "Monitoring SSH    : $MonitoringSshUser@$MonitoringHost`:$MonitoringSshPort"
Write-Host "Monitoring key    : $MonitoringSshKey"

$existingPipeline = Get-LivePipelineProcess -EnvironmentId $Environment
if ($existingPipeline) {
    Write-Host "Pipeline is already running. PID: $($existingPipeline.ProcessId)" -ForegroundColor Yellow
    exit 0
}

if (-not $SkipVmStartup) {
    Write-Step "Starting Vagrant machines in dependency order"
    $vmOrder = @(
        "monitoring-server-01",
        "ehr-db-server-01",
        "ehr-app-server-01",
        "file-server-01",
        "user-pc-01",
        "admin-pc-01",
        "attacker-kali",
        "zeek-sensor-02"
    )

    foreach ($vm in $vmOrder) {
        Write-Host "Starting/checking $vm ..."
        Invoke-Native -FilePath "vagrant" -Arguments @("up", $vm) -WorkingDirectory $VagrantRoot
    }
}

$sshExecutable = (Get-Command ssh.exe -ErrorAction Stop).Source

if (-not $SkipTunnel) {
    Write-Step "Verifying the bridged monitoring-server SSH endpoint"
    Wait-TcpPort `
        -HostName $MonitoringHost `
        -Port $MonitoringSshPort `
        -TimeoutSeconds $StartupTimeoutSeconds

    Wait-MonitoringIdentity `
        -SshExecutable $sshExecutable `
        -HostName $MonitoringHost `
        -Port $MonitoringSshPort `
        -User $MonitoringSshUser `
        -IdentityFile $MonitoringSshKey `
        -KnownHostsFile $knownHostsFile `
        -ExpectedHostname $ExpectedMonitoringHostname `
        -TimeoutSeconds $StartupTimeoutSeconds

    Write-Step "Ensuring the IPv4 OpenSearch SSH tunnel"
    $listener = Get-NetTCPConnection `
        -LocalAddress "127.0.0.1" `
        -LocalPort 9200 `
        -State Listen `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($listener) {
        $owner = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
        if (-not $owner -or $owner.ProcessName -ne "ssh") {
            throw "Port 127.0.0.1:9200 is already owned by a non-SSH process."
        }
        Write-Host "Existing SSH tunnel listener found. PID: $($listener.OwningProcess)"
    }
    else {
        $sshArguments = @(
            "-4",
            "-N",
            "-T",
            "-o", "BatchMode=yes",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=$knownHostsFile",
            "-i", $MonitoringSshKey,
            "-p", $MonitoringSshPort.ToString(),
            "-L", "127.0.0.1:9200:127.0.0.1:9200",
            "$MonitoringSshUser@$MonitoringHost"
        )

        $tunnelProcess = Start-Process `
            -FilePath $sshExecutable `
            -ArgumentList $sshArguments `
            -WorkingDirectory $VagrantRoot `
            -WindowStyle Hidden `
            -PassThru

        [ordered]@{
            environment_id = $Environment
            pid = $tunnelProcess.Id
            started_at = (Get-Date).ToString("o")
            local_endpoint = "127.0.0.1:9200"
            remote_endpoint = "$MonitoringSshUser@$MonitoringHost`:$MonitoringSshPort"
            expected_hostname = $ExpectedMonitoringHostname
        } | ConvertTo-Json | Set-Content -LiteralPath $tunnelStateFile -Encoding UTF8

        Wait-TcpPort -HostName "127.0.0.1" -Port 9200 -TimeoutSeconds 60
        Write-Host "OpenSearch tunnel started. PID: $($tunnelProcess.Id)"
    }
}

Write-Step "Running research preflight"
$preflightArguments = @(
    (Join-Path $ProjectRoot "scripts\research_preflight.py"),
    "--environment", $Environment,
    "--repair-stale-lock",
    "--timeout-seconds", "15",
    "--max-zeek-age-seconds", "600"
)
$preflightDeadline = (Get-Date).AddSeconds($StartupTimeoutSeconds)
$preflightSucceeded = $false

while ((Get-Date) -lt $preflightDeadline) {
    Push-Location $ProjectRoot
    try {
        & $PythonExecutable @preflightArguments
        $preflightExitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    if ($preflightExitCode -eq 0) {
        $preflightSucceeded = $true
        break
    }

    Write-Warning "Preflight is not ready yet. Retrying in 15 seconds."
    Start-Sleep -Seconds 15
}

if (-not $preflightSucceeded) {
    throw "Research preflight did not pass within $StartupTimeoutSeconds seconds."
}

Write-Step "Starting the continuous live pipeline"
$livePipelineScript = Join-Path $ProjectRoot "scripts\live_pipeline.py"
$pipelineArguments = @(
    $livePipelineScript,
    "--environment", $Environment,
    "--continuous",
    "--interval-seconds", $IntervalSeconds.ToString()
)

$pipelineHelp = & $PythonExecutable $livePipelineScript --help 2>&1
if (($pipelineHelp -join "`n") -match '--log-retention-days') {
    $pipelineArguments += @("--log-retention-days", "30")
}

if ($Detach) {
    $pipelineProcess = Start-Process `
        -FilePath $PythonExecutable `
        -ArgumentList $pipelineArguments `
        -WorkingDirectory $ProjectRoot `
        -WindowStyle Hidden `
        -PassThru

    [ordered]@{
        environment_id = $Environment
        pid = $pipelineProcess.Id
        started_at = (Get-Date).ToString("o")
        interval_seconds = $IntervalSeconds
    } | ConvertTo-Json | Set-Content -LiteralPath $pipelineStateFile -Encoding UTF8

    Write-Host "Pipeline started in the background. PID: $($pipelineProcess.Id)" -ForegroundColor Green
    Write-Host "Health command:"
    Write-Host "  & `"$PythonExecutable`" scripts\pipeline_health_check.py --environment $Environment"
    exit 0
}

[ordered]@{
    environment_id = $Environment
    wrapper_pid = $PID
    started_at = (Get-Date).ToString("o")
    interval_seconds = $IntervalSeconds
} | ConvertTo-Json | Set-Content -LiteralPath $pipelineStateFile -Encoding UTF8

& $PythonExecutable @pipelineArguments
exit $LASTEXITCODE
