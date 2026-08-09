<#
.SYNOPSIS
Runs one controlled Chapter 6 scenario repetition, refreshes telemetry,
validates the required evidence, archives the run, and executes the evaluator.

.EXAMPLE
.\scripts\chapter6\Invoke-Chapter6Scenario.ps1 `
  -ScenarioId B2 `
  -Repetition 1 `
  -VagrantDir "D:\path\to\vagrant-lab"

.NOTES
- Run from the Healthcare-risk-engine repository.
- The script refuses to overwrite an existing final run unless -Overwrite is used.
- It uses the scenario definitions currently aligned with scripts/evaluate_chapter6.py.
- A1 intentionally generates controlled failed SSH authentication in the isolated lab.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("B1","B2","A1","A2","A3","A4","A5","U1")]
    [string]$ScenarioId,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1,5)]
    [int]$Repetition,

    [Parameter(Mandatory = $true)]
    [string]$VagrantDir,

    [string]$Environment = "healthcare-lab",

    # Monday 2026-08-10 10:00 Asia/Colombo. Keeps temporal context controlled.
    [string]$EvaluationStartUTC = "2026-08-10T04:30:00Z",

    [int]$WazuhSize = 500,

    [double]$ValidationPaddingSeconds = 2.0,

    # Give Zeek a few seconds to flush the just-closed connection to conn.log
    # before the pipeline copies the file.
    [ValidateRange(0,30)]
    [int]$ZeekFlushWaitSeconds = 5,

    # Wazuh alerts can arrive a few seconds after the host event.
    # For scenarios that require Wazuh (A1/A5), retry telemetry refresh
    # before rejecting the run.
    [ValidateRange(0,10)]
    [int]$WazuhRetryCount = 4,

    [ValidateRange(1,30)]
    [int]$WazuhRetryWaitSeconds = 5,

    # Short Zeek connections may be written to conn.log a few seconds late.
    [ValidateRange(0,10)]
    [int]$ZeekRetryCount = 4,

    [ValidateRange(1,30)]
    [int]$ZeekRetryWaitSeconds = 5,

    [switch]$SkipPipelineRefresh,

    [switch]$Overwrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ProjectRoot {
    $candidate = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    if (-not (Test-Path (Join-Path $candidate "scripts\evaluate_chapter6.py"))) {
        throw "Could not locate repository root from $PSScriptRoot"
    }
    return $candidate
}

function Get-ScenarioDefinition {
    param([string]$Id)

    # VM names may be changed here if your Vagrantfile uses different machine names.
    $definitions = @{
        "B1" = [ordered]@{
            GroundTruth = "Benign"
            ExpectedClass = "Legitimate"
            SourceIP = "192.168.100.30"
            DestinationIP = "192.168.100.40"
            DestinationPort = 5432
            Protocol = "tcp"
            SourceVM = "ehr-app-server-01"
            RequireWazuh = $false
            WazuhAgentIPs = @("192.168.100.30","192.168.100.40")
            WazuhKeywords = @()
            ExpectedCorrelation = $false
            Description = "Approved EHR application server access to PostgreSQL"
            LinuxCommand = "nc -vz -w 3 192.168.100.40 5432"
        }
        "B2" = [ordered]@{
            GroundTruth = "Benign"
            ExpectedClass = "Low Suspicion"
            SourceIP = "192.168.100.21"
            DestinationIP = "192.168.100.30"
            DestinationPort = 22
            Protocol = "tcp"
            SourceVM = "admin-pc-01"
            RequireWazuh = $false
            WazuhAgentIPs = @("192.168.100.30")
            WazuhKeywords = @()
            ExpectedCorrelation = $false
            Description = "Approved administrator workstation access to EHR application SSH"
            LinuxCommand = "nc -vz -w 3 192.168.100.30 22"
        }
        "A1" = [ordered]@{
            GroundTruth = "Attack"
            ExpectedClass = "Likely Malicious"
            SourceIP = "192.168.100.20"
            DestinationIP = "192.168.100.40"
            DestinationPort = 22
            Protocol = "tcp"
            SourceVM = "user-pc-01"
            RequireWazuh = $true
            WazuhAgentIPs = @("192.168.100.40")
            WazuhKeywords = @("authentication failure","failed password","login failed","invalid user")
            ExpectedCorrelation = $true
            Description = "Controlled failed SSH authentication from workstation to EHR database"
            # BatchMode avoids interactive prompts. Three attempts improve the chance that
            # the DB host/Wazuh records an 'invalid user' authentication event.
            LinuxCommand = "for i in 1 2 3; do ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no invalid-a1@192.168.100.40 true || true; sleep 1; done"
        }
        "A2" = [ordered]@{
            GroundTruth = "Attack"
            ExpectedClass = "Suspicious"
            SourceIP = "192.168.100.20"
            DestinationIP = "192.168.100.40"
            DestinationPort = 5432
            Protocol = "tcp"
            SourceVM = "user-pc-01"
            RequireWazuh = $false
            WazuhAgentIPs = @("192.168.100.40")
            WazuhKeywords = @()
            ExpectedCorrelation = $false
            Description = "Direct workstation access to EHR PostgreSQL service"
            LinuxCommand = "nc -vz -w 3 192.168.100.40 5432"
        }
        "A3" = [ordered]@{
            GroundTruth = "Attack"
            ExpectedClass = "Suspicious"
            SourceIP = "192.168.100.20"
            DestinationIP = "192.168.100.30"
            DestinationPort = 22
            Protocol = "tcp"
            SourceVM = "user-pc-01"
            RequireWazuh = $false
            WazuhAgentIPs = @("192.168.100.30")
            WazuhKeywords = @()
            ExpectedCorrelation = $false
            Description = "Workstation access to EHR application SSH service"
            LinuxCommand = "nc -vz -w 3 192.168.100.30 22"
        }
        "A4" = [ordered]@{
            GroundTruth = "Attack"
            ExpectedClass = "Suspicious"
            SourceIP = "192.168.100.20"
            DestinationIP = "192.168.100.50"
            DestinationPort = 445
            Protocol = "tcp"
            SourceVM = "user-pc-01"
            RequireWazuh = $false
            WazuhAgentIPs = @("192.168.100.50")
            WazuhKeywords = @()
            ExpectedCorrelation = $false
            Description = "Workstation access to protected SMB/file-server service"
            LinuxCommand = "nc -vz -w 3 192.168.100.50 445"
        }
        "A5" = [ordered]@{
            GroundTruth = "Attack"
            ExpectedClass = "Likely Malicious"
            SourceIP = "192.168.100.30"
            DestinationIP = "192.168.100.40"
            DestinationPort = 5432
            Protocol = "tcp"
            SourceVM = "ehr-app-server-01"
            RequireWazuh = $true
            WazuhAgentIPs = @("192.168.100.30")
            WazuhKeywords = @("privilege escalation","root session","sudo","user changed to root")
            ExpectedCorrelation = $true
            Description = "Privilege activity on EHR app followed by database access"
            LinuxCommand = "sudo -n whoami >/dev/null && sleep 1 && nc -vz -w 3 192.168.100.40 5432"
        }
        "U1" = [ordered]@{
            GroundTruth = "Attack"
            ExpectedClass = "Suspicious"
            SourceIP = "192.168.101.60"
            DestinationIP = "192.168.100.40"
            DestinationPort = 5432
            Protocol = "tcp"
            SourceVM = "attacker-kali"
            RequireWazuh = $false
            WazuhAgentIPs = @("192.168.100.40")
            WazuhKeywords = @()
            ExpectedCorrelation = $false
            Description = "Unknown/unmanaged source access to EHR PostgreSQL"
            LinuxCommand = @'
IFACE=$(ip route get 192.168.100.40 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'); test -n "$IFACE" || exit 20; sudo ip addr del 192.168.101.60/32 dev "$IFACE" 2>/dev/null || true; sudo ip addr add 192.168.101.60/32 dev "$IFACE"; trap 'sudo ip addr del 192.168.101.60/32 dev "$IFACE" 2>/dev/null || true' EXIT; nc -vz -w 3 -s 192.168.101.60 192.168.100.40 5432
'@
        }
    }

    return $definitions[$Id]
}

function Invoke-VagrantLinux {
    param(
        [string]$VmName,
        [string]$Command,
        [string]$WorkingDirectory
    )

    Push-Location $WorkingDirectory
    try {
        Write-Host "Executing on $VmName ..."
        & vagrant ssh $VmName -c $Command
        if ($LASTEXITCODE -ne 0) {
            throw "Scenario command failed on $VmName with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

function Convert-ToEventTime {
    param($Value)
    if ($null -eq $Value -or "$Value".Trim() -eq "") {
        return $null
    }

    $text = "$Value".Trim()
    $number = 0.0
    if ([double]::TryParse(
        $text,
        [System.Globalization.NumberStyles]::Float,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$number
    )) {
        try {
            $whole = [math]::Floor($number)
            $fraction = $number - $whole
            return [DateTimeOffset]::FromUnixTimeSeconds([int64]$whole).AddSeconds($fraction)
        }
        catch {}
    }

    try {
        return [DateTimeOffset]::Parse(
            $text,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal
        )
    }
    catch {
        return $null
    }
}

function Test-InWindow {
    param(
        [DateTimeOffset]$Time,
        [DateTimeOffset]$Start,
        [DateTimeOffset]$End,
        [double]$PaddingSeconds
    )
    $lower = $Start.AddSeconds(-$PaddingSeconds)
    $upper = $End.AddSeconds($PaddingSeconds)
    return ($Time -ge $lower -and $Time -le $upper)
}

function Get-ZeekCandidates {
    param(
        [string]$Path,
        $Scenario,
        [DateTimeOffset]$Start,
        [DateTimeOffset]$End,
        [double]$PaddingSeconds
    )

    $events = Get-Content $Path -Raw | ConvertFrom-Json
    return @($events | Where-Object {
        $eventTime = Convert-ToEventTime $_.ts
        $eventTime -and
        (Test-InWindow $eventTime $Start $End $PaddingSeconds) -and
        $_.'id.orig_h' -eq $Scenario.SourceIP -and
        $_.'id.resp_h' -eq $Scenario.DestinationIP -and
        [int]$_.'id.resp_p' -eq [int]$Scenario.DestinationPort -and
        ("$($_.proto)".ToLowerInvariant() -eq $Scenario.Protocol)
    })
}

function Get-WazuhCandidates {
    param(
        [string]$Path,
        $Scenario,
        [DateTimeOffset]$Start,
        [DateTimeOffset]$End,
        [double]$PaddingSeconds
    )

    $events = Get-Content $Path -Raw | ConvertFrom-Json

    return @($events | Where-Object {
        $source = if ($_._source) { $_._source } else { $_ }

        $timestampValue = if ($source.'@timestamp') {
            $source.'@timestamp'
        }
        elseif ($source.timestamp) {
            $source.timestamp
        }
        else {
            $null
        }

        $eventTime = Convert-ToEventTime $timestampValue
        if (-not $eventTime -or -not (Test-InWindow $eventTime $Start $End $PaddingSeconds)) {
            return $false
        }

        $agentIp = if ($source.agent -and $source.agent.ip) {
            "$($source.agent.ip)"
        }
        elseif ($source.ip) {
            "$($source.ip)"
        }
        else {
            ""
        }

        if (@($Scenario.WazuhAgentIPs).Count -gt 0 -and $agentIp -notin @($Scenario.WazuhAgentIPs)) {
            return $false
        }

        if (@($Scenario.WazuhKeywords).Count -gt 0) {
            $text = ($_ | ConvertTo-Json -Depth 30 -Compress).ToLowerInvariant()
            foreach ($keyword in $Scenario.WazuhKeywords) {
                if ($text.Contains($keyword.ToLowerInvariant())) {
                    return $true
                }
            }
            return $false
        }

        return $true
    })
}

$ProjectRoot = Get-ProjectRoot
$Scenario = Get-ScenarioDefinition $ScenarioId
$RunID = "$ScenarioId-R$Repetition"
$FinalRunDir = Join-Path $ProjectRoot "evaluation\chapter6\final\$RunID"

if (-not (Test-Path $VagrantDir)) {
    throw "Vagrant directory does not exist: $VagrantDir"
}

if (Test-Path $FinalRunDir) {
    if (-not $Overwrite) {
        throw "$RunID already exists at $FinalRunDir. Use -Overwrite only if you intentionally want to replace it."
    }
    Remove-Item $FinalRunDir -Recurse -Force
}

Push-Location $ProjectRoot
try {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "Chapter 6 controlled run: $RunID"
    Write-Host "Scenario: $($Scenario.Description)"
    Write-Host "Expected: $($Scenario.GroundTruth) / $($Scenario.ExpectedClass)"
    Write-Host "Flow: $($Scenario.SourceIP) -> $($Scenario.DestinationIP):$($Scenario.DestinationPort)/$($Scenario.Protocol)"
    Write-Host "============================================================"

    $Start = [DateTimeOffset]::UtcNow
    $StartUTC = $Start.ToString("o")
    Write-Host "StartUTC: $StartUTC"

    Invoke-VagrantLinux `
        -VmName $Scenario.SourceVM `
        -Command $Scenario.LinuxCommand `
        -WorkingDirectory $VagrantDir

    $End = [DateTimeOffset]::UtcNow
    $EndUTC = $End.ToString("o")
    Write-Host "EndUTC  : $EndUTC"

    if (-not $SkipPipelineRefresh) {
        if ($ZeekFlushWaitSeconds -gt 0) {
            Write-Host ""
            Write-Host "Waiting $ZeekFlushWaitSeconds second(s) for Zeek conn.log flush..."
            Start-Sleep -Seconds $ZeekFlushWaitSeconds
        }

        Write-Host ""
        Write-Host "Refreshing live telemetry..."
        & python ".\scripts\live_pipeline.py" `
            --environment $Environment `
            --wazuh-size $WazuhSize `
            --skip-publish
        if ($LASTEXITCODE -ne 0) {
            throw "live_pipeline.py failed with exit code $LASTEXITCODE"
        }
    }

    $ZeekPath = ".\data\$Environment\live_zeek_conn.json"
    $WazuhPath = ".\data\$Environment\live_wazuh_events.json"

    if (-not (Test-Path $ZeekPath)) {
        throw "Zeek JSON not found: $ZeekPath"
    }
    if (-not (Test-Path $WazuhPath)) {
        throw "Wazuh JSON not found: $WazuhPath"
    }

    $ZeekCandidates = @(
        Get-ZeekCandidates `
            -Path $ZeekPath `
            -Scenario $Scenario `
            -Start $Start `
            -End $End `
            -PaddingSeconds $ValidationPaddingSeconds
    )

    $WazuhCandidates = @(
        Get-WazuhCandidates `
            -Path $WazuhPath `
            -Scenario $Scenario `
            -Start $Start `
            -End $End `
            -PaddingSeconds $ValidationPaddingSeconds
    )

    $ZeekCandidateCount = @($ZeekCandidates).Count
    $WazuhCandidateCount = @($WazuhCandidates).Count

    Write-Host ""
    Write-Host "Pre-archive evidence validation"
    Write-Host "  Zeek candidates : $ZeekCandidateCount"
    Write-Host "  Wazuh candidates: $WazuhCandidateCount"

    if ($ZeekCandidateCount -lt 1 -and -not $SkipPipelineRefresh) {
        for ($retry = 1; $retry -le $ZeekRetryCount -and $ZeekCandidateCount -lt 1; $retry++) {
            Write-Host ""
            Write-Host "Zeek evidence not available yet. Retry $retry/$ZeekRetryCount after $ZeekRetryWaitSeconds second(s)..."
            Start-Sleep -Seconds $ZeekRetryWaitSeconds

            & python ".\scripts\live_pipeline.py" `
                --environment $Environment `
                --wazuh-size $WazuhSize `
                --skip-publish

            if ($LASTEXITCODE -ne 0) {
                throw "live_pipeline.py failed during Zeek retry with exit code $LASTEXITCODE"
            }

            $ZeekCandidates = @(
                Get-ZeekCandidates `
                    -Path $ZeekPath `
                    -Scenario $Scenario `
                    -Start $Start `
                    -End $End `
                    -PaddingSeconds $ValidationPaddingSeconds
            )
            $ZeekCandidateCount = @($ZeekCandidates).Count
            Write-Host "  Zeek candidates after retry $retry : $ZeekCandidateCount"
        }
    }

    if ($ZeekCandidateCount -lt 1) {
        throw "Required Zeek evidence is missing for $RunID after retries. Run was NOT archived."
    }

    if ($Scenario.RequireWazuh -and $WazuhCandidateCount -lt 1 -and -not $SkipPipelineRefresh) {
        for ($retry = 1; $retry -le $WazuhRetryCount -and $WazuhCandidateCount -lt 1; $retry++) {
            Write-Host ""
            Write-Host "Wazuh evidence not available yet. Retry $retry/$WazuhRetryCount after $WazuhRetryWaitSeconds second(s)..."
            Start-Sleep -Seconds $WazuhRetryWaitSeconds

            & python ".\scripts\live_pipeline.py" `
                --environment $Environment `
                --wazuh-size $WazuhSize `
                --skip-publish

            if ($LASTEXITCODE -ne 0) {
                throw "live_pipeline.py failed during Wazuh retry with exit code $LASTEXITCODE"
            }

            $WazuhCandidates = @(
                Get-WazuhCandidates `
                    -Path $WazuhPath `
                    -Scenario $Scenario `
                    -Start $Start `
                    -End $End `
                    -PaddingSeconds $ValidationPaddingSeconds
            )
            $WazuhCandidateCount = @($WazuhCandidates).Count
            Write-Host "  Wazuh candidates after retry $retry : $WazuhCandidateCount"
        }
    }

    if ($Scenario.RequireWazuh -and $WazuhCandidateCount -lt 1) {
        throw "Required Wazuh evidence is missing for $RunID after retries. Run was NOT archived."
    }

    # Use the existing repository archive function.
    . ".\scripts\save_final_run.ps1"

    Save-FinalRun `
        -RunID $RunID `
        -StartUTC $StartUTC `
        -EndUTC $EndUTC `
        -Environment $Environment `
        -EvaluationStartUTC $EvaluationStartUTC

    Write-Host ""
    Write-Host "Running Chapter 6 evaluator..."
    & python ".\scripts\evaluate_chapter6.py" `
        --environment $Environment `
        --allow-incomplete

    if ($LASTEXITCODE -ne 0) {
        throw "evaluate_chapter6.py failed with exit code $LASTEXITCODE"
    }

    $PredictionCsv = ".\evaluation\chapter6\derived\final\final_run_predictions.csv"
    $Prediction = Import-Csv $PredictionCsv |
        Where-Object { $_.RunID -eq $RunID } |
        Select-Object -First 1

    if (-not $Prediction) {
        throw "Evaluator did not produce a row for $RunID"
    }

    Write-Host ""
    Write-Host "Evaluation result for $RunID"
    $Prediction | Format-List `
        RunID,
        ScenarioID,
        GroundTruth,
        ExpectedClass,
        WazuhEvidenceCount,
        ZeekEvidenceCount,
        Accepted,
        ExclusionReason,
        ExpectedCorrelation,
        ObservedCorrelation,
        CorrelatedEventCount,
        'Severity-only host baseline Score',
        'Severity-only host baseline Class',
        'Severity-only host baseline Binary',
        'Network-only contextual analysis Score',
        'Network-only contextual analysis Class',
        'Network-only contextual analysis Binary',
        'Contextual analysis without correlation Score',
        'Contextual analysis without correlation Class',
        'Contextual analysis without correlation Binary',
        'Full proposed framework Score',
        'Full proposed framework Class',
        'Full proposed framework Binary'

    if ("$($Prediction.Accepted)".ToLowerInvariant() -ne "true") {
        throw "$RunID was archived but evaluator rejected it: $($Prediction.ExclusionReason)"
    }

    Write-Host ""
    Write-Host "$RunID completed and accepted."
}
finally {
    Pop-Location
}
