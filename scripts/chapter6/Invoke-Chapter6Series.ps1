<#
.SYNOPSIS
Runs a range of repetitions for one Chapter 6 scenario.

.EXAMPLE
.\scripts\chapter6\Invoke-Chapter6Series.ps1 `
  -ScenarioId B2 `
  -From 1 `
  -To 5 `
  -VagrantDir "D:\vagrant-lab"

The series stops immediately if any repetition fails.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("B1","B2","A1","A2","A3","A4","A5","U1")]
    [string]$ScenarioId,

    [ValidateRange(1,5)]
    [int]$From = 1,

    [ValidateRange(1,5)]
    [int]$To = 5,

    [Parameter(Mandatory = $true)]
    [string]$VagrantDir,

    [string]$Environment = "healthcare-lab",

    [string]$EvaluationStartUTC = "2026-08-10T04:30:00Z",

    [int]$WazuhSize = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($From -gt $To) {
    throw "-From cannot be greater than -To"
}

$Runner = Join-Path $PSScriptRoot "Invoke-Chapter6Scenario.ps1"

if (-not (Test-Path $Runner)) {
    throw "Scenario runner not found: $Runner"
}

for ($repetition = $From; $repetition -le $To; $repetition++) {
    $runId = "$($ScenarioId)-R$($repetition)"

    Write-Host ""
    Write-Host "############################################################"
    Write-Host "Starting $runId"
    Write-Host "############################################################"

    $runnerArgs = @{
        ScenarioId        = $ScenarioId
        Repetition        = $repetition
        VagrantDir        = $VagrantDir
        Environment       = $Environment
        EvaluationStartUTC = $EvaluationStartUTC
        WazuhSize         = $WazuhSize
    }

    try {
        & $Runner @runnerArgs
    }
    catch {
        Write-Error "$runId failed: $($_.Exception.Message)"
        throw
    }
}

Write-Host ""
Write-Host "Requested series completed: $($ScenarioId) R$($From)-R$($To)"