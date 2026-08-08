# Chapter 6 final-run archive helper.
# Dot-source this file once per PowerShell session:
#   . .\scripts\save_final_run.ps1

function Save-FinalRun {
    param(
        [Parameter(Mandatory=$true)][string]$RunID,
        [Parameter(Mandatory=$true)][string]$StartUTC,
        [Parameter(Mandatory=$true)][string]$EndUTC,
        [string]$Environment = "healthcare-lab",
        [string]$EvaluationStartUTC = ""
    )

    $RunDir = ".\evaluation\chapter6\final\$RunID"
    New-Item -ItemType Directory -Force $RunDir | Out-Null

    $RequiredFiles = @(
        ".\data\$Environment\live_wazuh_events.json",
        ".\data\$Environment\live_zeek_conn.log",
        ".\data\$Environment\live_zeek_conn.json",
        ".\output\$Environment\scored_events.json",
        ".\logs\$Environment\live_pipeline_state.json"
    )

    foreach ($Path in $RequiredFiles) {
        if (-not (Test-Path $Path)) {
            throw "Required pipeline evidence file not found: $Path"
        }
    }

    Copy-Item ".\data\$Environment\live_wazuh_events.json" "$RunDir\live_wazuh_events.json" -Force
    Copy-Item ".\data\$Environment\live_zeek_conn.log" "$RunDir\live_zeek_conn.log" -Force
    Copy-Item ".\data\$Environment\live_zeek_conn.json" "$RunDir\live_zeek_conn.json" -Force
    Copy-Item ".\output\$Environment\scored_events.json" "$RunDir\scored_events.json" -Force
    Copy-Item ".\logs\$Environment\live_pipeline_state.json" "$RunDir\live_pipeline_state.json" -Force

    Get-Content ".\logs\$Environment\live_pipeline.log" -Tail 500 |
        Set-Content "$RunDir\pipeline_log_tail.txt"

    $RunInfo = [ordered]@{
        run_id      = $RunID
        scenario_id = ($RunID -split '-')[0]
        start_utc   = $StartUTC
        end_utc     = $EndUTC
        environment = $Environment
    }

    if ($EvaluationStartUTC) {
        $RunInfo["evaluation_start_utc"] = $EvaluationStartUTC
    }

    $RunInfo |
        ConvertTo-Json |
        Set-Content "$RunDir\run_info.json"

    Write-Host "Archived Chapter 6 final run: $RunID"
    Write-Host "  $RunDir"
}