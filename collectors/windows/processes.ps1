#Requires -Version 5.1
param(
    [string]$FixturePath,
    [switch]$IncludeCommandLines,
    [switch]$IncludeEventMessages,
    [int]$SinceHours = 24,
    [int]$MaxEvents = 200,
    [int]$MaxFiles = 50,
    [int]$MaxDepth = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-UtcNowIso {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Write-CollectorOutput {
    param(
        [string]$CollectorId,
        [array]$Records
    )
    $output = [ordered]@{
        collector_id     = $CollectorId
        collected_at_utc = Get-UtcNowIso
        record_count     = $Records.Count
        records          = $Records
    }
    $output | ConvertTo-Json -Depth 6 -Compress:$false
}

$fixture = $FixturePath
if (-not $fixture) {
    $fixture = $env:EIT_FIXTURE_FILE
}
if ($fixture -and (Test-Path -LiteralPath $fixture)) {
    Get-Content -LiteralPath $fixture -Raw | Write-Output
    exit 0
}

$records = [System.Collections.Generic.List[object]]::new()

Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $proc = $_
        $entry = [ordered]@{
            record_type   = 'process'
            pid           = $proc.Id
            name          = $proc.ProcessName
            session_id    = $proc.SessionId
            start_time_utc = if ($proc.StartTime) { $proc.StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { $null }
            path          = $null
            company       = $null
            parent_pid    = $null
        }

        try {
            $path = $proc.Path
            if ($path) {
                $entry.path = $path
            }
        } catch {
            $entry.path_error = 'path_access_denied'
        }

        if ($IncludeCommandLines) {
            try {
                $cim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction Stop
                $entry.command_line = $cim.CommandLine
                $entry.parent_pid = $cim.ParentProcessId
            } catch {
                $entry.command_line_error = $_.Exception.Message
            }
        } else {
            try {
                $cim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction Stop
                $entry.parent_pid = $cim.ParentProcessId
            } catch {
                $entry.parent_pid_error = 'cim_unavailable'
            }
        }

        $records.Add($entry)
    } catch {
        $records.Add([ordered]@{
            record_type = 'parse_error'
            error       = $_.Exception.Message
        })
    }
}

Write-CollectorOutput -CollectorId 'windows.processes' -Records $records.ToArray()
