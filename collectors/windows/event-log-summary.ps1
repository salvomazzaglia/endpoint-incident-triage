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
$sinceUtc = (Get-Date).ToUniversalTime().AddHours(-1 * $SinceHours)
$sinceFilter = $sinceUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

$logConfigs = @(
    @{ LogName = 'Security'; EventIds = @(4624, 4625, 4648, 4672, 4720, 4726, 7045) },
    @{ LogName = 'System'; EventIds = @(7034, 7036, 7040, 7045) },
    @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; EventIds = @(1116, 1117, 5001) }
)

foreach ($cfg in $logConfigs) {
    $collected = 0
    try {
        $filter = @{
            LogName   = $cfg.LogName
            StartTime = $sinceUtc
        }
        Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop | ForEach-Object {
            if ($collected -ge $MaxEvents) { return }
            try {
                $evt = $_
                if ($cfg.EventIds -contains $evt.Id) {
                    $entry = [ordered]@{
                        record_type   = 'event_log_entry'
                        log_name      = $cfg.LogName
                        event_id      = $evt.Id
                        level         = $evt.LevelDisplayName
                        provider      = $evt.ProviderName
                        time_created_utc = $evt.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                        machine       = $evt.MachineName
                    }
                    if ($IncludeEventMessages) {
                        $entry.message = $evt.Message
                    }
                    $records.Add($entry)
                    $collected++
                }
            } catch {
                $records.Add([ordered]@{
                    record_type = 'parse_error'
                    log_name    = $cfg.LogName
                    error       = $_.Exception.Message
                })
            }
        }
    } catch {
        $records.Add([ordered]@{
            record_type = 'collection_error'
            log_name    = $cfg.LogName
            since_utc   = $sinceFilter
            error       = $_.Exception.Message
        })
    }

    $records.Add([ordered]@{
        record_type = 'event_log_summary'
        log_name    = $cfg.LogName
        since_utc   = $sinceFilter
        max_events  = $MaxEvents
        collected   = $collected
    })
}

Write-CollectorOutput -CollectorId 'windows.event_log_summary' -Records $records.ToArray()
