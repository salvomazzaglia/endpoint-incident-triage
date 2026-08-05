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

$nowUtc = (Get-Date).ToUniversalTime()
$record = [ordered]@{
    current_time_utc    = Get-UtcNowIso
    current_time_local  = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffK')
    timezone_id         = [TimeZoneInfo]::Local.Id
    timezone_display    = [TimeZoneInfo]::Local.DisplayName
    utc_offset_minutes  = [int][TimeZoneInfo]::Local.GetUtcOffset($nowUtc).TotalMinutes
    daylight_saving     = [TimeZoneInfo]::Local.IsDaylightSavingTime($nowUtc)
    collected_at_utc    = Get-UtcNowIso
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if ($os.LastBootUpTime) {
        $bootUtc = $os.LastBootUpTime.ToUniversalTime()
        $record.last_boot_time_utc = $bootUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        $record.uptime_seconds = [int]((Get-Date).ToUniversalTime() - $bootUtc).TotalSeconds
    }
    $record.local_date_time = $os.LocalDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
} catch {
    $record.boot_error = $_.Exception.Message
}

try {
    $w32tm = & w32tm.exe /query /status 2>&1
    if ($LASTEXITCODE -eq 0) {
        $record.ntp_source = ($w32tm | Select-String -Pattern 'Source:' | ForEach-Object { $_.Line.Trim() }) -join '; '
        $record.ntp_last_sync = ($w32tm | Select-String -Pattern 'Last Successful Sync Time:' | ForEach-Object { $_.Line.Trim() }) -join '; '
    } else {
        $record.ntp_status = 'unavailable'
    }
} catch {
    $record.ntp_error = $_.Exception.Message
}

Write-CollectorOutput -CollectorId 'windows.time_context' -Records @($record)
