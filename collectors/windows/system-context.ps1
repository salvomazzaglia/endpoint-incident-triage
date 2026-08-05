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

$record = [ordered]@{
    hostname            = $env:COMPUTERNAME
    os_caption          = $null
    os_version          = $null
    os_architecture     = $null
    domain              = $null
    manufacturer        = $null
    model               = $null
    total_physical_memory_gb = $null
    logical_processors  = $null
    boot_time_utc       = $null
    collected_at_utc    = Get-UtcNowIso
}

try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $record.hostname = $cs.Name
    $record.domain = $cs.Domain
    $record.manufacturer = $cs.Manufacturer
    $record.model = $cs.Model
    $record.total_physical_memory_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
} catch {
    $record.domain_error = $_.Exception.Message
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $record.os_caption = $os.Caption
    $record.os_version = $os.Version
    $record.os_architecture = $os.OSArchitecture
    if ($os.LastBootUpTime) {
        $record.boot_time_utc = $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }
} catch {
    $record.os_error = $_.Exception.Message
}

try {
    $record.logical_processors = (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
        Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
} catch {
    $record.cpu_error = $_.Exception.Message
}

Write-CollectorOutput -CollectorId 'windows.system_context' -Records @($record)
