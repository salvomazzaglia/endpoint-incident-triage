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

try {
    $pref = Get-MpPreference -ErrorAction Stop
    $records.Add([ordered]@{
        record_type              = 'defender_preference'
        real_time_protection     = $null
        cloud_protection         = $pref.MAPSReporting
        submit_samples_consent   = $pref.SubmitSamplesConsent
        disable_realtime_monitoring = $pref.DisableRealtimeMonitoring
        collected_at_utc         = Get-UtcNowIso
    })
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = 'Get-MpPreference'
        error       = $_.Exception.Message
    })
}

try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $records.Add([ordered]@{
        record_type                 = 'defender_status'
        antivirus_enabled           = $status.AntivirusEnabled
        antispyware_enabled         = $status.AntispywareEnabled
        real_time_protection_enabled = $status.RealTimeProtectionEnabled
        on_access_protection_enabled = $status.OnAccessProtectionEnabled
        ioav_protection_enabled     = $status.IoavProtectionEnabled
        antispyware_signature_age   = $status.AntispywareSignatureAge
        antivirus_signature_age     = $status.AntivirusSignatureAge
        quick_scan_age              = $status.QuickScanAge
        full_scan_age               = $status.FullScanAge
        product_version             = $status.AMProductVersion
        engine_version              = $status.AMEngineVersion
        last_full_scan_source       = $status.LastFullScanSource
        last_quick_scan_source      = $status.LastQuickScanSource
        collected_at_utc            = Get-UtcNowIso
    })
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = 'Get-MpComputerStatus'
        error       = $_.Exception.Message
        security_tool_unavailable = $true
    })
}

Write-CollectorOutput -CollectorId 'windows.defender_status' -Records $records.ToArray()
