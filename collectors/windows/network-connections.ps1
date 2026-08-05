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
    Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
        try {
            $conn = $_
            $records.Add([ordered]@{
                record_type      = 'tcp_connection'
                local_address    = $conn.LocalAddress
                local_port       = $conn.LocalPort
                remote_address   = $conn.RemoteAddress
                remote_port      = $conn.RemotePort
                state            = [string]$conn.State
                owning_process   = $conn.OwningProcess
                creation_time_utc = if ($conn.CreationTime) { $conn.CreationTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { $null }
            })
        } catch {
            $records.Add([ordered]@{
                record_type = 'parse_error'
                source      = 'tcp'
                error       = $_.Exception.Message
            })
        }
    }
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = 'Get-NetTCPConnection'
        error       = $_.Exception.Message
    })
}

try {
    Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
        try {
            $ep = $_
            $records.Add([ordered]@{
                record_type    = 'udp_endpoint'
                local_address  = $ep.LocalAddress
                local_port     = $ep.LocalPort
                owning_process = $ep.OwningProcess
            })
        } catch {
            $records.Add([ordered]@{
                record_type = 'parse_error'
                source      = 'udp'
                error       = $_.Exception.Message
            })
        }
    }
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = 'Get-NetUDPEndpoint'
        error       = $_.Exception.Message
    })
}

Write-CollectorOutput -CollectorId 'windows.network_connections' -Records $records.ToArray()
