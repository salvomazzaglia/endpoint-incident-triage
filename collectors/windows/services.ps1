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

Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
    try {
        $svc = $_
        $binPath = $svc.PathName
        $pathWritable = $null
        if ($binPath) {
            $exePath = ($binPath -replace '^"([^"]+)".*$', '$1') -replace '^(\S+).*', '$1'
            if ($exePath -and (Test-Path -LiteralPath (Split-Path -Parent $exePath) -ErrorAction SilentlyContinue)) {
                try {
                    $dir = Split-Path -Parent $exePath
                    $acl = Get-Acl -LiteralPath $dir -ErrorAction Stop
                    $pathWritable = ($acl.Access | Where-Object {
                        $_.AccessControlType -eq 'Allow' -and
                        ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -eq [System.Security.AccessControl.FileSystemRights]::Write
                    }).Count -gt 0
                } catch {
                    $pathWritable = $null
                }
            }
        }

        $records.Add([ordered]@{
            record_type       = 'service'
            name              = $svc.Name
            display_name      = $svc.DisplayName
            state             = $svc.State
            start_mode        = $svc.StartMode
            path_name         = $binPath
            service_account   = $svc.StartName
            binary_dir_writable = $pathWritable
        })
    } catch {
        $records.Add([ordered]@{
            record_type = 'parse_error'
            error       = $_.Exception.Message
        })
    }
}

Write-CollectorOutput -CollectorId 'windows.services' -Records $records.ToArray()
