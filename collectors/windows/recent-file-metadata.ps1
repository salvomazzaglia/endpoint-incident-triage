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

$searchRoots = @(
    $env:TEMP,
    $env:TMP,
    "$env:WINDIR\Temp",
    "$env:APPDATA",
    "$env:LOCALAPPDATA"
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

$collected = 0
foreach ($root in $searchRoots) {
    if ($collected -ge $MaxFiles) { break }
    try {
        Get-ChildItem -LiteralPath $root -File -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -ge $sinceUtc } |
            Sort-Object LastWriteTimeUtc -Descending |
            ForEach-Object {
                if ($collected -ge $MaxFiles) { return }
                try {
                    $file = $_
                    $records.Add([ordered]@{
                        record_type        = 'recent_file'
                        path               = $file.FullName
                        name               = $file.Name
                        size_bytes         = $file.Length
                        created_time_utc   = $file.CreationTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                        modified_time_utc  = $file.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                        extension          = $file.Extension
                        search_root        = $root
                    })
                    $collected++
                } catch {
                    $records.Add([ordered]@{
                        record_type = 'parse_error'
                        path        = $_.FullName
                        error       = $_.Exception.Message
                    })
                }
            }
    } catch {
        $records.Add([ordered]@{
            record_type = 'collection_error'
            search_root = $root
            error       = $_.Exception.Message
        })
    }
}

$records.Add([ordered]@{
    record_type = 'collection_summary'
    since_utc   = $sinceUtc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    max_files   = $MaxFiles
    max_depth   = $MaxDepth
    collected   = $collected
})

Write-CollectorOutput -CollectorId 'windows.recent_file_metadata' -Records $records.ToArray()
