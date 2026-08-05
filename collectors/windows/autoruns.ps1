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

function Add-AutorunRecord {
    param(
        [System.Collections.Generic.List[object]]$Target,
        [string]$Location,
        [string]$Name,
        [string]$Command,
        [string]$Source
    )
    $exists = $null
    if ($Command) {
        $exe = ($Command -replace '^"([^"]+)".*$', '$1') -replace '^(\S+).*', '$1'
        if ($exe -and -not ($exe -match '^\\|^[\w]:')) {
            $exists = $null
        } elseif ($exe) {
            $exists = Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue
        }
    }
    $Target.Add([ordered]@{
        record_type   = 'autorun'
        location      = $Location
        name          = $Name
        command       = $Command
        source        = $Source
        target_exists = $exists
    })
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

$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($keyPath in $runKeys) {
    try {
        if (-not (Test-Path -LiteralPath $keyPath)) { continue }
        Get-ItemProperty -LiteralPath $keyPath -ErrorAction Stop |
            Get-Member -MemberType NoteProperty |
            Where-Object { $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') } |
            ForEach-Object {
                $propName = $_.Name
                try {
                    $value = (Get-ItemProperty -LiteralPath $keyPath -ErrorAction Stop).($propName)
                    Add-AutorunRecord -Target $records -Location $keyPath -Name $propName -Command ([string]$value) -Source 'registry_run'
                } catch {
                    $records.Add([ordered]@{
                        record_type = 'parse_error'
                        location    = $keyPath
                        name        = $propName
                        error       = $_.Exception.Message
                    })
                }
            }
    } catch {
        $records.Add([ordered]@{
            record_type = 'collection_error'
            location    = $keyPath
            error       = $_.Exception.Message
        })
    }
}

$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    try {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        Get-ChildItem -LiteralPath $folder -ErrorAction Stop | ForEach-Object {
            try {
                $item = $_
                Add-AutorunRecord -Target $records -Location $folder -Name $item.Name -Command $item.FullName -Source 'startup_folder'
            } catch {
                $records.Add([ordered]@{
                    record_type = 'parse_error'
                    location    = $folder
                    error       = $_.Exception.Message
                })
            }
        }
    } catch {
        $records.Add([ordered]@{
            record_type = 'collection_error'
            location    = $folder
            error       = $_.Exception.Message
        })
    }
}

Write-CollectorOutput -CollectorId 'windows.autoruns' -Records $records.ToArray()
