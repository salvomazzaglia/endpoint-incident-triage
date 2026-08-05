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
    $sessions = query user 2>&1
    if ($LASTEXITCODE -eq 0 -and $sessions) {
        $lines = @($sessions)
        for ($i = 1; $i -lt $lines.Count; $i++) {
            try {
                $line = $lines[$i].Trim()
                if (-not $line) { continue }
                $parts = $line -split '\s+', 6
                if ($parts.Count -ge 2) {
                    $records.Add([ordered]@{
                        record_type = 'interactive_session'
                        username    = $parts[0]
                        session_id  = if ($parts.Count -gt 1) { $parts[1] } else { $null }
                        state       = if ($parts.Count -gt 3) { $parts[3] } else { $null }
                        raw_line    = $line
                    })
                }
            } catch {
                $records.Add([ordered]@{
                    record_type = 'parse_error'
                    raw_line    = $lines[$i]
                    error       = $_.Exception.Message
                })
            }
        }
    }
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = 'query_user'
        error       = $_.Exception.Message
    })
}

try {
    Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop | ForEach-Object {
        try {
            $records.Add([ordered]@{
                record_type       = 'logon_session'
                logon_id          = $_.LogonId
                authentication_package = $_.AuthenticationPackage
                logon_type        = $_.LogonType
                start_time_utc    = if ($_.StartTime) { $_.StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { $null }
            })
        } catch {
            $records.Add([ordered]@{
                record_type = 'parse_error'
                source      = 'Win32_LogonSession'
                error       = $_.Exception.Message
            })
        }
    }
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = 'Win32_LogonSession'
        error       = $_.Exception.Message
    })
}

try {
    Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction Stop | ForEach-Object {
        try {
            $user = $_.Antecedent
            $records.Add([ordered]@{
                record_type = 'logged_on_user'
                user        = if ($user) { $user.Name } else { $null }
                domain      = if ($user) { $user.Domain } else { $null }
            })
        } catch {
            $records.Add([ordered]@{
                record_type = 'parse_error'
                source      = 'Win32_LoggedOnUser'
                error       = $_.Exception.Message
            })
        }
    }
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = 'Win32_LoggedOnUser'
        error       = $_.Exception.Message
    })
}

Write-CollectorOutput -CollectorId 'windows.users_sessions' -Records $records.ToArray()
