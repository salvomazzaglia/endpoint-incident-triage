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
    $tasks = Get-ScheduledTask -ErrorAction Stop
    foreach ($task in $tasks) {
        try {
            $action = $null
            $actionPath = $null
            $actionExists = $null
            if ($task.Actions -and $task.Actions.Count -gt 0) {
                $first = $task.Actions[0]
                $action = $first.Execute
                $actionPath = $first.Arguments
                $target = $first.Execute
                if ($target) {
                    $actionExists = Test-Path -LiteralPath $target -ErrorAction SilentlyContinue
                }
            }

            $records.Add([ordered]@{
                record_type      = 'scheduled_task'
                task_name        = $task.TaskName
                task_path        = $task.TaskPath
                state            = [string]$task.State
                author           = $task.Author
                description      = $task.Description
                execute          = $action
                arguments        = $actionPath
                execute_exists   = $actionExists
                last_run_time_utc = if ($task.LastRunTime) { $task.LastRunTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { $null }
                next_run_time_utc = if ($task.NextRunTime) { $task.NextRunTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { $null }
            })
        } catch {
            $records.Add([ordered]@{
                record_type = 'parse_error'
                task_name   = $task.TaskName
                error       = $_.Exception.Message
            })
        }
    }
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = 'Get-ScheduledTask'
        error       = $_.Exception.Message
    })
}

Write-CollectorOutput -CollectorId 'windows.scheduled_tasks' -Records $records.ToArray()
