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
    Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction Stop | ForEach-Object {
        try {
            $filter = $_
            $records.Add([ordered]@{
                record_type  = 'wmi_event_filter'
                name         = $filter.Name
                query        = $filter.Query
                query_language = $filter.QueryLanguage
                namespace    = 'root/subscription'
            })
        } catch {
            $records.Add([ordered]@{
                record_type = 'parse_error'
                source      = '__EventFilter'
                error       = $_.Exception.Message
            })
        }
    }
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = '__EventFilter'
        error       = $_.Exception.Message
    })
}

try {
    Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction Stop | ForEach-Object {
        try {
            $consumer = $_
            $records.Add([ordered]@{
                record_type = 'wmi_event_consumer'
                name        = $consumer.Name
                class_name  = $consumer.CimClass.CimClassName
                namespace   = 'root/subscription'
            })
        } catch {
            $records.Add([ordered]@{
                record_type = 'parse_error'
                source      = '__EventConsumer'
                error       = $_.Exception.Message
            })
        }
    }
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = '__EventConsumer'
        error       = $_.Exception.Message
    })
}

try {
    Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
        try {
            $binding = $_
            $records.Add([ordered]@{
                record_type = 'wmi_filter_consumer_binding'
                filter      = $binding.Filter
                consumer    = $binding.Consumer
                namespace   = 'root/subscription'
            })
        } catch {
            $records.Add([ordered]@{
                record_type = 'parse_error'
                source      = '__FilterToConsumerBinding'
                error       = $_.Exception.Message
            })
        }
    }
} catch {
    $records.Add([ordered]@{
        record_type = 'collection_error'
        source      = '__FilterToConsumerBinding'
        error       = $_.Exception.Message
    })
}

Write-CollectorOutput -CollectorId 'windows.wmi_persistence' -Records $records.ToArray()
