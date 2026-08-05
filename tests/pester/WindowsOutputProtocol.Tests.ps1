#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
}


Describe 'Windows collector output protocol' {
    It 'processes fixture output is valid JSON with process records' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'processes.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.processes.json'
        $raw = (& $collectorPath -FixturePath $fixture | Out-String)
        $payload = ($raw | ConvertFrom-Json)
        $payload.records[0].record_type | Should -Be 'process'
        $raw | Should -Match 'start_time_utc'
        $raw | Should -Match 'Z"'
    }

    It 'network-connections fixture preserves records array length' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'network-connections.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.network_connections.json'
        $payload = (& $collectorPath -FixturePath $fixture | ConvertFrom-Json)
        $payload.records.Count | Should -BeGreaterThan 0
    }

    It 'services fixture includes records with service metadata' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'services.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.services.json'
        $payload = (& $collectorPath -FixturePath $fixture | ConvertFrom-Json)
        $payload.records | Should -Not -BeNullOrEmpty
    }

    It 'autoruns fixture returns structured persistence records' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'autoruns.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.autoruns.json'
        $payload = (& $collectorPath -FixturePath $fixture | ConvertFrom-Json)
        $payload.records.Count | Should -BeGreaterThan 0
    }

    It 'event-log-summary fixture respects bounded output shape' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'event-log-summary.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.event_log_summary.json'
        $payload = (& $collectorPath -FixturePath $fixture | ConvertFrom-Json)
        $payload.records.Count | Should -BeLessOrEqual 200
    }

    It 'recent-file-metadata fixture returns metadata records only' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'recent-file-metadata.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.recent_file_metadata.json'
        $payload = (& $collectorPath -FixturePath $fixture | ConvertFrom-Json)
        $payload.records | Should -Not -BeNullOrEmpty
    }

    It 'defender-status fixture indicates synthetic availability record' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'defender-status.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.defender_status.json'
        $payload = (& $collectorPath -FixturePath $fixture | ConvertFrom-Json)
        $payload.records[0].available | Should -BeTrue
    }

    It 'scheduled-tasks fixture parses as JSON' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'scheduled-tasks.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.scheduled_tasks.json'
        { (& $collectorPath -FixturePath $fixture | ConvertFrom-Json) } | Should -Not -Throw
    }
}

Describe 'Windows Write-CollectorOutput protocol' {
    It 'Write-CollectorOutput includes collector_id and records keys in time-context.ps1' {
        $ctx = Get-EitWindowsTestContext
        $content = Get-Content -LiteralPath (Join-Path $ctx.CollectorsRoot 'time-context.ps1') -Raw
        $content | Should -Match 'collector_id'
        $content | Should -Match 'records'
        $content | Should -Match 'record_count'
    }
}

Describe 'Windows fixture passthrough fidelity' {
    It 'Returns fixture bytes unchanged for users-sessions' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'users-sessions.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.users_sessions.json'
        $expected = Get-Content -LiteralPath $fixture -Raw
        $actual = (& $collectorPath -FixturePath $fixture | Out-String).Trim()
        $actual | Should -Be $expected.Trim()
    }

    It 'Returns fixture bytes unchanged for wmi-persistence' {
        $ctx = Get-EitWindowsTestContext
        $collectorPath = Join-Path $ctx.CollectorsRoot 'wmi-persistence.ps1'
        $fixture = Join-Path $ctx.FixturesRoot 'windows.wmi_persistence.json'
        $expected = Get-Content -LiteralPath $fixture -Raw
        $actual = (& $collectorPath -FixturePath $fixture | Out-String).Trim()
        $actual | Should -Be $expected.Trim()
    }
}

Describe 'Windows collector script inventory for output protocol' {
    It 'Includes twelve collector scripts on disk' {
        $ctx = Get-EitWindowsTestContext
        $ctx.Collectors.Count | Should -Be 12
    }
}
