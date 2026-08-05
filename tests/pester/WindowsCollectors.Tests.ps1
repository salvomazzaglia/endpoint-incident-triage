#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
}


Describe 'Windows collector inventory' {
    It 'Discovers all expected Windows collector scripts' {
        $ctx = Get-EitWindowsTestContext
        $ctx.Collectors.Count | Should -Be 12
    }

    It 'Has a synthetic fixture for every collector script' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $fixtureName = $ctx.FixtureMap[$collectorFile.Name]
            $fixtureName | Should -Not -BeNullOrEmpty -Because "$($collectorFile.Name) must map to a fixture"
            $fixturePath = Join-Path $ctx.FixturesRoot $fixtureName
            Test-Path -LiteralPath $fixturePath | Should -BeTrue
        }
    }
}

Describe 'Windows collector fixture mode' -Tag 'Fixture' {
    It 'Returns fixture JSON from each collector without live inspection' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $fixtureName = $ctx.FixtureMap[$collectorFile.Name]
            $fixturePath = Join-Path $ctx.FixturesRoot $fixtureName
            $output = & $collectorFile.FullName -FixturePath $fixturePath 2>&1 | Out-String
            $LASTEXITCODE | Should -Be 0 -Because "$($collectorFile.Name) fixture mode should exit 0"
            $output.Trim() | Should -Not -BeNullOrEmpty
            { $output | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    It 'Honors EIT_FIXTURE_FILE environment variable for processes.ps1' {
        $ctx = Get-EitWindowsTestContext
        $fixturePath = Join-Path $ctx.FixturesRoot 'windows.processes.json'
        $env:EIT_FIXTURE_FILE = $fixturePath
        try {
            $collectorPath = Join-Path $ctx.CollectorsRoot 'processes.ps1'
            $output = & $collectorPath 2>&1 | Out-String
            $LASTEXITCODE | Should -Be 0
            ($output | ConvertFrom-Json).records.Count | Should -BeGreaterThan 0
        } finally {
            Remove-Item Env:EIT_FIXTURE_FILE -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Windows collector strict mode' {
    It 'Uses Set-StrictMode in every collector script' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Match 'Set-StrictMode\s+-Version\s+Latest' -Because $collectorFile.Name
        }
    }
}

Describe 'Windows collector safety guards (static analysis)' {
    It 'Does not use Invoke-Expression or iex in any collector' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Not -Match 'Invoke-Expression|\biex\b' -Because $collectorFile.Name
        }
    }

    It 'Does not download remote content in any collector' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Not -Match 'Invoke-WebRequest|Start-BitsTransfer|curl\.exe|wget' -Because $collectorFile.Name
        }
    }

    It 'Does not clear event logs in any collector' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Not -Match 'Clear-EventLog|wevtutil\s+cl' -Because $collectorFile.Name
        }
    }

    It 'Does not terminate processes in any collector' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Not -Match 'Stop-Process|taskkill' -Because $collectorFile.Name
        }
    }

    It 'Does not modify services or scheduled tasks in any collector' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Not -Match 'Set-Service|Start-Service|Stop-Service|Register-ScheduledTask|Unregister-ScheduledTask' -Because $collectorFile.Name
        }
    }

    It 'Does not write registry values in any collector' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Not -Match 'Set-ItemProperty|New-ItemProperty|Remove-ItemProperty' -Because $collectorFile.Name
        }
    }
}

Describe 'Windows collector fixture output schema' {
    It 'Fixture output for processes includes records array' {
        $ctx = Get-EitWindowsTestContext
        $fixturePath = Join-Path $ctx.FixturesRoot 'windows.processes.json'
        $collectorPath = Join-Path $ctx.CollectorsRoot 'processes.ps1'
        $payload = (& $collectorPath -FixturePath $fixturePath | ConvertFrom-Json)
        $payload.PSObject.Properties.Name | Should -Contain 'records'
        $payload.records.Count | Should -BeGreaterThan 0
    }

    It 'Fixture output for system-context includes synthetic hostname' {
        $ctx = Get-EitWindowsTestContext
        $fixturePath = Join-Path $ctx.FixturesRoot 'windows.system_context.json'
        $collectorPath = Join-Path $ctx.CollectorsRoot 'system-context.ps1'
        $payload = (& $collectorPath -FixturePath $fixturePath | ConvertFrom-Json)
        $payload.records[0].hostname | Should -Be 'SYNTHETIC-ENDPOINT-01'
    }
}
