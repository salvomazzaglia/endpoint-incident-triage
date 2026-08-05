#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
}


Describe 'Windows safety guard patterns' {
    It 'Blocks forbidden patterns in every collector script' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            foreach ($rule in $script:EitForbiddenPatterns) {
                $content | Should -Not -Match $rule.Pattern -Because "$($collectorFile.Name) must forbid $($rule.Name)"
            }
        }
    }
}

Describe 'Windows collector parameter safety' {
    It 'Exposes FixturePath in every collector script' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Match '\[string\]\$FixturePath|FixturePath' -Because $collectorFile.Name
        }
    }

    It 'Checks fixture path before live collection in every script' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Match 'FixturePath|EIT_FIXTURE_FILE' -Because $collectorFile.Name
            $content | Should -Match 'Test-Path|Get-Content' -Because $collectorFile.Name
        }
    }
}

Describe 'Windows collector error handling' {
    It 'Sets ErrorActionPreference to Stop in every script' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Match "\`$ErrorActionPreference\s*=\s*'Stop'" -Because $collectorFile.Name
        }
    }
}

Describe 'Windows collector JSON output helpers' {
    It 'Uses ConvertTo-Json in every collector script' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Match 'ConvertTo-Json' -Because $collectorFile.Name
        }
    }
}

Describe 'Windows optional sensitive flags' {
    It 'processes.ps1 supports IncludeCommandLines switch' {
        $ctx = Get-EitWindowsTestContext
        $content = Get-Content -LiteralPath (Join-Path $ctx.CollectorsRoot 'processes.ps1') -Raw
        $content | Should -Match '\[switch\]\$IncludeCommandLines'
    }

    It 'event-log-summary.ps1 supports IncludeEventMessages switch' {
        $ctx = Get-EitWindowsTestContext
        $content = Get-Content -LiteralPath (Join-Path $ctx.CollectorsRoot 'event-log-summary.ps1') -Raw
        $content | Should -Match '\[switch\]\$IncludeEventMessages'
    }
}

Describe 'Windows collector helper functions' {
    It 'Defines Get-UtcNowIso in every collector script' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Match 'function\s+Get-UtcNowIso' -Because $collectorFile.Name
        }
    }

    It 'Defines Write-CollectorOutput in every collector script' {
        $ctx = Get-EitWindowsTestContext
        foreach ($collectorFile in $ctx.Collectors) {
            $content = Get-Content -LiteralPath $collectorFile.FullName -Raw
            $content | Should -Match 'function\s+Write-CollectorOutput' -Because $collectorFile.Name
        }
    }
}
