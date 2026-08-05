function Get-EitWindowsTestContext {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $collectorsRoot = Join-Path $repoRoot 'collectors\windows'
    $fixturesRoot = Join-Path $repoRoot 'tests\fixtures\windows'
    $collectors = @(Get-ChildItem -Path $collectorsRoot -Filter '*.ps1' | Sort-Object Name)
    $fixtureMap = @{
        'autoruns.ps1'              = 'windows.autoruns.json'
        'defender-status.ps1'       = 'windows.defender_status.json'
        'event-log-summary.ps1'     = 'windows.event_log_summary.json'
        'network-connections.ps1'   = 'windows.network_connections.json'
        'processes.ps1'             = 'windows.processes.json'
        'recent-file-metadata.ps1'  = 'windows.recent_file_metadata.json'
        'scheduled-tasks.ps1'       = 'windows.scheduled_tasks.json'
        'services.ps1'              = 'windows.services.json'
        'system-context.ps1'        = 'windows.system_context.json'
        'time-context.ps1'          = 'windows.time_context.json'
        'users-sessions.ps1'        = 'windows.users_sessions.json'
        'wmi-persistence.ps1'       = 'windows.wmi_persistence.json'
    }
    [PSCustomObject]@{
        RepoRoot       = $repoRoot
        CollectorsRoot = $collectorsRoot
        FixturesRoot   = $fixturesRoot
        Collectors     = $collectors
        FixtureMap     = $fixtureMap
    }
}

$script:EitForbiddenPatterns = @(
    @{ Name = 'Invoke-Expression'; Pattern = 'Invoke-Expression|\biex\b' }
    @{ Name = 'Add-Type arbitrary code'; Pattern = 'Add-Type\s+-TypeDefinition' }
    @{ Name = 'Credential store access'; Pattern = 'Get-StoredCredential|CredentialManager|cmdkey' }
    @{ Name = 'LSASS access'; Pattern = 'lsass|MiniDumpWriteDump|comsvcs\.dll' }
    @{ Name = 'Memory dump'; Pattern = 'Out-Minidump|\.dmp\b|ProcDump' }
    @{ Name = 'Raw disk access'; Pattern = '\\\\\.\\PhysicalDrive|Disk\.Open' }
    @{ Name = 'VSS snapshot creation'; Pattern = 'CreateSnapshot|vssadmin\s+create' }
    @{ Name = 'Execution policy change'; Pattern = 'Set-ExecutionPolicy' }
    @{ Name = 'Environment dump'; Pattern = 'Get-ChildItem\s+Env:|dir\s+env:' }
    @{ Name = 'Network requests'; Pattern = 'Invoke-WebRequest|Invoke-RestMethod|Test-NetConnection\s+-Port' }
    @{ Name = 'Antivirus disable'; Pattern = 'Set-MpPreference\s+-Disable|DisableAntiSpyware' }
    @{ Name = 'Firewall modification'; Pattern = 'New-NetFirewallRule|Set-NetFirewallProfile' }
)
