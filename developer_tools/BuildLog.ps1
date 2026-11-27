# Mirrors build output to .\developer_tools\build.log (live coloured console + log with a first-line verdict).
# Deliberately does NOT log the machine or user name (this is a privacy tool).
param(
    [string]$ScriptPath = '.\build\BuildPipeline.ps1',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ScriptArgs
)
$ErrorActionPreference = 'Continue'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$logPath = Join-Path $PSScriptRoot 'build.log'
$script:Errors = 0
$script:Warnings = 0
Push-Location $repoRoot

function Get-Level([string]$Line) {
    if ([string]::IsNullOrWhiteSpace($Line)) { return 'Info' }
    if ($Line -match '(?i)\b0 Error\(s\)|\b0 errors\b') { return 'Info' }
    if ($Line -match '(?i)^ERROR:|\bBuild FAILED\b|: error [A-Z]{1,5}\d{3,}:|error MSB\d+:|\[PUBLISH\] STOPPED:') { return 'Error' }
    if ($Line -match '(?i)\b0 Warning\(s\)|\b0 warnings\b') { return 'Info' }
    if ($Line -match '(?i)^WARNING:|: warning [A-Z]{1,5}\d{3,}') { return 'Warning' }
    if ($Line -match '(?i)^SUCCESS:|Build succeeded\.|^Verified |\[Privacy\] Compiled binaries contain no') { return 'Success' }
    if ($Line -match '^#{5,}') { return 'Banner' }
    return 'Info'
}
function Write-Logged([string]$Line, [string]$Force) {
    $level = if ($Force) { $Force } else { Get-Level $Line }
    if (-not $Force) { if ($level -eq 'Error') { $script:Errors++ } elseif ($level -eq 'Warning') { $script:Warnings++ } }
    $color = @{ Error = 'Red'; Warning = 'Yellow'; Success = 'Green'; Banner = 'Cyan'; Info = 'Gray' }[$level]
    Write-Host $Line -ForegroundColor $color
    Add-Content -LiteralPath $logPath -Value $Line -Encoding utf8
}

if (Test-Path -LiteralPath $logPath) { Remove-Item -LiteralPath $logPath -Force }
$started = Get-Date
Write-Logged ('=' * 78) 'Banner'
Write-Logged "Sanitization build log  |  started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  |  $ScriptPath $($ScriptArgs -join ' ')" 'Banner'
Write-Logged ('=' * 78) 'Banner'

& powershell -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @ScriptArgs 2>&1 | ForEach-Object {
    $line = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_.ToString() }
    if ($null -ne $line) { Write-Logged $line }
}
$exit = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
$duration = '{0:hh\:mm\:ss}' -f ((Get-Date) - $started)
$verdict = if ($exit -ne 0 -or $script:Errors -gt 0) { 'FAIL' } elseif ($script:Warnings -gt 0) { 'WARN' } else { 'OK' }
$level = @{ FAIL = 'Error'; WARN = 'Warning'; OK = 'Success' }[$verdict]
$summary = "$verdict | $($script:Errors) errors | $($script:Warnings) warnings | exit $exit | $duration"
Write-Logged ('*' * 78) $level
Write-Logged "* BUILD VERDICT: $summary" $level
Write-Logged ('*' * 78) $level
$existing = [IO.File]::ReadAllText($logPath)
[IO.File]::WriteAllText($logPath, $summary + [Environment]::NewLine + [Environment]::NewLine + $existing, [Text.UTF8Encoding]::new($false))
Pop-Location
exit $exit
