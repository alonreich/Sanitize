param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)

$ErrorActionPreference = 'Continue'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $repoRoot
$IsDev = $Rest -contains '--dev'
$NoPublish = $IsDev -or ($Rest -contains '--no-publish')
$appProj = Join-Path $repoRoot 'src\Sanitization.App\Sanitization.App.csproj'
$cliProj = Join-Path $repoRoot 'src\Sanitization.Cli\Sanitization.Cli.csproj'
$testProj = Join-Path $repoRoot 'tests\Sanitization.Tests\Sanitization.Tests.csproj'
$compiled = Join-Path $repoRoot 'Compiled'
$publishDir = Join-Path $repoRoot 'obj\publish\NativeAot'
$changelog = Join-Path $repoRoot 'docs\CHANGELOG.md'
$version = Get-Date -Format 'yyyy.MM.dd.HHmm'

function Fail([string]$msg) { Write-Host "ERROR: $msg"; exit 1 }

Write-Host "##########################################################"
Write-Host " Sanitization build  |  mode: $(if ($IsDev) { 'DEV' } elseif ($NoPublish) { 'LOCAL RELEASE (no publish)' } else { 'OFFICIAL RELEASE' })  |  version $version"
Write-Host "##########################################################"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { Fail '.NET SDK not found. Install the .NET 10 SDK from https://dot.net' }
$sdks = (& dotnet --list-sdks) -join "`n"
if ($sdks -notmatch '(?m)^10\.') { Fail '.NET 10 SDK is required (found: ' + ($sdks -replace "`n", ', ') + ')' }

function Initialize-MsvcToolchain {
    $installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
    if ((Test-Path -LiteralPath $installer) -and ($env:PATH -notlike "*$installer*")) { $env:PATH = "$installer;$env:PATH" }
    if (Get-Command link.exe -ErrorAction SilentlyContinue) { return $true }
    $vswhere = Join-Path $installer 'vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { return $false }
    foreach ($inst in (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null)) {
        if ([string]::IsNullOrWhiteSpace($inst)) { continue }
        $devCmd = Join-Path $inst.Trim() 'Common7\Tools\VsDevCmd.bat'
        if (-not (Test-Path -LiteralPath $devCmd)) { continue }
        foreach ($line in (& cmd.exe /d /c "`"$devCmd`" -arch=x64 -host_arch=x64 >nul && set")) {
            $eq = $line.IndexOf('=')
            if ($eq -gt 0) { [Environment]::SetEnvironmentVariable($line.Substring(0, $eq), $line.Substring($eq + 1), 'Process') }
        }
        if (Get-Command link.exe -ErrorAction SilentlyContinue) { return $true }
    }
    return $false
}
if (-not (Initialize-MsvcToolchain)) { Fail 'NativeAOT needs the MSVC linker. Install Visual Studio (or Build Tools) with "Desktop development with C++".' }
Write-Host 'Native AOT toolchain detected.'

$repo = $null
if (-not $NoPublish) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot '.git'))) {
        Fail ("This folder is not a git repository yet, so there is nothing to release.`n" +
              "       One-time setup:  git init -b main  ;  git add -A  ;  git commit -m `"Initial commit`"`n" +
              "                        gh repo create Sanitization --private --source . --push`n" +
              "       Or build locally without publishing:  build.cmd --no-publish")
    }
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Fail 'GitHub CLI (gh) not found. Install it from https://cli.github.com and run: gh auth login' }
    & gh auth status *> $null
    if ($LASTEXITCODE -ne 0) { Fail 'GitHub CLI is not signed in. Run: gh auth login' }
    $status = (& git status --porcelain) -join "`n"
    if ($status.Trim()) { Fail "Working tree has uncommitted changes. Commit them first:`n$status" }
    & git fetch --quiet origin 2>$null
    $branch = (& git branch --show-current).Trim()
    $default = ((& git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>$null) -replace '^origin/', '').Trim()
    if (-not $default) { $default = 'main' }
    if ($branch -ne $default) { Fail "Releases are made from '$default' (you are on '$branch')." }
    $ahead = (& git rev-list --count "origin/$branch..HEAD" 2>$null)
    $behind = (& git rev-list --count "HEAD..origin/$branch" 2>$null)
    if ("$behind" -ne '0') { Fail "Your branch is behind origin/$branch. Pull first." }
    if ("$ahead" -ne '0') { Fail "You have $ahead unpushed commit(s). Push first, then release." }
    if (-not (Test-Path -LiteralPath $changelog)) { Fail 'docs\CHANGELOG.md is missing.' }
    $cl = Get-Content -LiteralPath $changelog -Raw
    $m = [regex]::Match($cl, '(?ms)^## Unreleased\s*\r?\n(.*?)(?=^## |\z)')
    if (-not $m.Success -or -not ($m.Groups[1].Value -replace '(?m)^\s*[-#*]?\s*$', '').Trim()) { Fail 'docs\CHANGELOG.md: write release notes under "## Unreleased" first.' }
    $notes = $m.Groups[1].Value.Trim()
    $repo = (& gh repo view --json nameWithOwner --jq .nameWithOwner).Trim()
    Write-Host "[RELEASE] Preflight OK: $repo, branch $branch, clean and pushed."
}

foreach ($proc in [System.Diagnostics.Process]::GetProcesses()) {
    try {
        $exe = $proc.MainModule.FileName
        if ($exe -and $exe.StartsWith($compiled, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "  -> Stopping $([IO.Path]::GetFileName($exe)) (PID $($proc.Id)): runs from .\Compiled"
            $proc.Kill(); [void]$proc.WaitForExit(5000)
        }
    } catch { } finally { $proc.Dispose() }
}

Write-Host '[TEST] Running unit tests...'
& dotnet test $testProj -c Release --nologo -v q
if ($LASTEXITCODE -ne 0) { Fail 'Unit tests failed. Nothing was built.' }
Write-Host 'SUCCESS: all unit tests passed.'

function Invoke-Publish([string]$Proj, [string]$OutDir, [bool]$SingleThreaded) {
    $pubArgs = @('publish', $Proj, '-c', 'Release', '-r', 'win-x64', '-p:PublishAot=true', '-p:SelfContained=true', '-p:TreatWarningsAsErrors=true',
        '-p:NativeDebugSymbols=false', "-p:Version=$version", '-nodeReuse:false', '-p:UseSharedCompilation=false', '-o', $OutDir, '-v', 'm')
    if ($SingleThreaded) { $pubArgs += '-p:IlcSingleThreaded=true' }
    $crashed = $false
    & dotnet @pubArgs 2>&1 | ForEach-Object {
        $line = $_.ToString(); Write-Host $line
        if ($line -match 'NativeAotFatalErrorException|CodeGenerationFailedException|error IL1013') { $crashed = $true }
    }
    return [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Crashed = $crashed }
}
if (Test-Path -LiteralPath $publishDir) { Remove-Item -LiteralPath $publishDir -Recurse -Force -ErrorAction SilentlyContinue }
foreach ($target in @(@{ Name = 'sanitize.exe (GUI)'; Proj = $appProj; Out = $publishDir }, @{ Name = 'ai-sanitize.exe (headless CLI)'; Proj = $cliProj; Out = $publishDir })) {
    Write-Host "[NativeAOT] Publishing $($target.Name) $version ..."
    $res = Invoke-Publish $target.Proj $target.Out $false
    if (-not $res.Ok -and $res.Crashed) { Write-Host 'WARNING: [NativeAOT] ILC crashed internally; retrying single-threaded...'; $res = Invoke-Publish $target.Proj $target.Out $true }
    if (-not $res.Ok) { Fail "NativeAOT publish of $($target.Name) failed (see the first error above)." }
}

if (-not $IsDev -and (Test-Path -LiteralPath $compiled)) { Get-ChildItem -LiteralPath $compiled -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $compiled | Out-Null
$wanted = @(Get-ChildItem -LiteralPath $publishDir -File | Where-Object { $_.Extension -in '.exe', '.dll' })
foreach ($exe in 'sanitize.exe', 'ai-sanitize.exe') { if (-not ($wanted | Where-Object Name -eq $exe)) { Fail "$exe was not produced." } }
foreach ($old in 'Sanitization.exe') { $o = Join-Path $compiled $old; if (Test-Path -LiteralPath $o) { Remove-Item -LiteralPath $o -Force; Write-Host "  -> removed old $old (renamed to sanitize.exe)" } }
foreach ($f in $wanted) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $compiled $f.Name) -Force }
foreach ($e in Get-ChildItem -LiteralPath $compiled -Force) {
    if ($e.Extension -notin '.exe', '.dll') { Remove-Item -LiteralPath $e.FullName -Recurse -Force; Write-Host "  -> removed stray $($e.Name) from .\Compiled" }
}
Write-Host "Verified .\Compiled: $((Get-ChildItem -LiteralPath $compiled | ForEach-Object Name) -join ', ')"

$terms = @()
if ($env:USERNAME -and $env:USERNAME.Length -ge 3) { $terms += "Users\$($env:USERNAME)"; $terms += "Users/$($env:USERNAME)" }
if ($env:COMPUTERNAME) { $terms += $env:COMPUTERNAME }
foreach ($bin in Get-ChildItem -LiteralPath $compiled -Filter '*.exe') {
    $bytes = [IO.File]::ReadAllBytes($bin.FullName)
    $ascii = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
    $wide = [Text.Encoding]::Unicode.GetString($bytes)
    foreach ($t in $terms) {
        if ($ascii.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or $wide.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Fail "[Privacy] $($bin.Name) contains this PC's user / computer name (a build path). Not shipping it."
        }
    }
}
Write-Host '[Privacy] Compiled binaries contain no user name, profile path or computer name.'
if ($NoPublish) { Write-Host "SUCCESS: built .\Compiled\sanitize.exe + ai-sanitize.exe ($version)."; exit 0 }

$tag = "v$version"
Set-Content -LiteralPath (Join-Path $repoRoot 'version.txt') -Value $version -NoNewline
$props = Join-Path $repoRoot 'Directory.Build.props'
(Get-Content -LiteralPath $props -Raw) -replace "(<Version Condition=""'\`$\(Version\)' == ''"">)[^<]*(</Version>)", "`${1}$version`${2}" | Set-Content -LiteralPath $props -NoNewline
$cl = Get-Content -LiteralPath $changelog -Raw
$cl = [regex]::Replace($cl, '(?m)^## Unreleased\s*$', "## Unreleased`r`n`r`n## $tag ($(Get-Date -Format 'yyyy-MM-dd'))", 1)
Set-Content -LiteralPath $changelog -Value $cl -NoNewline
& git add version.txt Directory.Build.props docs/CHANGELOG.md
& git commit -q -m "Release $tag"
if ($LASTEXITCODE -ne 0) { Fail 'Could not create the release commit.' }
& git tag -a $tag -m "Release $tag"
& git push -q origin HEAD
& git push -q origin $tag
if ($LASTEXITCODE -ne 0) { Write-Host 'ERROR: [PUBLISH] STOPPED: could not push the release commit / tag.'; exit 2 }

$zip = Join-Path $repoRoot "obj\Sanitization-$tag-win-x64.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $compiled '*') -DestinationPath $zip
$sha = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($zip))) -replace '-', '').ToLowerInvariant()
if ($sha.Length -ne 64) { Write-Host 'ERROR: [PUBLISH] STOPPED: could not compute SHA-256 of the zip.'; exit 2 }
$sums = Join-Path $repoRoot 'obj\SHA256SUMS.txt'
Set-Content -LiteralPath $sums -Value "$sha  $([IO.Path]::GetFileName($zip))" -NoNewline
$notesFile = Join-Path $repoRoot 'obj\release-notes.md'
Set-Content -LiteralPath $notesFile -Value $notes
& gh release create $tag $zip $sums --repo $repo --title "Sanitization $tag" --notes-file $notesFile
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: [PUBLISH] STOPPED: GitHub release $tag was not created (tag is pushed; rerun: gh release create $tag ...)."; exit 2 }
$assets = (& gh release view $tag --repo $repo --json assets --jq '.assets[].name') -join ','
if ($assets -notmatch [regex]::Escape([IO.Path]::GetFileName($zip))) { Write-Host 'ERROR: [PUBLISH] STOPPED: release asset missing after upload.'; exit 2 }
Write-Host "SUCCESS: released $tag to https://github.com/$repo/releases/tag/$tag"
exit 0
