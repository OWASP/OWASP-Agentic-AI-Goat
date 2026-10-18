#Requires -Version 5.1
<# Canonical native Windows foreground startup. Host and read-only dependency
   admission precede startup. Stop uses owned controller authority. #>
[CmdletBinding()]
param(
    [switch]$InitDb,
    [switch]$Plan,
    [switch]$Reset,
    [switch]$Stop
)
function Get-DvaiaWindowsStopNode {
    param(
        [string]$RepoRoot,
        [string]$UserProfile = $env:USERPROFILE,
        [scriptblock]$Find = { (Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source },
        [scriptblock]$Exists = { param($File)
            if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { return $false }
            $entry = Get-Item -LiteralPath $File -Force -ErrorAction Stop
            return (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
        },
        [scriptblock]$Runner = $null
    )
    $policy = Get-Content -LiteralPath (Join-Path $RepoRoot 'scripts\install\runtime-version-policy.sh') -Raw
    $matches = [regex]::Matches($policy, '(?m)^DVAIA_MINIMUM_NODE_VERSION=(\d+\.\d+\.\d+)\r?$')
    if ($matches.Count -ne 1) { throw 'WINDOWS_STOP_RUNTIME_POLICY_DENIED' }
    $minimum = $matches[0].Groups[1].Value
    if (-not $Runner) {
        # Import within function scope: the library's Plan/Execute parameters
        # cannot overwrite the startup wrapper's Plan/Stop switches.
        . (Join-Path $PSScriptRoot 'prerequisites.ps1')
        $Runner = ${function:Invoke-DvaiaPrerequisiteProcess}
    }
    $candidates = @()
    try { $installed = & $Find; if ($installed) { $candidates += [string]$installed } } catch { }
    if ([IO.Path]::IsPathRooted($UserProfile)) {
        $candidates += Join-Path $UserProfile ('.dvaia\tools\node-v' + $minimum + '-win-x64\node.exe')
    }
    foreach ($candidate in $candidates) {
        try {
            if (-not [IO.Path]::IsPathRooted($candidate) -or -not (& $Exists $candidate)) { continue }
            # Only bounded read-only probes may fall through after timeout/error.
            # Do not terminate a process or invoke installation as a fallback.
            $observed = & $Runner @{ id = 'verifyStopNode'; executable = $candidate; arguments = @('--version'); capture = $true; timeoutMs = 10000 }
            $version = $observed.output.Trim()
            if ($observed.exitCode -eq 0 -and $version -cmatch '^v(\d+\.\d+\.\d+)$' -and [version]$version.Substring(1) -ge [version]$minimum) { return $candidate }
        } catch { }
    }
    throw 'WINDOWS_STOP_RUNTIME_UNAVAILABLE'
}

if ($MyInvocation.InvocationName -ne '.') {
$ErrorActionPreference = 'Stop'
if ($Reset) {
    throw 'Startup never deletes databases. Use authenticated workshop reset controls or explicit migration tools.'
}
if ($Stop) {
    if ($Plan -or $InitDb) { throw '-Stop cannot be combined with -Plan or -InitDb.' }
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
    $node = Get-DvaiaWindowsStopNode -RepoRoot $RepoRoot
    & $node (Join-Path $RepoRoot 'scripts/launcher-control.js')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    return
}
. (Join-Path $PSScriptRoot 'wrapper-handoff.ps1')
$handoff = Invoke-DvaiaWindowsWrapperHandoff -Kind start -PlanMode ([bool]$Plan) -InitDb ([bool]$InitDb) -CompositionReady $true
$handoff | ConvertTo-Json -Depth 6
if ($Plan) {
    Write-Output 'Plan performed no service or database changes and did not require Node.js.'
    return
}
if ($handoff.blockers -contains 'WINDOWS_HOST_PREFLIGHT_DENIED') { throw 'WINDOWS_HOST_PREFLIGHT_DENIED: Use the reported approved Windows Hyper-V host requirements.' }
if ($handoff.blockers -contains 'WINDOWS_WRAPPER_COMPOSITION_PENDING') { throw 'WINDOWS_WRAPPER_COMPOSITION_PENDING: Required startup integration is unavailable. See docs/install/windows.md.' }
if (-not $handoff.componentSucceeded) { exit 1 }

}
