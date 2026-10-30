#Requires -Version 5.1
# Shared setup/start composition. Imports occur within function scopes so library
# CLI parameter blocks never overwrite wrapper switches. No global environment
# writes or policy changes. Plan starts no package/runtime provider.

function Invoke-OwaspAiGoatWindowsWrapperHost {
    . (Join-Path $PSScriptRoot 'host-preflight.ps1')
    return Invoke-OwaspAiGoatWindowsHostPreflight
}

function Invoke-OwaspAiGoatWindowsWrapperProvision {
    param($Request)
    . (Join-Path $PSScriptRoot 'dependencies.ps1')
    return Invoke-OwaspAiGoatWindowsDependencies -ExecuteMode $true -RepoRoot $Request.repoRoot -UserProfile $Request.userProfile -SystemRoot $Request.systemRoot -ProcessEnvironment $Request.environment
}

function Get-OwaspAiGoatWindowsWrapperBindings {
    param($Request,
        [scriptblock]$Runner = $null,
        [scriptblock]$Probe = $null,
        [scriptblock]$Find = { (Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source },
        [scriptblock]$Exists = { param($File) Test-Path -LiteralPath $File -PathType Leaf },
        [scriptblock]$NormalFile = { param($File) $entry = Get-Item -LiteralPath $File -Force -ErrorAction Stop; return (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and -not $entry.PSIsContainer) }
    )
    . (Join-Path $PSScriptRoot 'dependencies.ps1')
    . (Join-Path $PSScriptRoot 'packages.ps1')
    if (-not $Runner) { $Runner = ${function:Invoke-OwaspAiGoatPrerequisiteProcess} }
    if (-not $Probe) { $Probe = ${function:Get-OwaspAiGoatNativePackageProbe} }
    $policy = Get-OwaspAiGoatDependencyCoordinatorPolicy $Request.repoRoot
    $tools = Join-Path $Request.userProfile '.owasp-ai-goat\tools'
    foreach ($name in @('npm-bootstrap-operation.json','windows-package-operation.json','windows-package-restart.json')) { if (& $Exists (Join-Path $tools $name)) { throw 'WINDOWS_WRAPPER_OPERATION_RETAINED' } }
    $candidates = @(); try { $found = & $Find; if ($found) { $candidates += [string]$found } } catch { }
    $candidates += Join-Path $tools ('node-v' + $policy.nodeMinimum + '-win-x64\node.exe')
    $node = $null
    foreach ($candidate in $candidates) {
        try {
            if (-not [IO.Path]::IsPathRooted($candidate) -or -not (& $Exists $candidate) -or -not (& $NormalFile $candidate)) { continue }
            $checked = & $Runner @{ id = 'wrapperNodeVersion'; executable = $candidate; arguments = @('--version'); capture = $true; timeoutMs = 10000 }
            if ($checked.exitCode -eq 0 -and $checked.output.Trim() -cmatch '^v\d+\.\d+\.\d+$' -and [version]$checked.output.Trim().Substring(1) -ge [version]$policy.nodeMinimum) { $node = $candidate; break }
        } catch { }
    }
    if (-not $node) { throw 'WINDOWS_WRAPPER_NODE_UNAVAILABLE' }
    $npm = $null
    foreach ($candidate in @((Join-Path $tools ('npm-' + $policy.npmMinimum + '\node_modules\npm\bin\npm-cli.js')),(Join-Path (Split-Path $node -Parent) 'node_modules\npm\bin\npm-cli.js'))) {
        if (-not (& $Exists $candidate) -or -not (& $NormalFile $candidate)) { continue }
        $checked = & $Runner @{ id = 'wrapperNpmVersion'; executable = $node; arguments = @($candidate,'--version'); capture = $true; timeoutMs = 10000 }
        if ($checked.exitCode -eq 0 -and $checked.output.Trim() -ceq $policy.npmMinimum) { $npm = $candidate; break }
    }
    if (-not $npm) { throw 'WINDOWS_WRAPPER_NPM_UNAVAILABLE' }
    $bindings = @{ nodeExecutable = $node; npmCli = $npm; npmExecpath = $npm }
    foreach ($spec in @(@{ id = 'git'; key = 'gitExecutable' },@{ id = 'python'; key = 'pythonExecutable' },@{ id = 'buildTools'; key = 'visualStudioInstallation' },@{ id = 'ollama'; key = 'ollamaExecutable' },@{ id = 'multipass'; key = 'multipassExecutable' },@{ id = 'opensshClient'; key = 'sshExecutable' })) {
        $checked = & $Probe $spec.id $Runner
        if ($checked.id -cne $spec.id -or $checked.status -cne 'present' -or $checked.path -isnot [string] -or -not [IO.Path]::IsPathRooted($checked.path)) { throw 'WINDOWS_WRAPPER_PACKAGE_UNAVAILABLE' }
        $bindings[$spec.key] = $checked.path
    }
    if ((& $Probe 'ollamaService' $Runner).status -cne 'present') { throw 'WINDOWS_WRAPPER_OLLAMA_UNAVAILABLE' }
    return [pscustomobject]@{ componentSucceeded = $true; restartRequired = $false; operationRetained = $false; operationUncertain = $false; bindings = $bindings; childEnvironment = (New-OwaspAiGoatWindowsDependencyEnvironment -Bindings $bindings -Environment $Request.environment) }
}

function New-OwaspAiGoatWindowsCanonicalProcessInfo {
    param($Request)
    . (Join-Path $PSScriptRoot 'dependencies.ps1')
    . (Join-Path $PSScriptRoot 'prerequisites.ps1')
    $expected = Join-Path $Request.repoRoot $(if ($Request.kind -ceq 'start') { 'scripts\start-application.js' } elseif ($Request.kind -ceq 'setup') { 'scripts\setup-application.js' } else { throw 'WINDOWS_WRAPPER_PROCESS_DENIED' })
    if ($Request.arguments[0] -cne $expected -or -not [IO.Path]::IsPathRooted($Request.executable) -or $Request.environment -isnot [System.Collections.IDictionary]) { throw 'WINDOWS_WRAPPER_PROCESS_DENIED' }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Request.executable; $info.UseShellExecute = $false; $info.WorkingDirectory = $Request.repoRoot
    $info.Arguments = @($Request.arguments | ForEach-Object { ConvertTo-OwaspAiGoatProcessArgument $_ }) -join ' '
    # Replacement is essential: overlay leaves inherited VCINSTALLDIR or stale
    # executable bindings in place. Caller secrets stay inside this child only.
    $info.EnvironmentVariables.Clear()
    foreach ($key in $Request.environment.Keys) { $info.EnvironmentVariables[$key] = $Request.environment[$key] }
    return $info
}

function Invoke-OwaspAiGoatWindowsCanonicalProcess {
    param($Request)
    $info = New-OwaspAiGoatWindowsCanonicalProcessInfo $Request
    $child = [Diagnostics.Process]::Start($info)
    try {
        if ($Request.kind -ceq 'start') {
            # Foreground supervisor lifetime is owned by canonical start and its
            # authenticated Stop/signal drain, not a package-probe timeout.
            $child.WaitForExit()
        } elseif (-not $child.WaitForExit(3600000)) {
            # Do not terminate mid-migration/model/package work. Report an
            # indeterminate live operation; never retry it automatically.
            throw 'WINDOWS_WRAPPER_SETUP_OPERATION_UNCERTAIN'
        }
        return @{ exitCode = $child.ExitCode }
    } finally { $child.Dispose() }
}

function Invoke-OwaspAiGoatWindowsWrapperHandoff {
    param([ValidateSet('setup','start')][string]$Kind,
        [bool]$PlanMode = $false, [bool]$NoInstall = $false, [bool]$Upgrade = $false, [bool]$Repair = $false, [bool]$InitDb = $false,
        [bool]$CompositionReady = $false,
        [string]$RepoRoot = (Join-Path $PSScriptRoot '..\..\..'), [string]$UserProfile = $env:USERPROFILE, [string]$SystemRoot = $env:SystemRoot,
        [System.Collections.IDictionary]$Environment = $null,
        [scriptblock]$ObserveHost = ${function:Invoke-OwaspAiGoatWindowsWrapperHost},
        [scriptblock]$RootEnvironmentExists = { param($File) Test-Path -LiteralPath $File },
        [scriptblock]$IsElevated = { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) },
        [scriptblock]$Provision = ${function:Invoke-OwaspAiGoatWindowsWrapperProvision},
        [scriptblock]$Discover = ${function:Get-OwaspAiGoatWindowsWrapperBindings},
        [scriptblock]$Runner = ${function:Invoke-OwaspAiGoatWindowsCanonicalProcess}
    )
    $RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
    $arguments = @((Join-Path $RepoRoot $(if ($Kind -ceq 'setup') { 'scripts\setup-application.js' } else { 'scripts\start-application.js' })))
    if ($PlanMode) { $arguments += '--plan' }
    if ($Kind -ceq 'setup') {
        if ($NoInstall) { $arguments += '--no-install' }; if ($Upgrade) { $arguments += '--upgrade' }; if ($Repair) { $arguments += '--repair' }
    } elseif ($InitDb) { $arguments += '--init-db' }
    $result = [ordered]@{ schemaVersion = 1; component = ('windows-' + $Kind + '-handoff'); nonMutating = $PlanMode; componentSucceeded = $false; installationBlocked = $true; hostAdmission = $null; arguments = $arguments; bindings = $null; restartRequired = $false; operationRetained = $false; operationUncertain = $false; blockers = @() }
    try {
        $result.hostAdmission = & $ObserveHost
        if ($result.hostAdmission.hostSupported -isnot [bool] -or $result.hostAdmission.hostSupported -ne $true) { $result.blockers += 'WINDOWS_HOST_PREFLIGHT_DENIED' }
        if ($Kind -ceq 'setup' -and -not $Upgrade -and -not $Repair -and (& $RootEnvironmentExists (Join-Path $RepoRoot '.env'))) { $result.blockers += 'WINDOWS_FRESH_ENVIRONMENT_EXISTS' }
        if (-not $CompositionReady) { $result.blockers += 'WINDOWS_WRAPPER_COMPOSITION_PENDING' }
        # Plan works without Node and never invokes dependency/runtime providers.
        if ($PlanMode -or $result.blockers.Count -gt 0) { return [pscustomobject]$result }
        if (& $IsElevated) { throw 'WINDOWS_WRAPPER_RUN_AS_NORMAL_USER' }
        if ($null -eq $Environment) { $Environment = [Environment]::GetEnvironmentVariables('Process') }
        $request = @{ repoRoot = $RepoRoot; userProfile = $UserProfile; systemRoot = $SystemRoot; environment = $Environment }
        # --no-install skips locked npm installation only, as in canonical setup;
        # it does not waive required native prerequisites. Upgrade-only is DB-only.
        $dependency = $(if ($Kind -ceq 'setup' -and (-not $Upgrade -or $Repair)) { & $Provision $request } else { & $Discover $request })
        $result.restartRequired = ($dependency.restartRequired -eq $true); $result.operationRetained = $dependency.operationRetained; $result.operationUncertain = ($dependency.operationUncertain -eq $true)
        if ($dependency.componentSucceeded -ne $true -or $result.restartRequired -or $result.operationRetained -or $result.operationUncertain) {
            $result.blockers += @($dependency.blockers | Where-Object { $_ -is [string] -and $_ -cmatch '^WINDOWS_[A-Z0-9_]+$' })
            throw 'WINDOWS_WRAPPER_DEPENDENCIES_INCOMPLETE'
        }
        # Rebuild from admitted bindings, never trust a provider-supplied full env.
        . (Join-Path $PSScriptRoot 'dependencies.ps1')
        $child = New-OwaspAiGoatWindowsDependencyEnvironment -Bindings $dependency.bindings -Environment $Environment
        $result.bindings = $dependency.bindings
        $outcome = & $Runner @{ kind = $Kind; repoRoot = $RepoRoot; executable = $dependency.bindings.nodeExecutable; arguments = $arguments; environment = $child }
        if ($outcome.exitCode -isnot [int] -or $outcome.exitCode -ne 0) { throw 'WINDOWS_WRAPPER_CANONICAL_FAILED' }
        $result.componentSucceeded = $true; $result.installationBlocked = $false
    } catch {
        $code = [string]$_.Exception.Message
        if ($code -cnotmatch '^WINDOWS_[A-Z0-9_]+$') { $code = 'WINDOWS_WRAPPER_HANDOFF_FAILED' }
        if ($code -ceq 'WINDOWS_WRAPPER_SETUP_OPERATION_UNCERTAIN') { $result.operationUncertain = $true }
        if ($code -ceq 'WINDOWS_WRAPPER_OPERATION_RETAINED') { $result.operationRetained = $true }
        $result.blockers += $code
    }
    return [pscustomobject]$result
}
