#Requires -Version 5.1
<# Unwired prerequisite handoff. Future wrapper contract:
   powershell.exe -NoProfile -File scripts/install/Windows/dependencies.ps1 -Execute
   Accept only componentSucceeded=true and use returned absolute bindings. A
   dot-sourced caller may use childEnvironment; CLI callers use exported
   New-OwaspAiGoatWindowsDependencyEnvironment with their private environment. This
   does not authorize full setup/start. Package restart retirement remains an
   explicit packages.ps1 -Execute -Resume operation; this coordinator never retries. #>
[CmdletBinding()]
param([switch]$Plan, [switch]$Execute)

function Get-OwaspAiGoatDependencyCoordinatorPolicy {
    param([string]$RepoRoot)
    $source = Get-Content -LiteralPath (Join-Path $RepoRoot 'scripts\install\runtime-version-policy.sh') -Raw
    $policy = @{}
    foreach ($entry in @(@{ key = 'nodeMinimum'; variable = 'NODE' },@{ key = 'npmMinimum'; variable = 'NPM' })) {
        $matches = [regex]::Matches($source, ('(?m)^OWASP_AI_GOAT_MINIMUM_' + $entry.variable + '_VERSION=(\d+\.\d+\.\d+)\r?$'))
        if ($matches.Count -ne 1) { throw 'WINDOWS_DEPENDENCIES_POLICY_DENIED' }
        $policy[$entry.key] = $matches[0].Groups[1].Value
    }
    return $policy
}

function ConvertTo-OwaspAiGoatDependencyStage {
    param($Value, [string]$ExpectedComponent)
    if ($Value.schemaVersion -ne 1 -or $Value.component -cne $ExpectedComponent -or $Value.componentSucceeded -isnot [bool]) { throw 'WINDOWS_DEPENDENCIES_COMPONENT_CONTRACT_DENIED' }
    # Only closed status codes cross the coordinator boundary; no raw provider
    # output, private journal identities, environment values or diagnostics.
    $blockers = @($Value.blockers | Where-Object { $_ -is [string] -and $_ -cmatch '^WINDOWS_[A-Z0-9_]+$' })
    $retained = ($Value.operationRetained -eq $true -or $blockers -contains 'WINDOWS_NPM_OPERATION_INDETERMINATE')
    return [pscustomobject]@{ component = $ExpectedComponent; componentSucceeded = $Value.componentSucceeded; restartRequired = ($Value.restartRequired -eq $true); operationRetained = $retained; blockers = $blockers }
}

function New-OwaspAiGoatWindowsDependencyEnvironment {
    # Consumer contract: replace the child's inherited environment (Clear +
    # copy all returned entries). Overlaying entries leaves removed variables
    # such as VCINSTALLDIR inherited. The current prerequisite runner overlays;
    # this result must not be passed to it as a faithful replacement yet.
    param($Bindings, [System.Collections.IDictionary]$Environment)
    $required = @('nodeExecutable','npmCli','npmExecpath','gitExecutable','pythonExecutable','visualStudioInstallation','ollamaExecutable','multipassExecutable','sshExecutable')
    $keys = $(if ($Bindings -is [System.Collections.IDictionary]) { @($Bindings.Keys) } else { @($Bindings.PSObject.Properties.Name) })
    if ((($keys | Sort-Object) -join ',') -cne (($required | Sort-Object) -join ',') -or $null -eq $Environment) { throw 'WINDOWS_DEPENDENCIES_CHILD_BINDING_DENIED' }
    foreach ($key in $required) {
        $value = $Bindings.$key
        if ($value -isnot [string] -or $value -match '[\r\n\0;]' -or -not [IO.Path]::IsPathRooted($value)) { throw 'WINDOWS_DEPENDENCIES_CHILD_BINDING_DENIED' }
    }
    foreach ($key in @('nodeExecutable','npmCli','npmExecpath','gitExecutable','pythonExecutable','ollamaExecutable','multipassExecutable','sshExecutable')) { if (-not [IO.Path]::GetFileName($Bindings.$key) -or -not [IO.Path]::GetDirectoryName($Bindings.$key)) { throw 'WINDOWS_DEPENDENCIES_CHILD_BINDING_DENIED' } }
    if ($Bindings.npmExecpath -cne $Bindings.npmCli) { throw 'WINDOWS_DEPENDENCIES_CHILD_BINDING_DENIED' }
    $controlled = @('Path','npm_execpath','PYTHON','NODE_GYP_FORCE_PYTHON','npm_package_config_node_gyp_msvs_version','VCINSTALLDIR','OWASP_AI_GOAT_WINDOWS_MULTIPASS_EXECUTABLE','OWASP_AI_GOAT_WINDOWS_SSH_EXECUTABLE')
    $child = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $priorPaths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in $Environment.Keys) {
        if ($key -isnot [string] -or $key -match '[=\r\n\0]' -or $Environment[$key] -isnot [string] -or $Environment[$key] -match '[\0]') { throw 'WINDOWS_DEPENDENCIES_CHILD_ENVIRONMENT_DENIED' }
        if ($key -ieq 'Path') {
            foreach ($part in $Environment[$key].Split(';')) { if ($part.Length -gt 0) { $priorPaths.Add($part) } }
        } elseif ($key -in $controlled) { continue }
        else { $child.Add($key,$Environment[$key]) }
    }
    $paths = @($Bindings.nodeExecutable,$Bindings.gitExecutable,$Bindings.pythonExecutable,$Bindings.ollamaExecutable) | ForEach-Object { [IO.Path]::GetDirectoryName($_) }
    $child.Add('Path', ((@($paths) + @($priorPaths)) -join ';'))
    $child.Add('npm_execpath',$Bindings.npmCli)
    $child.Add('NODE_GYP_FORCE_PYTHON',$Bindings.pythonExecutable)
    $child.Add('PYTHON',$Bindings.pythonExecutable)
    # Locked node-gyp12/13 lib/node-gyp.js prefers this config prefix, converts
    # msvs_version to msvs-version; find-visualstudio.js admits an absolute path.
    # Remove inherited VCINSTALLDIR: a different VS developer shell otherwise
    # restricts discovery to its installation despite this admitted selection.
    $child.Add('npm_package_config_node_gyp_msvs_version',$Bindings.visualStudioInstallation)
    # The lab session re-verifies these admitted executable observations. No
    # PATH lookup, global driver change or authentication command is delegated.
    $child.Add('OWASP_AI_GOAT_WINDOWS_MULTIPASS_EXECUTABLE',$Bindings.multipassExecutable)
    $child.Add('OWASP_AI_GOAT_WINDOWS_SSH_EXECUTABLE',$Bindings.sshExecutable)
    return ,$child
}

function ConvertTo-OwaspAiGoatWindowsDependenciesPublicResult {
    param($Value)
    # Never serialize childEnvironment: it preserves caller secrets privately.
    $public = [ordered]@{}
    foreach ($key in @('schemaVersion','component','nonMutating','componentSucceeded','installationBlocked','restartRequired','operationRetained','operationUncertain','runtimePolicy','bindings','stages','steps','blockers','delegated')) { $public[$key] = $Value.$key }
    return [pscustomobject]$public
}

function Invoke-OwaspAiGoatWindowsDependencies {
    param(
        [bool]$ExecuteMode = $false,
        [string]$RepoRoot = (Join-Path $PSScriptRoot '..\..\..'),
        [string]$UserProfile = $env:USERPROFILE,
        [string]$SystemRoot = $env:SystemRoot,
        [scriptblock]$Bootstrap = $null,
        [scriptblock]$Packages = $null,
        [scriptblock]$Runner = $null,
        [System.Collections.IDictionary]$ProcessEnvironment = $null
    )
    $policy = Get-OwaspAiGoatDependencyCoordinatorPolicy $RepoRoot
    $result = [ordered]@{
        schemaVersion = 1; component = 'windows-native-dependencies'; nonMutating = (-not $ExecuteMode)
        componentSucceeded = $false; installationBlocked = $true; restartRequired = $false; operationRetained = $false; operationUncertain = $false
        runtimePolicy = $policy; bindings = $null; childEnvironment = $null; stages = @()
        steps = @('verify or bootstrap pinned Node/npm','verify or provision Git/Python/MSVC/Windows SDK/Ollama/Multipass/OpenSSH client and service readiness')
        blockers = @('WINDOWS_PROTECTED_LAB_INTEGRATION_PENDING','WINDOWS_FULL_INSTALLER_INTEGRATION_PENDING')
        delegated = @('owned Hyper-V lab caller and lifecycle integration','locked npm ci and native addon build','Chrome installation and browser sandbox verification','configured 8B model pull and genuine inference','PostgreSQL and lab sidecar provisioning')
    }
    # Plan does not dot-source or invoke any component, process or provider seam.
    if (-not $ExecuteMode) { return [pscustomobject]$result }
    try {
        if (-not $Bootstrap -or -not $Packages -or -not $Runner) {
            # Library imports stay in this function scope; their CLI parameter
            # blocks cannot clobber the coordinator's Plan/Execute switches.
            . (Join-Path $PSScriptRoot 'packages.ps1')
            if (-not $Bootstrap) { $Bootstrap = { param($Request) Invoke-OwaspAiGoatWindowsPrerequisites -ExecuteMode $true -RepoRoot $Request.repoRoot -UserProfile $Request.userProfile -SystemRoot $Request.systemRoot } }
            if (-not $Packages) { $Packages = { param($Request) Invoke-OwaspAiGoatWindowsPackages -ExecuteMode $true -RepoRoot $Request.repoRoot -UserProfile $Request.userProfile -SystemRoot $Request.systemRoot } }
            if (-not $Runner) { $Runner = ${function:Invoke-OwaspAiGoatPrerequisiteProcess} }
        }
        $request = @{ repoRoot = $RepoRoot; userProfile = $UserProfile; systemRoot = $SystemRoot }
        $runtime = & $Bootstrap $request
        $stage = ConvertTo-OwaspAiGoatDependencyStage $runtime 'windows-native-prerequisites'
        $result.stages += $stage
        $result.restartRequired = $stage.restartRequired; $result.operationRetained = $stage.operationRetained
        if (-not $stage.componentSucceeded -or $stage.restartRequired -or $stage.operationRetained) { $result.blockers += 'WINDOWS_RUNTIME_COMPONENT_INCOMPLETE'; return [pscustomobject]$result }
        $binding = $runtime.runtime
        if ($binding.nodeExecutable -isnot [string] -or $binding.npmCli -isnot [string] -or $binding.npmExecpath -isnot [string] -or -not [IO.Path]::IsPathRooted($binding.nodeExecutable) -or -not [IO.Path]::IsPathRooted($binding.npmCli) -or $binding.npmExecpath -cne $binding.npmCli) { throw 'WINDOWS_DEPENDENCIES_RUNTIME_BINDING_DENIED' }
        $node = & $Runner @{ id = 'handoffNode'; executable = $binding.nodeExecutable; arguments = @('--version'); capture = $true; timeoutMs = 10000 }
        if ($node.exitCode -ne 0 -or $node.output.Trim() -cnotmatch '^v\d+\.\d+\.\d+$' -or [version]$node.output.Trim().Substring(1) -lt [version]$policy.nodeMinimum) { throw 'WINDOWS_DEPENDENCIES_NODE_HANDOFF_DENIED' }
        $npm = & $Runner @{ id = 'handoffNpm'; executable = $binding.nodeExecutable; arguments = @($binding.npmCli,'--version'); capture = $true; timeoutMs = 10000 }
        if ($npm.exitCode -ne 0 -or $npm.output.Trim() -cne $policy.npmMinimum) { throw 'WINDOWS_DEPENDENCIES_NPM_HANDOFF_DENIED' }
        # The native package component is PowerShell-based; it needs no Node PATH
        # lookup. Pass verified bindings as explicit context, never alter PATH.
        $request.runtime = @{ nodeExecutable = $binding.nodeExecutable; npmCli = $binding.npmCli; npmExecpath = $binding.npmExecpath }
        $native = & $Packages $request
        $stage = ConvertTo-OwaspAiGoatDependencyStage $native 'windows-native-packages'
        $result.stages += $stage
        $result.restartRequired = $stage.restartRequired; $result.operationRetained = $stage.operationRetained
        if (-not $stage.componentSucceeded -or $stage.restartRequired -or $stage.operationRetained) { $result.blockers += 'WINDOWS_PACKAGE_COMPONENT_INCOMPLETE'; return [pscustomobject]$result }
        $paths = @{}
        foreach ($spec in @(@{ id = 'git'; key = 'gitExecutable' },@{ id = 'python'; key = 'pythonExecutable' },@{ id = 'buildTools'; key = 'visualStudioInstallation' },@{ id = 'ollama'; key = 'ollamaExecutable' },@{ id = 'multipass'; key = 'multipassExecutable' },@{ id = 'opensshClient'; key = 'sshExecutable' })) {
            $observed = @($native.dependencies | Where-Object { $_.id -ceq $spec.id })
            if ($observed.Count -ne 1 -or $observed[0].status -cne 'present' -or $observed[0].path -isnot [string] -or -not [IO.Path]::IsPathRooted($observed[0].path)) { throw 'WINDOWS_DEPENDENCIES_PACKAGE_BINDING_DENIED' }
            $paths[$spec.key] = $observed[0].path
        }
        $service = @($native.dependencies | Where-Object { $_.id -ceq 'ollamaService' })
        if ($service.Count -ne 1 -or $service[0].status -cne 'present') { throw 'WINDOWS_DEPENDENCIES_OLLAMA_HANDOFF_DENIED' }
        $result.bindings = @{ nodeExecutable = $binding.nodeExecutable; npmCli = $binding.npmCli; npmExecpath = $binding.npmExecpath; gitExecutable = $paths.gitExecutable; pythonExecutable = $paths.pythonExecutable; visualStudioInstallation = $paths.visualStudioInstallation; ollamaExecutable = $paths.ollamaExecutable; multipassExecutable = $paths.multipassExecutable; sshExecutable = $paths.sshExecutable }
        if ($null -eq $ProcessEnvironment) { $ProcessEnvironment = [Environment]::GetEnvironmentVariables('Process') }
        $result.childEnvironment = New-OwaspAiGoatWindowsDependencyEnvironment -Bindings $result.bindings -Environment $ProcessEnvironment
        $result.componentSucceeded = $true
    } catch {
        $code = [string]$_.Exception.Message
        if ($code -cnotmatch '^WINDOWS_[A-Z0-9_]+$') { $code = 'WINDOWS_DEPENDENCIES_FAILED' }
        # A thrown component may have persisted a journal before it failed. Do
        # not assert it stopped or retry it; the component owns further recovery.
        $result.operationRetained = $null; $result.operationUncertain = $true
        $result.blockers += $code
    }
    return [pscustomobject]$result
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Plan -and $Execute) { throw '-Plan and -Execute cannot be combined.' }
    try {
        $output = Invoke-OwaspAiGoatWindowsDependencies -ExecuteMode ([bool]$Execute)
        ConvertTo-OwaspAiGoatWindowsDependenciesPublicResult $output | ConvertTo-Json -Depth 8
        if ($Execute -and -not $output.componentSucceeded) { exit 1 }
    } catch {
        [pscustomobject]@{ schemaVersion = 1; component = 'windows-native-dependencies'; componentSucceeded = $false; installationBlocked = $true; code = 'WINDOWS_DEPENDENCIES_FAILED' } | ConvertTo-Json
        exit 1
    }
}
