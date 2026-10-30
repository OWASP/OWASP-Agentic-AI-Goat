#Requires -Version 5.1
<# Read-only inventory. This is not an installer or native Windows qualification.
   Dot-source for controlled probes; direct invocation emits one JSON document.
   No private configuration is read and raw command output is never returned. #>
[CmdletBinding()]
param()

function Invoke-OwaspAiGoatDependencyProbe {
    param([string]$Name, [string]$Command, [string[]]$Arguments)
    $found = Get-Command $Command -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    # Avoid launching the Microsoft Store Python execution alias during inventory.
    if ($Name -eq 'python' -and $found -and $found.Source -match '\\Microsoft\\WindowsApps\\') { $found = $null }
    if (-not $found) { return @{ available = $false; exitCode = -1; output = '' } }
    $process = New-Object System.Diagnostics.Process
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    # Arguments are internal fixed probe literals, never user/config values.
    $quotedArgs = @($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    if ($found.Source -match '\.(cmd|bat)$') {
        $info.FileName = $env:ComSpec
        $info.Arguments = '/d /s /c ""' + $found.Source + '" ' + $quotedArgs + '"'
    } else {
        $info.FileName = $found.Source
        $info.Arguments = $quotedArgs
    }
    if ($Name -eq 'ollamaModel') { $info.EnvironmentVariables['OLLAMA_HOST'] = 'http://127.0.0.1:11434' }
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(5000)) {
            $process.Kill()
            return @{ available = $true; exitCode = -1; output = '' }
        }
        # A descendant can retain redirected pipes after the probe exits.
        # Never let a non-mutating inventory wait indefinitely for those pipes.
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 1000)) {
            return @{ available = $true; exitCode = -1; output = '' }
        }
        return @{ available = $true; exitCode = $process.ExitCode; output = $stdout.GetAwaiter().GetResult() + "`n" + $stderr.GetAwaiter().GetResult() }
    } catch { return @{ available = $true; exitCode = -1; output = '' } }
    finally { $process.Dispose() }
}

function Get-OwaspAiGoatVersionStatus {
    param($Observation, [string]$Minimum)
    if (-not $Observation.available) { return 'missing' }
    if ($Observation.exitCode -ne 0 -or -not $Observation.output.Trim()) { return 'missing' }
    if ($Observation.output -notmatch '(?m)^\s*(?:v|Python |git version |ollama version is )?(\d+\.\d+\.\d+)(?:\s|$|\.)') { return 'versionUnsupported' }
    if ($Minimum -and ([version]$Matches[1] -lt [version]$Minimum)) { return 'versionUnsupported' }
    return 'present'
}

function New-OwaspAiGoatDependencyItem {
    param([string]$Id, [string]$Status, [string]$Requirement, [string]$NextStep)
    return [pscustomobject][ordered]@{ id = $Id; status = $Status; requirement = $Requirement; nextStep = $NextStep }
}

function Get-OwaspAiGoatPythonInventoryStatus {
    param($Observation)
    $status = Get-OwaspAiGoatVersionStatus $Observation '3.11.0'
    if ($status -ne 'present') { return $status }
    # Match the maintained Python range admitted by packages.ps1. A version
    # probe alone does not establish its separate x64 executable requirement.
    if ($Observation.output -notmatch '(?m)^\s*Python 3\.(11|12|13|14)\.\d+\s*$') { return 'versionUnsupported' }
    return 'present'
}

function Get-OwaspAiGoatWindowsDependencyPlan {
    [CmdletBinding()]
    param(
        [string]$RepoRoot = (Join-Path $PSScriptRoot '..\..\..'),
        [scriptblock]$Probe = ${function:Invoke-OwaspAiGoatDependencyProbe},
        [scriptblock]$PathProbe = { param($Path) Test-Path -LiteralPath $Path -PathType Leaf },
        [scriptblock]$SdkProbe = {
            param($ProgramFilesX86)
            if (-not $ProgramFilesX86) { return $false }
            $kits = Join-Path $ProgramFilesX86 'Windows Kits\10'
            $versions = @(Get-ChildItem -LiteralPath (Join-Path $kits 'Include') -Directory -ErrorAction SilentlyContinue)
            foreach ($version in $versions) {
                $header = Join-Path $version.FullName 'um\Windows.h'
                $library = Join-Path $kits ('Lib\' + $version.Name + '\um\x64\kernel32.lib')
                if ((Test-Path -LiteralPath $header -PathType Leaf) -and (Test-Path -LiteralPath $library -PathType Leaf)) { return $true }
            }
            return $false
        },
        [hashtable]$Environment = @{
            Browser = $env:PUPPETEER_EXECUTABLE_PATH; BrowserCache = $env:PUPPETEER_CACHE_DIR
            UserProfile = $env:USERPROFILE; ProgramFilesX86 = ${env:ProgramFiles(x86)}
            ExternalPostgres = [bool]$env:PG_ADMIN_DATABASE_URL; Model = $env:OLLAMA_MODEL
            Windows = ($env:OS -eq 'Windows_NT'); Architecture = $env:PROCESSOR_ARCHITECTURE
        }
    )
    $policy = Get-Content -LiteralPath (Join-Path $RepoRoot 'scripts/install/runtime-version-policy.sh') -Raw
    if ($policy -notmatch '(?m)^OWASP_AI_GOAT_MINIMUM_NODE_VERSION=(\d+\.\d+\.\d+)\s*$') { throw 'Missing Node runtime policy.' }
    $nodeMinimum = $Matches[1]
    if ($policy -notmatch '(?m)^OWASP_AI_GOAT_MINIMUM_NPM_VERSION=(\d+\.\d+\.\d+)\s*$') { throw 'Missing npm runtime policy.' }
    $npmMinimum = $Matches[1]
    $lock = Get-Content -LiteralPath (Join-Path $RepoRoot 'package-lock.json') -Raw | ConvertFrom-Json
    $nativePackages = @('hnswlib-node', 'bcrypt', 'better-sqlite3', 'sqlite3')
    $nativeEvidence = @($nativePackages | ForEach-Object {
        $entry = $lock.packages.PSObject.Properties['node_modules/' + $_]
        if ($entry) { [pscustomobject]@{ name = $_; version = $entry.Value.version } }
    })
    $items = New-Object 'System.Collections.Generic.List[object]'
    $hostStatus = 'versionUnsupported'
    if ($Environment.Windows -and $Environment.Architecture -eq 'AMD64') { $hostStatus = 'present' }
    $items.Add((New-OwaspAiGoatDependencyItem 'windowsHost' $hostStatus 'Native Windows x64 inventory candidate; full installer integration remains incomplete.' 'Installation remains blocked by incomplete Windows installer integration and the pending Docker/protected sandbox backend decision.'))
    foreach ($spec in @(
        @{ id = 'node'; command = 'node.exe'; minimum = $nodeMinimum },
        @{ id = 'npm'; command = 'npm.cmd'; minimum = $npmMinimum },
        @{ id = 'git'; command = 'git.exe'; minimum = '' },
        @{ id = 'ollama'; command = 'ollama.exe'; minimum = '' }
    )) {
        $observation = & $Probe $spec.id $spec.command @('--version')
        $status = Get-OwaspAiGoatVersionStatus $observation $spec.minimum
        $requirement = $spec.id + ' command available'
        if ($spec.minimum) { $requirement = $spec.id + ' >= ' + $spec.minimum + ' (shared qualified installer floor)' }
        $items.Add((New-OwaspAiGoatDependencyItem $spec.id $status $requirement 'Install or verify this prerequisite separately; this plan makes no changes.'))
    }
    # The locked source-building hnswlib-node addon requires node-gyp prerequisites.
    # The package component admits maintained Python 3.11 through 3.14;
    # node-gyp discovery alone does not define the supported installer range.
    # Windows build requirements: https://github.com/nodejs/node-gyp#on-windows
    $python = & $Probe 'python' 'python.exe' @('--version')
    if ((Get-OwaspAiGoatPythonInventoryStatus $python) -ne 'present') {
        $pythonFallback = & $Probe 'python' 'py.exe' @('-3', '--version')
        if ($pythonFallback.available) { $python = $pythonFallback }
    }
    $items.Add((New-OwaspAiGoatDependencyItem 'python' (Get-OwaspAiGoatPythonInventoryStatus $python) 'Python 3.11 through 3.14 version candidate for locked native addons; packages must separately verify x64.' 'Provide Python 3.11 through 3.14 x64 through the native package component; this inventory makes no changes.'))
    $vswhere = 'vswhere.exe'
    if ($Environment.ProgramFilesX86) { $vswhere = Join-Path $Environment.ProgramFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe' }
    $vs = & $Probe 'cppBuildTools' $vswhere @('-latest', '-products', '*', '-version', '[16.0,)', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationVersion')
    $items.Add((New-OwaspAiGoatDependencyItem 'cppBuildTools' (Get-OwaspAiGoatVersionStatus $vs '16.0.0') 'Visual Studio 2019+ C++ toolchain candidate; Build Tools and full Visual Studio both admitted to inventory.' 'Install the Desktop development with C++ workload; node-gyp must verify MSBuild/toolchain/SDK compatibility.'))
    $sdkStatus = 'missing'
    if (& $SdkProbe $Environment.ProgramFilesX86) { $sdkStatus = 'present' }
    $items.Add((New-OwaspAiGoatDependencyItem 'windowsSdk' $sdkStatus 'Matching Windows SDK header and x64 library candidates for native addons.' 'Install the Windows SDK through the C++ workload; qualify node-gyp/native addon builds.'))
    $docker = & $Probe 'docker' 'docker.exe' @('--version')
    $dockerStatus = 'missing'
    if ($docker.available -and $docker.exitCode -eq 0 -and $docker.output -match '^Docker version \d+\.\d+\.\d+') { $dockerStatus = 'present' }
    elseif ($docker.available) { $dockerStatus = 'versionUnsupported' }
    $items.Add((New-OwaspAiGoatDependencyItem 'docker' $dockerStatus 'Docker CLI for local PostgreSQL 18 and Linux lab sidecars, including external PostgreSQL installs.' 'Select and qualify the Windows Docker/backend authority; do not change contexts or services.'))
    $compose = & $Probe 'compose' 'docker.exe' @('compose', 'version', '--short')
    $items.Add((New-OwaspAiGoatDependencyItem 'compose' (Get-OwaspAiGoatVersionStatus $compose '2.0.0') 'Docker Compose v2 plugin.' 'Provide the Compose v2 plugin and verify owned daemon binding.'))
    $daemon = & $Probe 'linuxDockerDaemon' 'docker.exe' @('version', '--format', '{{.Server.Os}}')
    $daemonStatus = 'missing'
    if ($daemon.available -and $daemon.exitCode -eq 0) {
        $daemonStatus = 'versionUnsupported'
        if ($daemon.output.Trim() -eq 'linux') { $daemonStatus = 'present' }
    }
    $items.Add((New-OwaspAiGoatDependencyItem 'linuxDockerDaemon' $daemonStatus 'Reachable Linux container daemon; current context is inventory, never admitted authority.' 'Windows Docker/protected sandbox backend integration remains pending; this inventory cannot authorize a daemon.'))
    $model = & $Probe 'ollamaModel' 'ollama.exe' @('list')
    $modelStatus = 'missing'
    if ($model.available -and $model.exitCode -eq 0 -and $model.output -match '(?m)^llama3\.1:8b\s') { $modelStatus = 'present' }
    if ($Environment.Model -and $Environment.Model -ne 'llama3.1:8b') { $modelStatus = 'versionUnsupported' }
    $items.Add((New-OwaspAiGoatDependencyItem 'ollamaModel' $modelStatus 'Local llama3.1:8b inventory at 127.0.0.1:11434; no inference performed.' 'Verify or pull the qualified 8B model separately, then qualify actual inference.'))
    $browserStatus = 'missing'
    if ($Environment.Browser) {
        $browserStatus = 'versionUnsupported'
        if ([IO.Path]::IsPathRooted($Environment.Browser) -and (& $PathProbe $Environment.Browser)) { $browserStatus = 'present' }
    } else {
        $cache = $Environment.BrowserCache
        if (-not $cache -and $Environment.UserProfile) { $cache = Join-Path $Environment.UserProfile '.cache\puppeteer' }
        if ($cache) {
            $candidates = @(Get-ChildItem -Path (Join-Path $cache 'chrome\win64-*\chrome-win64\chrome.exe') -ErrorAction SilentlyContinue)
            if ($candidates.Count -gt 0) { $browserStatus = 'present' }
        }
    }
    $items.Add((New-OwaspAiGoatDependencyItem 'browser' $browserStatus 'Puppeteer Chrome for Testing or explicit PUPPETEER_EXECUTABLE_PATH file candidate.' 'Locked npm installation provisions Chrome; setup must launch/close it sandboxed before database work.'))
    $pgStatus = 'missing'
    if ($Environment.ExternalPostgres -or $daemonStatus -eq 'present') { $pgStatus = 'present' }
    $items.Add((New-OwaspAiGoatDependencyItem 'postgres' $pgStatus 'External PG_ADMIN_DATABASE_URL presence or Linux Docker candidate for PostgreSQL 18; no connection tested.' 'Validate administrator access, private configuration and 16 runtime/migration pairs through supported provisioning.'))
    return [pscustomobject][ordered]@{
        schemaVersion = 1; platform = 'windows'; nonMutating = $true
        installationBlocked = $true; nativeQualified = $false
        blockers = @('WINDOWS_NATIVE_INSTALL_UNQUALIFIED', 'WINDOWS_PRIVATE_AUTHORITY_UNQUALIFIED', 'WINDOWS_OWNED_SANDBOX_BACKEND_UNDECIDED')
        runtimePolicy = @{ nodeMinimum = $nodeMinimum; npmMinimum = $npmMinimum }
        nativeAddonEvidence = $nativeEvidence; dependencies = @($items.ToArray())
        statusMeaning = @{ present = 'Inventory candidate detected; component validation and installer integration remain separate'; missing = 'Capability not detected or read-only probe failed'; versionUnsupported = 'Detected version, configuration or platform cannot satisfy this plan' }
        qualification = 'Inventory presence is not service readiness, model provenance, browser sandbox proof, database authority or supported sandbox admission.'
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Get-OwaspAiGoatWindowsDependencyPlan | ConvertTo-Json -Depth 6
}
