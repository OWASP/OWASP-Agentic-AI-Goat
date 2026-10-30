#Requires -Version 5.1
<# Opt-in native packages only. Plan starts no process. The dependency
   coordinator invokes this component after host admission; owned Hyper-V lab
   and protected sandbox readiness remain separately gated.
   Sources: https://learn.microsoft.com/en-us/windows/package-manager/winget/install
   https://learn.microsoft.com/en-us/windows/package-manager/winget/source
   https://docs.ollama.com/windows
   https://raw.githubusercontent.com/nodejs/node/v26.10.0/BUILDING.md
   https://devguide.python.org/versions/
   https://docs.python.org/3.13/using/windows.html#installing-without-ui
   https://raw.githubusercontent.com/git-for-windows/build-extra/main/installer/install.iss
   https://raw.githubusercontent.com/ollama/ollama/main/app/updater/updater_windows.go
   https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/c/Canonical/Multipass/1.16.4/Canonical.Multipass.installer.yaml
   https://raw.githubusercontent.com/canonical/multipass/v1.16.4/packaging/windows/wix/Package.wxs
   https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse #>
[CmdletBinding()]
param([switch]$Plan, [switch]$Execute, [switch]$Resume)
$packagePlanFlag = $Plan; $packageExecuteFlag = $Execute; $packageResumeFlag = $Resume
. (Join-Path $PSScriptRoot 'prerequisites.ps1')
$Plan = $packagePlanFlag; $Execute = $packageExecuteFlag; $Resume = $packageResumeFlag

function Get-OwaspAiGoatNativePackagePolicy {
    # node-gyp 12/13 discovers Python >=3.6; maintained CPython is an additional
    # installation policy, not a fabricated node-gyp minimum. Node26 needs VS17.14+.
    return @(
        @{ id = 'git'; package = 'Git.Git'; scope = 'user' },
        @{ id = 'python'; package = 'Python.Python.3.13'; scope = 'user'; supported = '3.11 through 3.14, x64' },
        @{ id = 'buildTools'; package = 'Microsoft.VisualStudio.2022.BuildTools'; scope = 'machine'; supported = 'VS17.14+ or VS18, MSVC14.44+, SDK26100' },
        @{ id = 'ollama'; package = 'Ollama.Ollama'; scope = 'user' },
        @{ id = 'multipass'; package = 'Canonical.Multipass'; scope = 'machine'; version = '1.16.4'; supported = 'stable1.16.4+ within1.16.x, existing hyperv driver only; never upgrade an existing installation' },
        @{ id = 'opensshClient'; capability = 'OpenSSH.Client~~~~0.0.1.0'; supported = 'Microsoft in-box client only; no server installation' }
    )
}

function Find-OwaspAiGoatPackageExecutable {
    param([string]$Name, [string[]]$Candidates = @())
    foreach ($candidate in $Candidates) { if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate } }
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and $command.Source -notmatch '\\WindowsApps\\python') { return $command.Source }
    return $null
}

function Test-OwaspAiGoatPackageSignature {
    param([string]$File, [string]$Publisher)
    $signature = Get-AuthenticodeSignature -LiteralPath $File -ErrorAction Stop
    return ($signature.Status -eq 'Valid' -and $signature.SignerCertificate.Subject -match $Publisher)
}

function Test-OwaspAiGoatMultipassExistingFootprint {
    # Fresh MSI writes daemon configuration and can stop an existing service.
    # Refuse adoption/upgrade, including orphan data or custom storage, rather
    # than invoking that installer over any possibly unrelated installation.
    if ($env:MULTIPASS_STORAGE -or [Environment]::GetEnvironmentVariable('MULTIPASS_STORAGE','Machine')) { return $true }
    foreach ($path in @((Join-Path $env:ProgramData 'Multipass'),(Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local\multipassd'),(Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Roaming\multipassd'),(Join-Path $env:LOCALAPPDATA 'multipass'),(Join-Path $env:LOCALAPPDATA 'multipass-client-certificate'),(Join-Path $env:ProgramFiles 'Multipass'))) {
        if (Test-Path -LiteralPath $path -ErrorAction Stop) { return $true }
    }
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Multipass','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Multipass')) { if (Test-Path -LiteralPath $key -ErrorAction Stop) { return $true } }
    try { $service = Get-Service -Name Multipass -ErrorAction Stop; return ($null -ne $service) }
    catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }; return $false }
}

function Get-OwaspAiGoatNativePackageProbe {
    param([string]$Id, [scriptblock]$Runner)
    $missing = @{ id = $Id; status = 'missing' }
    switch ($Id) {
        'hyperVHost' {
            . (Join-Path $PSScriptRoot 'host-preflight.ps1')
            $hostAdmission = Invoke-OwaspAiGoatWindowsHostPreflight
            return @{ id = $Id; status = $(if ($hostAdmission.hostSupported) { 'present' } else { 'versionUnsupported' }) }
        }
        'multipass' {
            $file = Join-Path $env:ProgramFiles 'Multipass\bin\multipass.exe'
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
                if (Test-OwaspAiGoatMultipassExistingFootprint) { return @{ id = $Id; status = 'versionUnsupported'; existingInstallation = $true } }
                return $missing
            }
            if (-not (Test-OwaspAiGoatPackageSignature $file 'O=Canonical(?: Group)? (?:Ltd\.?|Limited)(?:,|$)')) { throw 'WINDOWS_MULTIPASS_SIGNATURE_DENIED' }
            $version = & $Runner @{ id = 'probeMultipassVersion'; executable = $file; arguments = @('--version'); capture = $true; timeoutMs = 10000 }
            $versions = [regex]::Matches($version.output, '(?m)^(multipassd?)\s+(1\.16\.[0-9]+)(?:\+win)?\s*$')
            if ($version.exitCode -ne 0 -or $versions.Count -ne 2 -or $versions[0].Groups[1].Value -ceq $versions[1].Groups[1].Value -or $versions[0].Groups[2].Value -cne $versions[1].Groups[2].Value -or [version]$versions[0].Groups[2].Value -lt [version]'1.16.4') { return @{ id = $Id; status = 'versionUnsupported'; existingInstallation = $true } }
            $driver = & $Runner @{ id = 'probeMultipassDriver'; executable = $file; arguments = @('get','local.driver'); capture = $true; timeoutMs = 10000 }
            if ($driver.exitCode -ne 0 -or $driver.output.Trim() -cne 'hyperv') { return @{ id = $Id; status = 'versionUnsupported'; existingInstallation = $true } }
            return @{ id = $Id; status = 'present'; path = $file; version = $versions[0].Groups[2].Value; driver = 'hyperv' }
        }
        'opensshClient' {
            $file = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
            if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $missing }
            if (-not (Test-OwaspAiGoatPackageSignature $file 'O=Microsoft Corporation(?:,|$)')) { throw 'WINDOWS_OPENSSH_SIGNATURE_DENIED' }
            $observed = & $Runner @{ id = 'probeOpenSSHClient'; executable = $file; arguments = @('-V'); capture = $true; timeoutMs = 10000 }
            if ($observed.exitCode -ne 0 -or $observed.output.Trim() -cnotmatch '^OpenSSH_for_Windows_([0-9]+\.[0-9]+(?:p[0-9]+)?),\s+.+$') { return @{ id = $Id; status = 'versionUnsupported' } }
            return @{ id = $Id; status = 'present'; path = $file; version = $Matches[1] }
        }
        'winget' {
            $app = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $app) { return $missing }
            $file = Join-Path $app.InstallLocation 'winget.exe'
            if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or -not (Test-OwaspAiGoatPackageSignature $file 'O=Microsoft Corporation(?:,|$)')) { return $missing }
            return @{ id = $Id; status = 'present'; path = $file }
        }
        'python' {
            $candidates = @((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'))
            foreach ($minor in @(14,12,11)) { $candidates += Join-Path $env:LOCALAPPDATA ('Programs\Python\Python3' + $minor + '\python.exe') }
            $file = Find-OwaspAiGoatPackageExecutable 'python.exe' $candidates
            if (-not $file) { return $missing }
            $observed = & $Runner @{ id = 'probePython'; executable = $file; arguments = @('-I','-c','import sys,struct,json; print(json.dumps({"version":".".join(map(str,sys.version_info[:3])),"bits":struct.calcsize("P")*8,"path":sys.executable}))'); capture = $true; timeoutMs = 10000 }
            if ($observed.exitCode -ne 0) { return $missing }
            $value = $observed.output | ConvertFrom-Json
            $supported = ($value.version -match '^3\.(11|12|13|14)\.\d+$' -and $value.bits -eq 64)
            return @{ id = $Id; status = $(if ($supported) { 'present' } else { 'versionUnsupported' }); path = $value.path; version = $value.version }
        }
        'buildTools' {
            $where = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
            if (-not (Test-Path -LiteralPath $where -PathType Leaf)) { return $missing }
            if (-not (Test-OwaspAiGoatPackageSignature $where 'O=Microsoft Corporation(?:,|$)')) { throw 'WINDOWS_VSWHERE_SIGNATURE_DENIED' }
            $observed = & $Runner @{ id = 'probeVisualStudio'; executable = $where; arguments = @('-products','*','-version','[17.14,19.0)','-format','json','-utf8'); capture = $true; timeoutMs = 10000 }
            if ($observed.exitCode -ne 0) { return $missing }
            $instances = @($observed.output | ConvertFrom-Json) | Where-Object { $_.isComplete -and $_.isLaunchable -and -not $_.isPrerelease } | Sort-Object installationVersion -Descending
            foreach ($instance in $instances) {
                $home = $instance.installationPath
                $msbuild = Join-Path $home 'MSBuild\Current\Bin\MSBuild.exe'
                $toolset = Join-Path $home 'VC\Tools\MSVC'
                $compiler = @(Get-ChildItem -LiteralPath $toolset -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^14\.\d+\.\d+$' -and [version]$_.Name -ge [version]'14.44.0' } | ForEach-Object { Join-Path $_.FullName 'bin\Hostx64\x64\cl.exe' } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
                $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
                $sdkPresent = $true
                foreach ($relative in @('Include\10.0.26100.0\um\Windows.h','Include\10.0.26100.0\ucrt\stdio.h','Lib\10.0.26100.0\um\x64\kernel32.lib','Lib\10.0.26100.0\ucrt\x64\ucrt.lib')) {
                    if (-not (Test-Path -LiteralPath (Join-Path $sdk $relative) -PathType Leaf)) { $sdkPresent = $false }
                }
                if ($compiler.Count -gt 0 -and $sdkPresent -and (Test-Path -LiteralPath $msbuild -PathType Leaf)) {
                    $checked = & $Runner @{ id = 'probeMsbuild'; executable = $msbuild; arguments = @('-version','-nologo'); capture = $true; timeoutMs = 10000 }
                    if ($checked.exitCode -eq 0 -and $checked.output.Trim() -match '^1[78]\.\d+\.\d+(?:\.\d+)?$') { return @{ id = $Id; status = 'present'; path = $home; version = $instance.installationVersion } }
                }
            }
            if ($instances.Count -gt 0) { return @{ id = $Id; status = 'versionUnsupported'; modifyPath = $instances[0].installationPath } }
            return $missing
        }
        'ollamaService' {
            try {
                $version = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/version' -Method Get -TimeoutSec 3 -ErrorAction Stop
                if ($version.version -match '^\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?$') { return @{ id = $Id; status = 'present'; version = $version.version } }
            } catch { }
            return $missing
        }
        default {
            if ($Id -eq 'git') { $file = Find-OwaspAiGoatPackageExecutable 'git.exe' @((Join-Path $env:ProgramFiles 'Git\cmd\git.exe'),(Join-Path $env:LOCALAPPDATA 'Programs\Git\cmd\git.exe')); $pattern = '^git version 2\.\d+\.\d+' }
            elseif ($Id -eq 'ollama') { $file = Find-OwaspAiGoatPackageExecutable 'ollama.exe' @((Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe')); $pattern = '\b\d+\.\d+\.\d+\b' }
            else { throw 'WINDOWS_PACKAGE_PROBE_DENIED' }
            if (-not $file) { return $missing }
            $observed = & $Runner @{ id = ('probe' + $Id); executable = $file; arguments = @('--version'); capture = $true; timeoutMs = 10000 }
            return @{ id = $Id; status = $(if ($observed.exitCode -eq 0 -and $observed.output -match $pattern) { 'present' } else { 'versionUnsupported' }); path = $file }
        }
    }
}

function Invoke-OwaspAiGoatTrustedPackageAction {
    param($Request)
    if ($Request.id -eq 'installopensshClient') {
        # Fixed Microsoft client capability only. No sshd, firewall, policy or
        # authentication commands; DISM may report3010, never reboot itself.
        $expected = Join-Path $env:SystemRoot 'System32\dism.exe'
        $fixed = @('/Online','/Add-Capability','/CapabilityName:OpenSSH.Client~~~~0.0.1.0','/NoRestart','/Quiet')
        if ($Request.executable -cne $expected -or ($Request.arguments -join '|') -cne ($fixed -join '|') -or -not (Test-OwaspAiGoatPackageSignature $expected 'O=Microsoft Corporation(?:,|$)')) { throw 'WINDOWS_OPENSSH_INSTALL_ACTION_DENIED' }
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $expected; $start.UseShellExecute = $true; $start.Verb = 'runas'
        $start.Arguments = @($fixed | ForEach-Object { ConvertTo-OwaspAiGoatProcessArgument $_ }) -join ' '
        $child = [Diagnostics.Process]::Start($start)
        try {
            if (-not $child.WaitForExit($Request.timeoutMs)) { throw 'WINDOWS_PACKAGE_TIMEOUT' }
            return @{ exitCode = $child.ExitCode }
        } finally { $child.Dispose() }
    }
    if ($Request.id -eq 'visualStudioModify') {
        # Only this fixed Microsoft installer action may request UAC. No npm or
        # repository command is admitted here. Keep unrelated installed addons.
        $expected = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\setup.exe'
        if ($Request.executable -ne $expected -or -not (Test-OwaspAiGoatPackageSignature $expected 'O=Microsoft Corporation(?:,|$)')) { throw 'WINDOWS_VS_INSTALLER_DENIED' }
        $actionArguments = @($Request.arguments)
        $fixed = @('modify','--installPath',$null,'--add','Microsoft.VisualStudio.Workload.VCTools','--add','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','--add','Microsoft.VisualStudio.Component.Windows11SDK.26100','--quiet','--norestart')
        if ($actionArguments.Count -ne $fixed.Count) { throw 'WINDOWS_VS_ARGUMENTS_DENIED' }
        for ($index = 0; $index -lt $fixed.Count; $index++) { if ($index -ne 2 -and $actionArguments[$index] -cne $fixed[$index]) { throw 'WINDOWS_VS_ARGUMENTS_DENIED' } }
        $home = [IO.Path]::GetFullPath($actionArguments[2])
        $roots = @((Join-Path $env:ProgramFiles 'Microsoft Visual Studio'),(Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio'))
        $admitted = $false
        foreach ($root in $roots) { if ($home.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { $admitted = $true } }
        if (-not $admitted -or $actionArguments[2] -ne $home) { throw 'WINDOWS_VS_INSTALL_PATH_DENIED' }
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = $expected; $start.UseShellExecute = $true; $start.Verb = 'runas'
        $start.Arguments = @($Request.arguments | ForEach-Object { ConvertTo-OwaspAiGoatProcessArgument $_ }) -join ' '
        $child = [Diagnostics.Process]::Start($start)
        try {
            if (-not $child.WaitForExit($Request.timeoutMs)) { throw 'WINDOWS_PACKAGE_TIMEOUT' }
            return @{ exitCode = $child.ExitCode }
        } finally { $child.Dispose() }
    }
    if ($Request.id -eq 'ollamaStart') {
        $expected = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama app.exe'
        if ($Request.executable -ne $expected -or -not (Test-OwaspAiGoatPackageSignature $expected 'O=Ollama Inc\.(?:,|$)')) { throw 'WINDOWS_OLLAMA_APP_DENIED' }
        # GUI tray is deliberately long lived; acknowledge launch, then verify API.
        $child = Start-Process -FilePath $expected -PassThru -ErrorAction Stop
        $child.Dispose(); return @{ exitCode = 0 }
    }
    return Invoke-OwaspAiGoatPrerequisiteProcess $Request
}

function Get-OwaspAiGoatPackageBootBinding {
    param([scriptblock]$Runner, [string]$PowerShell, [string]$RepoRoot)
    # Reuse the reviewed native host/boot observation; no independent WMI identity.
    $wire = @{ version = 1; operation = 'capture'; pid = $PID } | ConvertTo-Json -Compress
    $response = & $Runner @{ id = 'packageBootCapture'; executable = $PowerShell; arguments = @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $RepoRoot 'scripts\windows\windows-process-identity.ps1')); input = $wire; capture = $true; timeoutMs = 30000 }
    $ack = $response.output | ConvertFrom-Json
    if ($response.exitCode -ne 0 -or $ack.version -ne 1 -or $ack.ok -ne $true -or $ack.operation -cne 'capture') { throw 'WINDOWS_PACKAGE_BOOT_OBSERVATION_DENIED' }
    return [pscustomobject]@{ hostSha256 = $ack.data.hostSha256; bootFileTime = $ack.data.bootFileTime; currentSid = $ack.data.currentSid }
}

function Test-OwaspAiGoatPackageBootBinding {
    param($Binding)
    $keys = @($Binding.PSObject.Properties.Name | Sort-Object) -join ','
    return ($keys -ceq 'bootFileTime,currentSid,hostSha256' -and $Binding.hostSha256 -is [string] -and $Binding.hostSha256 -cmatch '^[a-f0-9]{64}$' -and $Binding.bootFileTime -is [string] -and $Binding.bootFileTime -cmatch '^[1-9][0-9]{0,18}$' -and $Binding.currentSid -is [string] -and $Binding.currentSid -cmatch '^S-1-[0-9]+(?:-[0-9]+){1,15}$' -and $Binding.currentSid.Length -le 184)
}

function Invoke-OwaspAiGoatWindowsPackages {
    param(
        [bool]$ExecuteMode = $false,
        [bool]$ResumeRestart = $false,
        [string]$RepoRoot = (Join-Path $PSScriptRoot '..\..\..'),
        [string]$UserProfile = $env:USERPROFILE,
        [string]$SystemRoot = $env:SystemRoot,
        [scriptblock]$Runner = ${function:Invoke-OwaspAiGoatTrustedPackageAction},
        [scriptblock]$Probe = ${function:Get-OwaspAiGoatNativePackageProbe},
        [scriptblock]$Exists = { param($File) Test-Path -LiteralPath $File -PathType Leaf },
        [scriptblock]$HostSupported = { $env:OS -eq 'Windows_NT' -and $env:PROCESSOR_ARCHITECTURE -eq 'AMD64' -and [int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber -ge 19045 },
        [scriptblock]$IsElevated = { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) },
        [scriptblock]$Pause = { Start-Sleep -Milliseconds 500 },
        [scriptblock]$BootObservation = ${function:Get-OwaspAiGoatPackageBootBinding}
    )
    $result = [ordered]@{ schemaVersion = 1; component = 'windows-native-packages'; nonMutating = (-not $ExecuteMode); installationBlocked = $true; nativeQualified = $false; restartRequired = $false; operationRetained = $false; componentSucceeded = $false; completed = @(); dependencies = @(); packages = @(Get-OwaspAiGoatNativePackagePolicy); blockers = @('WINDOWS_PROTECTED_SANDBOX_INTEGRATION_PENDING','WINDOWS_GLOBAL_INSTALL_UNQUALIFIED'); delegated = @('pinned Node/npm bootstrap','locked npm ci and native addon build','Chrome installation and browser sandbox qualification','llama3.1:8b model pull and genuine inference','PostgreSQL and owned Hyper-V lab provisioning') }
    # Crucial: Plan never invokes even read-only executable probes or helper scripts.
    if (-not $ExecuteMode) { return [pscustomobject]$result }
    if (-not (& $HostSupported)) { $result.blockers += 'WINDOWS_HOST_UNSUPPORTED'; return [pscustomobject]$result }
    if (& $IsElevated) { $result.blockers += 'WINDOWS_RUN_AS_NORMAL_USER'; return [pscustomobject]$result }
    if (-not [IO.Path]::IsPathRooted($UserProfile) -or -not [IO.Path]::IsPathRooted($SystemRoot)) { throw 'WINDOWS_PACKAGE_PATH_DENIED' }
    $powershell = Join-Path $SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $helper = Join-Path $RepoRoot 'scripts\windows\windows-private-state.ps1'
    $base = Join-Path $UserProfile '.owasp-ai-goat'; $tools = Join-Path $base 'tools'
    $marker = Join-Path $tools 'windows-package-operation.json'
    $receipt = Join-Path $tools 'windows-package-restart.json'
    $hasMarker = & $Exists $marker; $hasReceipt = & $Exists $receipt
    # Check both names: orphan receipts never authorize another operation.
    if ($hasMarker -or $hasReceipt) {
        $result.operationRetained = $true
        if (-not $ResumeRestart -or -not $hasMarker -or -not $hasReceipt) {
            $result.blockers += $(if ($hasMarker -and $hasReceipt -and -not $ResumeRestart) { 'WINDOWS_PACKAGE_RESTART_RESUME_REQUIRED' } else { 'WINDOWS_PACKAGE_OPERATION_INDETERMINATE' })
            return [pscustomobject]$result
        }
    } elseif ($ResumeRestart) { $result.blockers += 'WINDOWS_PACKAGE_RESTART_NOT_PENDING'; return [pscustomobject]$result }

    foreach ($directory in @($base,$tools)) {
        $wire = @{ version = 1; operation = 'ensurePrivateDirectory'; path = $directory } | ConvertTo-Json -Compress
        $response = & $Runner @{ id = 'packagePrivateDirectory'; executable = $powershell; arguments = @('-NoLogo','-NoProfile','-NonInteractive','-File',$helper); input = $wire; capture = $true; timeoutMs = 30000 }
        $ack = $response.output | ConvertFrom-Json
        if ($response.exitCode -ne 0 -or $ack.version -ne 1 -or $ack.ok -ne $true) { throw 'WINDOWS_PACKAGE_PRIVATE_DIRECTORY_DENIED' }
    }
    $lock = Get-Content -LiteralPath (Join-Path $RepoRoot 'package-lock.json') -Raw | ConvertFrom-Json
    $gypEntries = @($lock.packages.PSObject.Properties | Where-Object { $_.Name -match '(^|/)node_modules/node-gyp$' })
    if ($gypEntries.Count -eq 0 -or @($gypEntries | Where-Object { $_.Value.version -notmatch '^(12|13)\.' }).Count -gt 0) { $result.blockers += 'WINDOWS_LOCKED_NODE_GYP_POLICY_UNQUALIFIED'; return [pscustomobject]$result }
    $perform = {
        param([string]$Id, $Request, [scriptblock]$Verify)
        $binding = & $BootObservation $Runner $powershell $RepoRoot
        if (-not (Test-OwaspAiGoatPackageBootBinding $binding)) { throw 'WINDOWS_PACKAGE_BOOT_OBSERVATION_DENIED' }
        # Fresh CreateNew below also prevents concurrent replay after the name check.
        $bytes = [Text.Encoding]::UTF8.GetBytes((@{ version = 2; operation = $Id; outcome = 'indeterminate'; bootBinding = $binding } | ConvertTo-Json -Depth 4 -Compress))
        $wire = @{ version = 1; operation = 'createPrivateFile'; path = $marker; bytesBase64 = [Convert]::ToBase64String($bytes) } | ConvertTo-Json -Compress
        $result.operationRetained = $true
        $response = & $Runner @{ id = 'packageOperationJournal'; executable = $powershell; arguments = @('-NoLogo','-NoProfile','-NonInteractive','-File',$helper); input = $wire; capture = $true; timeoutMs = 30000 }
        $result.operationRetained = $true
        $ack = $response.output | ConvertFrom-Json
        if ($response.exitCode -ne 0 -or $ack.version -ne 1 -or $ack.ok -ne $true -or $ack.operation -ne 'createPrivateFile' -or $ack.path -ne $marker -or $ack.size -ne $bytes.Length -or $ack.identity.fileId -notmatch '^[a-f0-9]{16}$') { throw 'WINDOWS_PACKAGE_JOURNAL_DENIED' }
        $outcome = & $Runner $Request
        # Exact WinGet restart codes from AppInstallerErrors.h, plus MSI codes.
        if ($outcome.exitCode -in @(3010,1641,-1978334967,-1978334966,-1978334965)) {
            $result.restartRequired = $true; $result.blockers += 'WINDOWS_PACKAGE_RESTART_REQUIRED'
            # REBOOT_REQUIRED_FOR_INSTALL does not acknowledge a completed install.
            if ($outcome.exitCode -eq -1978334966) { $result.blockers += 'WINDOWS_PACKAGE_RESTART_INSTALL_INCOMPLETE'; return $false }
            $restartBytes = [Text.Encoding]::UTF8.GetBytes((@{ version = 1; outcome = 'restartRequired'; exitCode = $outcome.exitCode; journalBytesBase64 = [Convert]::ToBase64String($bytes); journalIdentity = $ack.identity } | ConvertTo-Json -Depth 4 -Compress))
            $wire = @{ version = 1; operation = 'createPrivateFile'; path = $receipt; bytesBase64 = [Convert]::ToBase64String($restartBytes) } | ConvertTo-Json -Compress
            $written = & $Runner @{ id = 'packageRestartReceipt'; executable = $powershell; arguments = @('-NoLogo','-NoProfile','-NonInteractive','-File',$helper); input = $wire; capture = $true; timeoutMs = 30000 }
            $receiptAck = $written.output | ConvertFrom-Json
            if ($written.exitCode -ne 0 -or $receiptAck.version -ne 1 -or $receiptAck.ok -ne $true -or $receiptAck.operation -cne 'createPrivateFile' -or $receiptAck.path -cne $receipt -or $receiptAck.size -ne $restartBytes.Length -or $receiptAck.identity.fileId -cnotmatch '^[a-f0-9]{16}$') { throw 'WINDOWS_PACKAGE_RESTART_RECEIPT_UNCERTAIN' }
            return $false
        }
        if ($outcome.exitCode -ne 0) { throw 'WINDOWS_PACKAGE_INSTALL_FAILED' }
        if (-not (& $Verify)) { throw 'WINDOWS_PACKAGE_VERIFICATION_FAILED' }
        $wire = @{ version = 1; operation = 'deleteMatchingPrivateFile'; path = $marker; bytesBase64 = [Convert]::ToBase64String($bytes); expectedIdentity = $ack.identity } | ConvertTo-Json -Depth 4 -Compress
        $response = & $Runner @{ id = 'packageOperationRetire'; executable = $powershell; arguments = @('-NoLogo','-NoProfile','-NonInteractive','-File',$helper); input = $wire; capture = $true; timeoutMs = 30000 }
        $deleted = $response.output | ConvertFrom-Json
        if ($response.exitCode -ne 0 -or $deleted.version -ne 1 -or $deleted.ok -ne $true -or $deleted.deleted -ne $true) { throw 'WINDOWS_PACKAGE_OPERATION_RETIRE_UNCERTAIN' }
        $result.operationRetained = $false; $result.completed += $Id; return $true
    }
    try {
        if ($ResumeRestart) {
            $records = @{}
            foreach ($entry in @(@{ key = 'journal'; path = $marker },@{ key = 'receipt'; path = $receipt })) {
                $wire = @{ version = 1; operation = 'readPrivateFile'; path = $entry.path } | ConvertTo-Json -Compress
                $read = & $Runner @{ id = ('packageResumeRead' + $entry.key); executable = $powershell; arguments = @('-NoLogo','-NoProfile','-NonInteractive','-File',$helper); input = $wire; capture = $true; timeoutMs = 30000 }
                $ack = $read.output | ConvertFrom-Json
                if ($read.exitCode -ne 0 -or $ack.version -ne 1 -or $ack.ok -ne $true -or $ack.operation -cne 'readPrivateFile' -or $ack.path -cne $entry.path -or $ack.size -lt 1 -or $ack.size -gt 4096 -or $ack.identity.fileId -cnotmatch '^[a-f0-9]{16}$') { throw 'WINDOWS_PACKAGE_RESTART_RECORD_DENIED' }
                $raw = [Convert]::FromBase64String($ack.bytesBase64)
                if ($raw.Length -ne $ack.size -or [Convert]::ToBase64String($raw) -cne $ack.bytesBase64) { throw 'WINDOWS_PACKAGE_RESTART_RECORD_DENIED' }
                $records[$entry.key] = @{ ack = $ack; value = ([Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json) }
            }
            $journal = $records.journal; $saved = $records.receipt.value
            if ((@($journal.value.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'bootBinding,operation,outcome,version' -or $journal.value.version -isnot [int] -or $journal.value.version -ne 2 -or $journal.value.outcome -cne 'indeterminate' -or -not (Test-OwaspAiGoatPackageBootBinding $journal.value.bootBinding)) { throw 'WINDOWS_PACKAGE_RESTART_RECORD_DENIED' }
            if ((@($saved.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'exitCode,journalBytesBase64,journalIdentity,outcome,version' -or $saved.version -isnot [int] -or $saved.version -ne 1 -or $saved.outcome -cne 'restartRequired' -or $saved.exitCode -isnot [int] -or $saved.exitCode -notin @(3010,1641,-1978334967,-1978334965) -or $saved.journalBytesBase64 -isnot [string] -or $saved.journalBytesBase64 -cne $journal.ack.bytesBase64 -or $saved.journalIdentity.fileId -cne $journal.ack.identity.fileId -or $saved.journalIdentity.volumeSerial -ne $journal.ack.identity.volumeSerial -or (@($saved.journalIdentity.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'fileId,volumeSerial') { throw 'WINDOWS_PACKAGE_RESTART_RECEIPT_DENIED' }
            $targets = @{ wingetBootstrap = 'winget'; installgit = 'git'; installpython = 'python'; installbuildTools = 'buildTools'; installollama = 'ollama'; ollamaStart = 'ollamaService'; installmultipass = 'multipass'; installopensshClient = 'opensshClient' }
            if ($journal.value.operation -cnotin @($targets.Keys)) { throw 'WINDOWS_PACKAGE_RESTART_OPERATION_DENIED' }
            $fresh = & $BootObservation $Runner $powershell $RepoRoot
            $prior = $journal.value.bootBinding
            if (-not (Test-OwaspAiGoatPackageBootBinding $fresh) -or $fresh.hostSha256 -cne $prior.hostSha256 -or $fresh.currentSid -cne $prior.currentSid) { throw 'WINDOWS_PACKAGE_RESTART_HOST_DENIED' }
            if ([UInt64]$fresh.bootFileTime -le [UInt64]$prior.bootFileTime) { $result.restartRequired = $true; throw 'WINDOWS_PACKAGE_RESTART_BOOT_UNCHANGED' }
            if ((& $Probe $targets[$journal.value.operation] $Runner).status -cne 'present') { throw 'WINDOWS_PACKAGE_RESTART_POSTCONDITION_DENIED' }
            # Resume retires only this acknowledged operation, then returns. It
            # cannot implicitly launch any installer. Both names remain guarded
            # if either identity-bound retirement is interrupted or uncertain.
            foreach ($entry in @(@{ key = 'journal'; path = $marker },@{ key = 'receipt'; path = $receipt })) {
                $record = $records[$entry.key].ack
                $wire = @{ version = 1; operation = 'deleteMatchingPrivateFile'; path = $entry.path; bytesBase64 = $record.bytesBase64; expectedIdentity = $record.identity } | ConvertTo-Json -Depth 4 -Compress
                $deleted = & $Runner @{ id = ('packageResumeRetire' + $entry.key); executable = $powershell; arguments = @('-NoLogo','-NoProfile','-NonInteractive','-File',$helper); input = $wire; capture = $true; timeoutMs = 30000 }
                $ack = $deleted.output | ConvertFrom-Json
                if ($deleted.exitCode -ne 0 -or $ack.version -ne 1 -or $ack.ok -ne $true -or $ack.deleted -ne $true) { throw 'WINDOWS_PACKAGE_RESTART_RETIRE_UNCERTAIN' }
            }
            $result.operationRetained = $false; $result.completed += $journal.value.operation; $result.componentSucceeded = $true
            return [pscustomobject]$result
        }
        # WinGet is an installation mechanism, not a required application tool.
        # Preserve supported installed tools and independently repair eligible VS.
        $observations = @{}; $needsWinGet = $false
        foreach ($package in $result.packages) {
            $before = & $Probe $package.id $Runner
            $observations[$package.id] = $before
            # Never upgrade/repair/adopt unrelated Multipass. Fresh MSI writes
            # its daemon configuration, so even orphan data blocks installation.
            if ($package.id -eq 'multipass' -and $before.status -ne 'present' -and $before.status -ne 'missing') { throw 'WINDOWS_MULTIPASS_EXISTING_INSTALLATION_UNSUPPORTED' }
            if ($package.id -eq 'opensshClient' -and $before.status -notin @('present','missing')) { throw 'WINDOWS_OPENSSH_CLIENT_UNSUPPORTED' }
            if ($before.status -ne 'present' -and $package.id -ne 'opensshClient' -and -not ($package.id -eq 'buildTools' -and $before.modifyPath)) { $needsWinGet = $true }
        }
        # The tagged MSI calls DISM to enable Hyper-V. Require it already fully
        # enabled/running, including a fresh pre-install observation below.
        if ((& $Probe 'hyperVHost' $Runner).status -cne 'present') { throw 'WINDOWS_MULTIPASS_HYPERV_HOST_REQUIRED' }
        if ($needsWinGet) {
            $winget = & $Probe 'winget' $Runner
            if ($winget.status -ne 'present') {
                # Fixed official current-user bootstrap. No repository trust changes,
                # execution-policy bypass, TLS override, or elevation of this script.
                $bootstrap = @'
$ErrorActionPreference = 'Stop'
$repository = Get-PSRepository -Name PSGallery
if ($repository.SourceLocation.TrimEnd('/') -ne 'https://www.powershellgallery.com/api/v2') { throw 'WINDOWS_PSGALLERY_SOURCE_DENIED' }
Install-PackageProvider -Name NuGet -Scope CurrentUser -Force | Out-Null
Install-Module -Name Microsoft.WinGet.Client -RequiredVersion 1.29.380 -Scope CurrentUser -Repository PSGallery -Force | Out-Null
Import-Module Microsoft.WinGet.Client -RequiredVersion 1.29.380
Repair-WinGetPackageManager -Latest
'@
                $request = @{ id = 'wingetBootstrap'; executable = $powershell; arguments = @('-NoLogo','-NoProfile','-NonInteractive','-Command',$bootstrap); timeoutMs = 600000 }
                if (-not (& $perform 'wingetBootstrap' $request { (& $Probe 'winget' $Runner).status -eq 'present' })) { return [pscustomobject]$result }
                $winget = & $Probe 'winget' $Runner
            }
            $source = & $Runner @{ id = 'wingetSource'; executable = $winget.path; arguments = @('source','export','winget','--disable-interactivity'); capture = $true; timeoutMs = 30000 }
            $official = $source.output | ConvertFrom-Json
            if ($source.exitCode -ne 0 -or $official.Name -ne 'winget' -or $official.Arg -ne 'https://cdn.winget.microsoft.com/cache' -or $official.Identifier -ne 'Microsoft.Winget.Source_8wekyb3d8bbwe' -or $official.Type -ne 'Microsoft.PreIndexed.Package') { throw 'WINDOWS_WINGET_SOURCE_DENIED' }
        }
        foreach ($package in $result.packages) {
            $before = $observations[$package.id]
            if ($before.status -ne 'present') {
                if ($package.id -eq 'opensshClient') {
                    $request = @{ id = 'installopensshClient'; executable = (Join-Path $SystemRoot 'System32\dism.exe'); arguments = @('/Online','/Add-Capability','/CapabilityName:OpenSSH.Client~~~~0.0.1.0','/NoRestart','/Quiet'); timeoutMs = 1800000 }
                } elseif ($package.id -eq 'buildTools' -and $before.modifyPath) {
                    $request = @{ id = 'visualStudioModify'; executable = (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\setup.exe'); arguments = @('modify','--installPath',$before.modifyPath,'--add','Microsoft.VisualStudio.Workload.VCTools','--add','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','--add','Microsoft.VisualStudio.Component.Windows11SDK.26100','--quiet','--norestart'); timeoutMs = 1800000 }
                } else {
                    $arguments = @('install','--id',$package.package,'--exact','--source','winget','--scope',$package.scope,'--architecture','x64','--silent','--accept-source-agreements','--accept-package-agreements','--disable-interactivity')
                    # Official manifests default to PATH changes. Bind absolute
                    # executables instead; neither Git nor Python edits PATH.
                    if ($package.id -eq 'git') { $arguments += @('--override','/CURRENTUSER /SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /o:PathOption=BashOnly') }
                    if ($package.id -eq 'python') { $arguments += @('--override','/quiet /norestart InstallAllUsers=0 PrependPath=0 AppendPath=0 Include_launcher=0 InstallLauncherAllUsers=0') }
                    # Ollama's official per-user installer appends its own HKCU
                    # directory; this component never writes/reorders PATH.
                    if ($package.id -eq 'buildTools') { $arguments += @('--override','--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100') }
                    if ($package.id -eq 'multipass') {
                        if ((& $Probe 'multipass' $Runner).status -cne 'missing' -or (& $Probe 'hyperVHost' $Runner).status -cne 'present') { throw 'WINDOWS_MULTIPASS_FRESH_INSTALL_ADMISSION_DENIED' }
                        # Only pinned absent-package installation. No migration,
                        # driver set, VM stop/delete or existing daemon rewrite.
                        $arguments += @('--version','1.16.4','--no-upgrade','--override','/qn /norestart DRIVER=hyperv REMOVE_DATA=no')
                    }
                    $request = @{ id = ('install' + $package.id); executable = $winget.path; arguments = $arguments; timeoutMs = 1800000 }
                }
                $target = $package.id
                if (-not (& $perform ('install' + $target) $request { (& $Probe $target $Runner).status -eq 'present' })) { return [pscustomobject]$result }
            }
            $verified = & $Probe $package.id $Runner
            if ($verified.status -cne 'present') { throw 'WINDOWS_PACKAGE_FINAL_VERIFICATION_FAILED' }
            $result.dependencies += $verified
        }
        if ((& $Probe 'ollamaService' $Runner).status -ne 'present') {
            $request = @{ id = 'ollamaStart'; executable = (Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama app.exe'); arguments = @(); timeoutMs = 30000 }
            $verify = { for ($attempt = 0; $attempt -lt 20; $attempt++) { if ((& $Probe 'ollamaService' $Runner).status -eq 'present') { return $true }; & $Pause }; return $false }
            if (-not (& $perform 'ollamaStart' $request $verify)) { return [pscustomobject]$result }
        }
        $result.dependencies += (& $Probe 'ollamaService' $Runner)
        $result.componentSucceeded = $true
    } catch {
        $code = [string]$_.Exception.Message
        if ($code -notmatch '^WINDOWS_[A-Z0-9_]+$') { $code = 'WINDOWS_PACKAGE_FAILED' }
        $result.blockers += $code
    }
    return [pscustomobject]$result
}

if ($MyInvocation.InvocationName -ne '.') {
    if (($Plan -and $Execute) -or ($Resume -and (-not $Execute -or $Plan))) { throw 'Use -Execute -Resume to retire an acknowledged restart operation.' }
    try {
        $output = Invoke-OwaspAiGoatWindowsPackages -ExecuteMode ([bool]$Execute) -ResumeRestart ([bool]$Resume)
        $output | ConvertTo-Json -Depth 8
        if ($Execute -and -not $output.componentSucceeded) { exit 1 }
    }
    catch { [pscustomobject]@{ schemaVersion = 1; component = 'windows-native-packages'; installationBlocked = $true; nativeQualified = $false; code = 'WINDOWS_PACKAGE_FAILED' } | ConvertTo-Json; exit 1 }
}
