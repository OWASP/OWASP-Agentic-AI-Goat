#Requires -Version 5.1
<# Read-only Hyper-V host admission. No feature enablement, reboot or VM work.
   SKU constants: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo
   Pro Education N constant: https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
   ProductType/OperatingSystemSKU: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
   Feature states: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-optionalfeature
   Hypervisor evidence/capability suppression: https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements
   HypervisorPresent: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem
   CPU Architecture/AddressWidth: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor
   Hyper-V Administrators SID/access: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
   Hyper-V Get-VM module: https://learn.microsoft.com/en-us/powershell/module/hyper-v/get-vm #>
[CmdletBinding()]
param()

function Get-DvaiaWindowsHostObservation {
    # Select only public admission facts; no machine names, IDs or serial numbers.
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property OperatingSystemSKU,ProductType,Version,BuildNumber -OperationTimeoutSec 10 -ErrorAction Stop
    $system = Get-CimInstance -ClassName Win32_ComputerSystem -Property HypervisorPresent -OperationTimeoutSec 10 -ErrorAction Stop
    $processors = @(Get-CimInstance -ClassName Win32_Processor -Property Architecture,AddressWidth,VirtualizationFirmwareEnabled,SecondLevelAddressTranslationExtensions,VMMonitorModeExtensions -OperationTimeoutSec 10 -ErrorAction Stop)
    $features = @(Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name='Microsoft-Hyper-V' OR Name='Microsoft-Hyper-V-Hypervisor'" -Property Name,InstallState -OperationTimeoutSec 10 -ErrorAction Stop)
    # Conservative servicing gate. An inaccessible registry probe throws and is
    # unknown, never silently interpreted as a clear reboot state.
    $pending = (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop) -or
        (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop)
    # Check the enabled current token, not a localized group name or a roster.
    # Setup never adds membership or requests an elevated application token.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $hypervAdministrator = $principal.IsInRole((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-578')))
    } finally { $identity.Dispose() }
    # Discover only the installed system module; import its absolute manifest so
    # a user PSModulePath entry cannot satisfy the required native observer API.
    # No VM command is invoked and no VM needs to exist for this check.
    $systemModuleBase = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules\Hyper-V'))
    $modules = @(Get-Module -ListAvailable -Name Hyper-V -ErrorAction Stop | Where-Object {
        $base = [IO.Path]::GetFullPath($_.ModuleBase)
        $base.Equals($systemModuleBase, [StringComparison]::OrdinalIgnoreCase) -or $base.StartsWith($systemModuleBase + '\', [StringComparison]::OrdinalIgnoreCase)
    })
    $hypervPowerShellAvailable = $false
    if ($modules.Count -gt 0) {
        $module = $modules | Sort-Object Version -Descending | Select-Object -First 1
        Import-Module -Name $module.Path -ErrorAction Stop
        $command = Get-Command -Name 'Hyper-V\Get-VM' -ErrorAction Stop
        $commandBase = [IO.Path]::GetFullPath($command.Module.ModuleBase)
        $hypervPowerShellAvailable = $command.CommandType -eq 'Cmdlet' -and $command.ModuleName -ceq 'Hyper-V' -and
            ($commandBase.Equals($systemModuleBase, [StringComparison]::OrdinalIgnoreCase) -or $commandBase.StartsWith($systemModuleBase + '\', [StringComparison]::OrdinalIgnoreCase))
    }
    return @{ os = $os; processors = $processors; features = $features; hypervisorPresent = $system.HypervisorPresent; rebootPending = [bool]$pending;
        hypervAdministrator = [bool]$hypervAdministrator; hypervPowerShellAvailable = [bool]$hypervPowerShellAvailable }
}

function Test-DvaiaWindowsHostObservation {
    param($Observation)
    # Explicit approved client families, including N, evaluation and LTSC:
    # Enterprise 4/27/70/72/84, Enterprise S 125/126/129/130;
    # Professional 48/49, Workstation 161/162, Pro Education 164/165;
    # Education 121/122. Unknown/IoT/Server/Home products are not admitted.
    $allowedSkus = @(4,27,48,49,70,72,84,121,122,125,126,129,130,161,162,164,165)
    $result = [ordered]@{ schemaVersion = 1; component = 'windows-hyperv-host-preflight'; nonMutating = $true; hostSupported = $false; minimumBuild = 19045; allowedSkus = $allowedSkus; capabilityEvidence = 'unknown'; blockers = @() }
    $blockers = New-Object 'System.Collections.Generic.List[object]'
    $add = { param($Code,$Remedy) $blockers.Add([pscustomobject]@{ code = $Code; remedy = $Remedy }) }
    try {
        if ($Observation.hypervAdministrator -isnot [bool] -or $Observation.hypervPowerShellAvailable -isnot [bool]) { throw 'unknown' }
        if (-not $Observation.hypervAdministrator) { & $add 'WINDOWS_HOST_HYPERV_PERMISSION_REQUIRED' 'Ask a host administrator to grant this user Hyper-V Administrators membership, then sign out and sign in before rerunning setup from a normal terminal. Setup does not change groups or elevate the application.' }
        if (-not $Observation.hypervPowerShellAvailable) { & $add 'WINDOWS_HOST_HYPERV_POWERSHELL_REQUIRED' 'Ask a host administrator to enable Hyper-V Module for Windows PowerShell through Windows Features, complete any required restart, then rerun setup. Setup does not enable Windows features.' }
        $os = $Observation.os
        if ($null -eq $os -or [string]$os.ProductType -cnotmatch '^\d+$' -or [string]$os.OperatingSystemSKU -cnotmatch '^\d+$') { throw 'unknown' }
        if ([int]$os.ProductType -ne 1) { & $add 'WINDOWS_HOST_CLIENT_REQUIRED' 'Use an approved Windows Pro, Education or Enterprise client; Windows Server is unsupported.' }
        if ($allowedSkus -notcontains [int]$os.OperatingSystemSKU) { & $add 'WINDOWS_HOST_EDITION_UNSUPPORTED' 'Use Windows Pro, Education or Enterprise with Hyper-V; Home and unknown editions are unsupported.' }
        # Existing Ollama package admission requires build19045 or newer. This
        # is an application minimum, not a claim that every build has OS support.
        if ([string]$os.Version -cnotmatch '^10\.0\.\d+(?:\.\d+)?$' -or [string]$os.BuildNumber -cnotmatch '^\d+$' -or [int]$os.BuildNumber -lt 19045) { & $add 'WINDOWS_HOST_BUILD_UNSUPPORTED' 'Use Windows 10 build19045 or newer, or Windows 11, with current security updates.' }
        $processors = @($Observation.processors)
        if ($processors.Count -eq 0) { throw 'unknown' }
        foreach ($cpu in $processors) {
            if ($null -eq $cpu.Architecture -or $null -eq $cpu.AddressWidth) { throw 'unknown' }
            if ([int]$cpu.Architecture -ne 9 -or [int]$cpu.AddressWidth -ne 64) { & $add 'WINDOWS_HOST_X64_REQUIRED' 'Use an x64 Windows host; ARM64 and 32-bit hosts are unsupported.'; break }
        }
        foreach ($name in @('Microsoft-Hyper-V','Microsoft-Hyper-V-Hypervisor')) {
            $feature = @($Observation.features | Where-Object { $_.Name -ceq $name })
            if ($feature.Count -ne 1 -or $null -eq $feature[0].InstallState -or [int]$feature[0].InstallState -eq 4) { throw 'unknown' }
            if ([int]$feature[0].InstallState -ne 1) { & $add 'WINDOWS_HOST_HYPERV_DISABLED' 'Enable the Hyper-V platform through Windows Features, then restart explicitly before setup.' }
        }
        if ($Observation.rebootPending -isnot [bool] -or $Observation.hypervisorPresent -isnot [bool]) { throw 'unknown' }
        if ($Observation.rebootPending) { & $add 'WINDOWS_HOST_RESTART_PENDING' 'Finish pending Windows servicing and restart explicitly, then rerun the preflight.' }
        if ($Observation.hypervisorPresent) {
            # Microsoft documents that running Hyper-V suppresses individual
            # capability reporting. Do not falsely deny null/false CPU flags.
            $result.capabilityEvidence = 'running-hypervisor'
        } else {
            $result.capabilityEvidence = 'processor-flags'
            foreach ($cpu in $processors) {
                foreach ($key in @('VirtualizationFirmwareEnabled','SecondLevelAddressTranslationExtensions','VMMonitorModeExtensions')) {
                    if ($cpu.$key -isnot [bool]) { throw 'unknown' }
                    if (-not $cpu.$key) { & $add 'WINDOWS_HOST_VIRTUALIZATION_UNAVAILABLE' 'Use hardware with SLAT and VM monitor extensions and enable virtualization in firmware.'; break }
                }
            }
            & $add 'WINDOWS_HOST_HYPERV_NOT_RUNNING' 'Start the Windows Hyper-V hypervisor by completing feature and firmware configuration, then restart explicitly.'
        }
    } catch { & $add 'WINDOWS_HOST_OBSERVATION_UNKNOWN' 'Obtain readable Windows CIM/servicing observations and rerun the preflight; unknown host state is unsupported.' }
    $result.blockers = @($blockers | Sort-Object code -Unique)
    $result.hostSupported = ($result.blockers.Count -eq 0)
    return [pscustomobject]$result
}

function Invoke-DvaiaWindowsHostPreflight {
    param([scriptblock]$Observe = ${function:Get-DvaiaWindowsHostObservation})
    try { $observed = & $Observe } catch { $observed = $null }
    return Test-DvaiaWindowsHostObservation $observed
}

if ($MyInvocation.InvocationName -ne '.') {
    $result = Invoke-DvaiaWindowsHostPreflight
    $result | ConvertTo-Json -Depth 5
    if (-not $result.hostSupported) { exit 1 }
}
