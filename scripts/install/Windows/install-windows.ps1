#Requires -Version 5.1
<# Canonical native setup handoff after the controlled composition cohort.
   Host/prerequisite/private-state gates still fail before unsupported work. #>
[CmdletBinding()]
param([switch]$Plan, [switch]$NoInstall, [switch]$Upgrade, [switch]$Repair)

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    . (Join-Path $PSScriptRoot 'wrapper-handoff.ps1')
    $handoff = Invoke-OwaspAiGoatWindowsWrapperHandoff -Kind setup -PlanMode ([bool]$Plan) -NoInstall ([bool]$NoInstall) -Upgrade ([bool]$Upgrade) -Repair ([bool]$Repair) -CompositionReady $true
    $handoff | ConvertTo-Json -Depth 6
    if ($Plan) {
        Write-Output 'Plan performed no package, service, configuration, or database changes and did not require Node.js.'
        return
    }
    if ($handoff.blockers -contains 'WINDOWS_HOST_PREFLIGHT_DENIED') { throw 'WINDOWS_HOST_PREFLIGHT_DENIED: Use the reported approved Windows Hyper-V host requirements.' }
    if ($handoff.blockers -contains 'WINDOWS_FRESH_ENVIRONMENT_EXISTS') { throw 'WINDOWS_FRESH_ENVIRONMENT_EXISTS: Fresh setup preserves an existing root .env; use additive upgrade or repair.' }
    if ($handoff.blockers -contains 'WINDOWS_WRAPPER_COMPOSITION_PENDING') { throw 'WINDOWS_WRAPPER_COMPOSITION_PENDING: Required setup integration is unavailable. See docs/install/windows.md.' }
    if (-not $handoff.componentSucceeded) { exit 1 }
}
