#Requires -Version 5.1
<# Read-only local VM observation. VMId is an observed Hyper-V identifier, not
   proof of VM disk immutability or authority to start, stop or delete a VM.
   Get-VM -Name supports wildcards; the owned name grammar forbids them:
   https://learn.microsoft.com/en-us/powershell/module/hyper-v/get-vm
   No ComputerName/CimSession/Credential is accepted; the default host is local. #>
[CmdletBinding()]
param()

function Assert-OwaspAiGoatOwnedHyperVName {
    param($Name)
    if ($Name -isnot [string] -or $Name.Length -gt 57 -or $Name -cmatch '[\r\n]' -or $Name -cnotmatch '^owasp-ai-goat-lab-[a-z0-9](?:[a-z0-9-]{0,45}[a-z0-9])?$') { throw 'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED' }
}

function Get-OwaspAiGoatOwnedHyperVObservation {
    param([string]$Name, [scriptblock]$Probe = { param($ExactName) Hyper-V\Get-VM -Name $ExactName -ErrorAction Stop })
    Assert-OwaspAiGoatOwnedHyperVName $Name
    $first = $null
    # Reject identity/state changes during this bounded observation. The caller
    # must still compare VMId with retained ownership before any later restart.
    foreach ($index in @(1,2)) {
        $rows = @(& $Probe $Name)
        if ($rows.Count -ne 1) { throw 'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED' }
        $vm = $rows[0]
        if ($null -eq $vm -or $vm.Name -isnot [string] -or $vm.Name -cne $Name) { throw 'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED' }
        $id = [Guid]::Empty
        if (-not [Guid]::TryParseExact([string]$vm.Id, 'D', [ref]$id) -or $id -eq [Guid]::Empty) { throw 'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED' }
        $state = [string]$vm.State
        if (@('Running','Off','Saved') -cnotcontains $state) { throw 'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED' }
        $current = [pscustomobject][ordered]@{ version = 1; operation = 'observeOwnedHyperVVm'; name = $Name; vmId = $id.ToString('D').ToLowerInvariant(); state = $state }
        if ($first -and ($current.vmId -cne $first.vmId -or $current.state -cne $first.state)) { throw 'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED' }
        $first = $current
    }
    return $first
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        # Read a bounded request, not unbounded ReadToEnd or interpreted code.
        $builder = New-Object Text.StringBuilder
        while (($character = [Console]::In.Read()) -ne -1) {
            if ($builder.Length -ge 1024) { throw 'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED' }
            [void]$builder.Append([char]$character)
        }
        $request = $builder.ToString() | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $request -or $request -is [Array] -or (@($request.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'name,operation,version' -or ($request.version -isnot [int] -and $request.version -isnot [long]) -or $request.version -ne 1 -or $request.operation -cne 'observeOwnedHyperVVm') { throw 'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED' }
        Assert-OwaspAiGoatOwnedHyperVName $request.name
        Get-OwaspAiGoatOwnedHyperVObservation -Name $request.name | ConvertTo-Json -Depth 3 -Compress
    } catch {
        [Console]::Out.WriteLine('{"version":1,"ok":false,"code":"WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED"}')
        exit 1
    }
}
