#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
function Exact-Keys($value, [string[]]$expected) {
    if ($null -eq $value) { throw 'denied' }
    $actual = @($value.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -cne (($expected | Sort-Object) -join ',')) { throw 'denied' }
}
try {
    $buffer = New-Object System.Text.StringBuilder
    while (($character = [Console]::In.Read()) -ne -1) {
        if ($buffer.Length -ge 4096) { throw 'denied' }
        [void]$buffer.Append([char]$character)
    }
    $request = ConvertFrom-Json -InputObject $buffer.ToString()
    if ($request.version -isnot [int] -or $request.version -ne 1 -or
        $request.operation -isnot [string] -or $request.pid -isnot [int] -or $request.pid -le 0) { throw 'denied' }
    switch -CaseSensitive ($request.operation) {
        'capture' { Exact-Keys $request @('version','operation','pid') }
        'absence' {
            Exact-Keys $request @('version','operation','pid','binding','recordedPids')
            Exact-Keys $request.binding @('hostSha256','bootFileTime','currentSid')
            if ($request.binding.hostSha256 -isnot [string] -or $request.binding.hostSha256 -cnotmatch '^[a-f0-9]{64}$' -or
                $request.binding.bootFileTime -isnot [string] -or $request.binding.bootFileTime -cnotmatch '^[1-9][0-9]{0,19}$' -or
                $request.binding.currentSid -isnot [string] -or $request.binding.currentSid.Length -gt 184 -or
                $request.recordedPids -isnot [Array] -or $request.recordedPids.Count -lt 1 -or $request.recordedPids.Count -gt 32) { throw 'denied' }
            foreach ($recordedPid in $request.recordedPids) {
                if ($recordedPid -isnot [int] -or $recordedPid -le 0) { throw 'denied' }
            }
        }
        default { throw 'denied' }
    }
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-process-identity.cs') -ReferencedAssemblies 'System.dll','System.Core.dll','System.Management.dll','System.Security.dll'
    if ($request.operation -ceq 'capture') { $data = [DvaiaWindowsProcessIdentity]::Capture([uint32]$request.pid) }
    else {
        $data = [DvaiaWindowsProcessIdentity]::ObserveAbsence([uint32]$request.pid,
            $request.binding.hostSha256, $request.binding.bootFileTime, $request.binding.currentSid,
            [uint32[]]$request.recordedPids)
    }
    $response = @{version=1; ok=$true; operation=$request.operation; data=$data}
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $response -Compress -Depth 6))
} catch {
    # A failure is neither absence nor authority. Do not disclose diagnostics.
    [Console]::Out.WriteLine('{"version":1,"ok":false,"operation":"capture","data":null}')
    exit 1
}
