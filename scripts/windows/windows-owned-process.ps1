#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$job = $null
function Exact-Keys($value, [string[]]$expected) {
    if ($null -eq $value) { throw 'denied' }
    $actual = @($value.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -cne (($expected | Sort-Object) -join ',')) { throw 'denied' }
}
function Read-BoundedLine {
    $buffer = New-Object System.Text.StringBuilder
    while ($true) {
        $character = [Console]::In.Read()
        if ($character -eq -1) {
            if ($buffer.Length -ne 0) { throw 'denied' }
            return $null
        }
        if ($character -eq 10) { return $buffer.ToString() }
        if ($buffer.Length -ge 4096) { throw 'denied' }
        [void]$buffer.Append([char]$character)
    }
}
try {
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-owned-process.cs')
    $job = New-Object DvaiaOwnedProcessJob
    [Console]::Out.WriteLine('{"version":1,"event":"ready"}')
    [Console]::Out.Flush()
    while ($null -ne ($line = Read-BoundedLine)) {
        if ($line.Length -gt 4096) { throw 'denied' }
        $request = ConvertFrom-Json -InputObject $line
        Exact-Keys $request @('version','id','operation','data')
        if ($request.version -ne 1 -or $request.id -isnot [string] -or $request.id -cnotmatch '^[a-f0-9]{32}$') { throw 'denied' }
        $data = $null
        switch -CaseSensitive ($request.operation) {
            'pin' {
                Exact-Keys $request.data @('pid')
                if ($request.data.pid -isnot [int] -or $request.data.pid -le 1) { throw 'denied' }
                $data = @{pid=$request.data.pid; creationFileTime=$job.Pin([uint32]$request.data.pid)}
            }
            'assign' {
                Exact-Keys $request.data @('creationFileTime')
                if ($request.data.creationFileTime -isnot [string] -or $request.data.creationFileTime -cnotmatch '^[1-9][0-9]{0,19}$') { throw 'denied' }
                $job.Assign($request.data.creationFileTime)
                $data = @{assigned=$true}
            }
            'members' { Exact-Keys $request.data @(); $members=@($job.Members()); $data=@{pids=$members; activeCount=$members.Count} }
            'guardianOnly' { Exact-Keys $request.data @(); $data=@{guardianOnly=$job.GuardianOnly()} }
            'terminate' { Exact-Keys $request.data @(); $job.Terminate(); $data=@{terminated=$true} }
            default { throw 'denied' }
        }
        $response=@{version=1; id=$request.id; operation=$request.operation; ok=$true; data=$data}
        [Console]::Out.WriteLine((ConvertTo-Json -InputObject $response -Compress -Depth 5))
        [Console]::Out.Flush()
    }
} catch {
    # Do not disclose protocol/native diagnostics or process/environment data.
    [Console]::Out.WriteLine('{"version":1,"event":"denied"}')
    [Console]::Out.Flush()
    exit 1
} finally { if ($null -ne $job) { $job.Dispose() } }
