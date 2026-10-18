# Native Windows 5.1 private handle operations. This helper grants no maintenance,
# recovery or publication authority. The invoking user's processes, elevated administrators
# and SYSTEM are trusted; an ACL cannot isolate secrets from the same identity.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false, $true)
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    # Do not ReadToEnd: requests and responses have a fixed wire bound.
    $limit = 1500000
    $builder = New-Object System.Text.StringBuilder
    $buffer = New-Object char[] 4096
    while (($count = [Console]::In.Read($buffer, 0, [Math]::Min($buffer.Length, $limit + 1 - $builder.Length))) -gt 0) {
        [void]$builder.Append($buffer, 0, $count)
        if ($builder.Length -gt $limit) { throw 'Denied' }
    }
    $wire = $builder.ToString()
    if ([System.Text.Encoding]::UTF8.GetByteCount($wire) -gt $limit) { throw 'Denied' }
    $request = ConvertFrom-Json -InputObject $wire
    $keys = @($request.PSObject.Properties.Name | Sort-Object)
    $expected = @('operation', 'path', 'version')
    if ($request.operation -eq 'createPrivateFile') { $expected = @('bytesBase64', 'operation', 'path', 'version') }
    if ($request.operation -ceq 'deleteMatchingPrivateFile') { $expected = @('bytesBase64', 'expectedIdentity', 'operation', 'path', 'version') }
    if (($keys -join ',') -ne ($expected -join ',') -or $request.version -ne 1 -or $request.path -isnot [string] -or $request.operation -isnot [string]) { throw 'Denied' }
    if ($request.operation -cnotin @('ensurePrivateDirectory', 'inspectPrivateDirectory', 'inspectWorkspaceDirectory', 'readPrivateFile', 'readPrivateWorkspaceFile', 'createPrivateFile', 'deleteMatchingPrivateFile', 'readAndFlushPrivateFile', 'readAndFlushPrivateWorkspaceFile')) { throw 'Denied' }
    if ($request.operation -eq 'createPrivateFile' -and $request.bytesBase64 -isnot [string]) { throw 'Denied' }
    if ($request.operation -ceq 'deleteMatchingPrivateFile') {
        $identityKeys = @($request.expectedIdentity.PSObject.Properties.Name | Sort-Object)
        if (($identityKeys -join ',') -cne 'fileId,volumeSerial' -or
            ($request.expectedIdentity.volumeSerial -isnot [int] -and $request.expectedIdentity.volumeSerial -isnot [long]) -or
            $request.expectedIdentity.volumeSerial -lt 0 -or $request.expectedIdentity.volumeSerial -gt [uint32]::MaxValue -or
            $request.expectedIdentity.fileId -isnot [string] -or $request.expectedIdentity.fileId -cnotmatch '^[a-f0-9]{16}$' -or
            $request.bytesBase64 -isnot [string] -or $request.bytesBase64.Length -gt 5464) { throw 'Denied' }
    }
    # No source or request content is expanded into a PowerShell command.
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-private-state.cs') -ErrorAction Stop
    if ($request.operation -ceq 'deleteMatchingPrivateFile') {
        $response = [Dvaia.WindowsPrivateState]::Invoke($request.operation, $request.path, $request.bytesBase64,
            [uint32]$request.expectedIdentity.volumeSerial, $request.expectedIdentity.fileId)
    } else { $response = [Dvaia.WindowsPrivateState]::Invoke($request.operation, $request.path, $request.bytesBase64) }
    $json = ConvertTo-Json -InputObject $response -Depth 4 -Compress
    if ([System.Text.Encoding]::UTF8.GetByteCount($json) -gt $limit) { throw 'Denied' }
    [Console]::Out.Write($json)
} catch {
    # Neither exceptions nor PowerShell error records may expose request bytes.
    [Console]::Out.Write('{"version":1,"ok":false,"code":"WINDOWS_PRIVATE_STATE_DENIED"}')
    exit 1
}
