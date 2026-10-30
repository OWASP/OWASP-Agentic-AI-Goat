# Controlled/native foundation, not application integration or OS qualification.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false, $true)
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $limit = 3000000
    $builder = New-Object System.Text.StringBuilder
    $buffer = New-Object char[] 4096
    while (($count = [Console]::In.Read($buffer, 0, [Math]::Min($buffer.Length, $limit + 1 - $builder.Length))) -gt 0) {
        [void]$builder.Append($buffer, 0, $count)
        if ($builder.Length -gt $limit) { throw 'Denied' }
    }
    $wire = $builder.ToString()
    if ([System.Text.Encoding]::UTF8.GetByteCount($wire) -gt $limit) { throw 'Denied' }
    $request = ConvertFrom-Json -InputObject $wire
    $expected = 'intentPath,operation,operationId,targetPath,version'
    if ($request.operation -eq 'preparePrivatePublication') { $expected = 'intentPath,operation,operationId,originalBytesBase64,resultBytesBase64,targetPath,version' }
    if ((@($request.PSObject.Properties.Name | Sort-Object) -join ',') -ne $expected -or $request.version -ne 1 -or $request.operation -isnot [string] -or $request.targetPath -isnot [string] -or $request.intentPath -isnot [string] -or $request.operationId -isnot [string]) { throw 'Denied' }
    if ($request.operation -eq 'preparePrivatePublication' -and ($request.resultBytesBase64 -isnot [string] -or ($null -ne $request.originalBytesBase64 -and $request.originalBytesBase64 -isnot [string]))) { throw 'Denied' }
    Add-Type -Path (Join-Path $PSScriptRoot 'windows-private-publication.cs') -ReferencedAssemblies 'System.dll', 'System.Core.dll', 'System.Web.Extensions.dll' -ErrorAction Stop
    $response = [OwaspAiGoat.WindowsPrivatePublication]::Invoke($request.operation, $request.targetPath, $request.intentPath, $request.operationId, $request.originalBytesBase64, $request.resultBytesBase64)
    $json = ConvertTo-Json -InputObject $response -Depth 4 -Compress
    if ([System.Text.Encoding]::UTF8.GetByteCount($json) -gt 4096) { throw 'Denied' }
    [Console]::Out.Write($json)
} catch {
    [Console]::Out.Write('{"version":1,"ok":false,"code":"WINDOWS_PRIVATE_PUBLICATION_DENIED"}')
    exit 1
}
