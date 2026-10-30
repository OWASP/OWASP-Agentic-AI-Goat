#Requires -Version 5.1
<# Independent prerequisite component. Default/-Plan is read-only; -Execute
   prepares Node/npm only; independent packages.ps1 handles other native packages. Global installation remains
   blocked. Docker/backend and protected sandbox admission are separate work. #>
[CmdletBinding()]
param([switch]$Plan, [switch]$Execute)

. (Join-Path $PSScriptRoot 'dependency-plan.ps1')

function ConvertTo-OwaspAiGoatProcessArgument {
    param([string]$Argument)
    # Win32 CommandLineToArgvW quoting, including spaces and trailing slashes.
    $escaped = [regex]::Replace($Argument, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-OwaspAiGoatPrerequisiteProcess {
    param($Request)
    $arguments = @($Request.arguments | ForEach-Object { ConvertTo-OwaspAiGoatProcessArgument $_ }) -join ' '
    if ($Request.elevate) { throw 'WINDOWS_PREREQUISITE_ELEVATION_DENIED' }
    if (-not ('OwaspAiGoat.PrerequisiteOutput' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
namespace OwaspAiGoat {
  public static class PrerequisiteOutput {
    public static async Task<string> Read(StreamReader reader, bool capture) {
      var buffer = new char[4096]; var text = new StringBuilder(); bool exceeded = false;
      int count;
      while ((count = await reader.ReadAsync(buffer, 0, buffer.Length)) > 0) {
        if (!capture) continue;
        if (text.Length + count > 65536) { exceeded = true; continue; }
        text.Append(buffer, 0, count);
      }
      if (exceeded) throw new InvalidOperationException("WINDOWS_PREREQUISITE_OUTPUT_LIMIT");
      return text.ToString();
    }
  }
}
'@
    }
    $child = New-Object System.Diagnostics.Process
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Request.executable
    $info.Arguments = $arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    if ($Request.environment) { foreach ($key in $Request.environment.Keys) { $info.EnvironmentVariables[$key] = $Request.environment[$key] } }
    $child.StartInfo = $info
    try {
        [void]$child.Start()
        $stdout = [OwaspAiGoat.PrerequisiteOutput]::Read($child.StandardOutput, [bool]$Request.capture)
        $stderr = [OwaspAiGoat.PrerequisiteOutput]::Read($child.StandardError, [bool]$Request.capture)
        if ($Request.input) { $child.StandardInput.Write($Request.input) }
        $child.StandardInput.Close()
        if (-not $child.WaitForExit($Request.timeoutMs)) {
            # Do not kill an installer halfway through machine package work.
            throw 'WINDOWS_PREREQUISITE_TIMEOUT'
        }
        # Descendants can retain pipes after the parent exits; drain is bounded too.
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 10000)) { throw 'WINDOWS_PREREQUISITE_DRAIN_TIMEOUT' }
        $output = $stdout.GetAwaiter().GetResult() + "`n" + $stderr.GetAwaiter().GetResult()
        if ($output.Length -gt 65536) { throw 'WINDOWS_PREREQUISITE_OUTPUT_LIMIT' }
        return @{ exitCode = $child.ExitCode; output = $output }
    } finally { $child.Dispose() }
}

function Receive-OwaspAiGoatOfficialDownload {
    param([string]$Uri, [string]$Destination)
    if ($Uri -notmatch '^https://nodejs\.org/dist/v\d+\.\d+\.\d+/(?:SHASUMS256\.txt|node-v\d+\.\d+\.\d+-win-x64\.zip)$') { throw 'WINDOWS_PREREQUISITE_DOWNLOAD_DENIED' }
    # Framework HttpClient retains OS certificate verification. No TLS override.
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(10)
    $cancel = New-Object System.Threading.CancellationTokenSource
    $cancel.CancelAfter(600000)
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    try {
        $response = $client.GetAsync($Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancel.Token).GetAwaiter().GetResult()
        try {
            [void]$response.EnsureSuccessStatusCode()
            if ($response.Content.Headers.ContentLength -gt 200MB) { throw 'WINDOWS_PREREQUISITE_DOWNLOAD_LIMIT' }
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $file = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $buffer = New-Object byte[] 65536
                [long]$total = 0
                while ($true) {
                    $remaining = 600000 - [int]$deadline.ElapsedMilliseconds
                    if ($remaining -le 0) { $cancel.Cancel(); throw 'WINDOWS_PREREQUISITE_DOWNLOAD_TIMEOUT' }
                    $reading = $stream.ReadAsync($buffer, 0, $buffer.Length, $cancel.Token)
                    if (-not $reading.Wait($remaining)) { $cancel.Cancel(); throw 'WINDOWS_PREREQUISITE_DOWNLOAD_TIMEOUT' }
                    $count = $reading.GetAwaiter().GetResult()
                    if ($count -eq 0) { break }
                    $total += $count
                    if ($total -gt 200MB) { $cancel.Cancel(); throw 'WINDOWS_PREREQUISITE_DOWNLOAD_LIMIT' }
                    $file.Write($buffer, 0, $count)
                }
                $file.Flush()
            } finally { $cancel.Cancel(); $file.Dispose(); $stream.Dispose() }
        } finally { $response.Dispose() }
    } finally { $cancel.Cancel(); $cancel.Dispose(); $client.Dispose(); $handler.Dispose() }
}

function Expand-OwaspAiGoatNodeArchive {
    param([string]$Archive, [string]$Destination, [string]$ExpectedRoot)
    if ($ExpectedRoot -notmatch '^node-v\d+\.\d+\.\d+-win-x64$') { throw 'WINDOWS_NODE_ARCHIVE_DENIED' }
    if (Test-Path -LiteralPath (Join-Path $Destination $ExpectedRoot)) { throw 'WINDOWS_NODE_PARTIAL_RUNTIME' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        [long]$expandedSize = 0
        if ($zip.Entries.Count -gt 20000) { throw 'WINDOWS_NODE_ARCHIVE_DENIED' }
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            $expandedSize += $entry.Length
            if ($expandedSize -gt 500MB -or
                -not $name.StartsWith($ExpectedRoot + '/', [StringComparison]::Ordinal) -or
                $name -match '(^|/)\.\.?(/|$)|[\\<>:"|?*]|[. ](/|$)' -or
                (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000 -or
                ($entry.ExternalAttributes -band 0x400) -ne 0) { throw 'WINDOWS_NODE_ARCHIVE_DENIED' }
        }
    } finally { $zip.Dispose() }
    # Default extractor refuses replacement; only the exact checked root is admitted.
    [IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)
}

function Invoke-OwaspAiGoatWindowsPrerequisites {
    [CmdletBinding()]
    param(
        [bool]$ExecuteMode = $false,
        [string]$RepoRoot = (Join-Path $PSScriptRoot '..\..\..'),
        [string]$UserProfile = $env:USERPROFILE,
        [string]$SystemRoot = $env:SystemRoot,
        [scriptblock]$Inventory = { param($Root) Get-OwaspAiGoatWindowsDependencyPlan -RepoRoot $Root },
        [scriptblock]$Runner = ${function:Invoke-OwaspAiGoatPrerequisiteProcess},
        [scriptblock]$Download = ${function:Receive-OwaspAiGoatOfficialDownload},
        [scriptblock]$Hash = { param($File) (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash },
        [scriptblock]$ReadText = { param($File) Get-Content -LiteralPath $File -Raw },
        [scriptblock]$Expand = ${function:Expand-OwaspAiGoatNodeArchive},
        [scriptblock]$DirectoryExists = { param($Directory) Test-Path -LiteralPath $Directory -PathType Container },
        [scriptblock]$Exists = { param($File) Test-Path -LiteralPath $File -PathType Leaf },
        [scriptblock]$Find = { param($Name) (Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source },
        [scriptblock]$Cleanup = { param($File) if (Test-Path -LiteralPath $File -PathType Leaf) { Remove-Item -LiteralPath $File -Force } },
        [scriptblock]$IsElevated = { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    )
    $snapshot = & $Inventory $RepoRoot
    $result = [ordered]@{
        schemaVersion = 1; component = 'windows-native-prerequisites'; nonMutating = (-not $ExecuteMode)
        installationBlocked = $true; nativeQualified = $false; componentSucceeded = $false; restartRequired = $false
        completed = @(); blockers = @('WINDOWS_OWNED_SANDBOX_BACKEND_UNDECIDED', 'WINDOWS_GLOBAL_INSTALL_UNQUALIFIED', 'WINDOWS_NATIVE_BUILD_PREREQUISITES_UNQUALIFIED', 'WINDOWS_OLLAMA_SERVICE_UNQUALIFIED')
        dependencies = $snapshot.dependencies; runtime = $null
        unimplemented = @('Docker backend prerequisite provisioning and full installer integration')
        delegated = @('independent packages.ps1 Git/Python/MSVC/Windows SDK/Ollama provisioning and service readiness (not integrated)', 'locked npm ci', 'Puppeteer Chrome installation and sandbox verification', 'llama3.1:8b pull and genuine inference', 'embedding cache', 'database preparation')
    }
    if (-not $ExecuteMode) { return [pscustomobject]$result }
    $states = @{}
    foreach ($item in $snapshot.dependencies) { $states[$item.id] = $item.status }
    if ($states.windowsHost -ne 'present') { $result.blockers += 'WINDOWS_HOST_UNSUPPORTED'; return [pscustomobject]$result }
    if (& $IsElevated) { $result.blockers += 'WINDOWS_RUN_AS_NORMAL_USER'; return [pscustomobject]$result }
    if (-not [IO.Path]::IsPathRooted($UserProfile) -or -not [IO.Path]::IsPathRooted($SystemRoot)) { throw 'WINDOWS_PREREQUISITE_PATH_DENIED' }
    $powershell = Join-Path $SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $helper = Join-Path $RepoRoot 'scripts\windows\windows-private-state.ps1'
    $privateDirectory = {
        param($Directory)
        # Direct native PS helper works before Node exists; request is stdin data.
        $request = @{ version = 1; operation = 'ensurePrivateDirectory'; path = $Directory } | ConvertTo-Json -Compress
        $response = & $Runner @{ id = 'privateDirectory'; executable = $powershell; arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $helper); input = $request; capture = $true; timeoutMs = 30000 }
        if ($response.exitCode -ne 0) { throw 'WINDOWS_PREREQUISITE_PRIVATE_DIRECTORY_DENIED' }
        $admitted = $response.output | ConvertFrom-Json
        if ($admitted.version -ne 1 -or $admitted.ok -ne $true) { throw 'WINDOWS_PREREQUISITE_PRIVATE_DIRECTORY_DENIED' }
    }
    $base = Join-Path $UserProfile '.owasp-ai-goat'
    $tools = Join-Path $base 'tools'
    $cache = Join-Path $tools 'downloads'
    foreach ($directory in @($base, $tools, $cache)) { & $privateDirectory $directory }
    $operation = Join-Path $tools 'npm-bootstrap-operation.json'
    if (& $Exists $operation) { $result.blockers += 'WINDOWS_NPM_OPERATION_INDETERMINATE'; return [pscustomobject]$result }
    $nodeMinimum = $snapshot.runtimePolicy.nodeMinimum
    $npmMinimum = $snapshot.runtimePolicy.npmMinimum
    if ($nodeMinimum -notmatch '^\d+\.\d+\.\d+$' -or $npmMinimum -notmatch '^\d+\.\d+\.\d+$') { throw 'WINDOWS_RUNTIME_POLICY_INVALID' }
    $node = & $Find 'node.exe'
    if ($states.node -ne 'present') {
        $archiveName = 'node-v' + $nodeMinimum + '-win-x64.zip'
        $nodeDirectory = Join-Path $tools ('node-v' + $nodeMinimum + '-win-x64')
        $node = Join-Path $nodeDirectory 'node.exe'
        if (-not (& $Exists $node)) {
            if (& $DirectoryExists $nodeDirectory) { throw 'WINDOWS_NODE_PARTIAL_RUNTIME' }
            $nonce = [Guid]::NewGuid().ToString('N')
            $archive = Join-Path $cache ($nonce + '.zip')
            $checksums = Join-Path $cache ($nonce + '.sha256')
            try {
                & $Download ('https://nodejs.org/dist/v' + $nodeMinimum + '/' + $archiveName) $archive
                & $Download ('https://nodejs.org/dist/v' + $nodeMinimum + '/SHASUMS256.txt') $checksums
                $matches = @((& $ReadText $checksums) -split "`n" | Where-Object { $_ -match ('^[a-fA-F0-9]{64}\s+' + [regex]::Escape($archiveName) + '\s*$') })
                if ($matches.Count -ne 1 -or ($matches[0] -split '\s+')[0] -ine (& $Hash $archive)) { throw 'WINDOWS_NODE_CHECKSUM_MISMATCH' }
                # Never overwrite an incomplete runtime or other files automatically.
                & $Expand $archive $tools ('node-v' + $nodeMinimum + '-win-x64')
            } finally { & $Cleanup $archive; & $Cleanup $checksums }
        }
        $result.completed += 'nodeArchive'
    }
    $nodeVersion = & $Runner @{ id = 'verifyNode'; executable = $node; arguments = @('--version'); capture = $true; timeoutMs = 10000 }
    if ((Get-OwaspAiGoatVersionStatus @{ available = $true; exitCode = $nodeVersion.exitCode; output = $nodeVersion.output } $nodeMinimum) -ne 'present') { throw 'WINDOWS_NODE_VERIFICATION_FAILED' }
    $bundledNpm = Join-Path (Split-Path $node -Parent) 'node_modules\npm\bin\npm-cli.js'
    if (-not (& $Exists $bundledNpm)) { throw 'WINDOWS_NPM_BOOTSTRAP_MISSING' }
    $npmPrefix = Join-Path $tools ('npm-' + $npmMinimum)
    & $privateDirectory $npmPrefix
    $npmCli = Join-Path $npmPrefix 'node_modules\npm\bin\npm-cli.js'
    $journal = $null
    if (-not (& $Exists $npmCli)) {
        # Persist before spawning: timeout/unknown outcome must never auto-retry.
        $operationBytes = [Text.Encoding]::UTF8.GetBytes('{"version":1,"operation":"npmBootstrap","outcome":"indeterminate"}')
        $operationRequest = @{ version = 1; operation = 'createPrivateFile'; path = $operation; bytesBase64 = [Convert]::ToBase64String($operationBytes) } | ConvertTo-Json -Compress
        $written = & $Runner @{ id = 'npmOperationJournal'; executable = $powershell; arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $helper); input = $operationRequest; capture = $true; timeoutMs = 30000 }
        $journal = $written.output | ConvertFrom-Json
        if ($written.exitCode -ne 0 -or $journal.version -ne 1 -or $journal.ok -ne $true -or $journal.operation -ne 'createPrivateFile' -or $journal.path -ne $operation -or $journal.size -ne $operationBytes.Length -or $journal.identity.fileId -notmatch '^[a-f0-9]{16}$') { throw 'WINDOWS_NPM_JOURNAL_DENIED' }
        $npmInstall = & $Runner @{ id = 'npmBootstrap'; executable = $node; arguments = @($bundledNpm, 'install', '--global', ('npm@' + $npmMinimum), '--prefix', $npmPrefix, '--ignore-scripts', '--registry', 'https://registry.npmjs.org', '--strict-ssl=true'); environment = @{ NODE_USE_SYSTEM_CA = '1'; NODE_TLS_REJECT_UNAUTHORIZED = '1' }; timeoutMs = 600000 }
        if ($npmInstall.exitCode -ne 0) { throw 'WINDOWS_NPM_INSTALL_FAILED' }

    }
    $npmVersion = & $Runner @{ id = 'verifyNpm'; executable = $node; arguments = @($npmCli, '--version'); capture = $true; timeoutMs = 10000 }
    if ($npmVersion.exitCode -ne 0 -or $npmVersion.output.Trim() -ne $npmMinimum) { throw 'WINDOWS_NPM_VERIFICATION_FAILED' }
    if ($journal) {
        $deleteRequest = @{ version = 1; operation = 'deleteMatchingPrivateFile'; path = $operation; bytesBase64 = [Convert]::ToBase64String($operationBytes); expectedIdentity = $journal.identity } | ConvertTo-Json -Depth 4 -Compress
        $deleted = & $Runner @{ id = 'npmOperationRetire'; executable = $powershell; arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $helper); input = $deleteRequest; capture = $true; timeoutMs = 30000 }
        $retired = $deleted.output | ConvertFrom-Json
        if ($deleted.exitCode -ne 0 -or $retired.version -ne 1 -or $retired.ok -ne $true -or $retired.deleted -ne $true) { throw 'WINDOWS_NPM_OPERATION_RETIRE_UNCERTAIN' }
        $result.completed += 'npmBootstrap'
    }
    # Explicit binding for existing setup-npm-admission, not a global PATH change.
    $result.runtime = @{ nodeExecutable = $node; npmCli = $npmCli; npmExecpath = $npmCli }
    $result.componentSucceeded = $true
    $after = & $Inventory $RepoRoot
    $result.dependencies = $after.dependencies
    foreach ($item in $after.dependencies) {
        if ($item.id -in @('git', 'python', 'ollama', 'cppBuildTools', 'windowsSdk') -and $item.status -ne 'present') { $result.blockers += ('WINDOWS_INDEPENDENT_PACKAGE_COMPONENT_REQUIRED_' + $item.id.ToUpperInvariant()) }
        if ($item.id -in @('docker', 'compose', 'linuxDockerDaemon') -and $item.status -ne 'present') { $result.blockers += ('WINDOWS_DOCKER_PREREQUISITE_' + $item.id.ToUpperInvariant()) }
    }
    return [pscustomobject]$result
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($Plan -and $Execute) { throw '-Plan and -Execute cannot be combined.' }
    try {
        $output = Invoke-OwaspAiGoatWindowsPrerequisites -ExecuteMode ([bool]$Execute)
        $output | ConvertTo-Json -Depth 7
        if ($Execute -and -not $output.componentSucceeded) { exit 1 }
    }
    catch {
        # Subprocess/provider errors may contain sensitive output. Emit a closed code.
        $code = [string]$_.Exception.Message
        if ($code -notmatch '^WINDOWS_[A-Z0-9_]+$') { $code = 'WINDOWS_PREREQUISITE_FAILED' }
        [pscustomobject]@{ schemaVersion = 1; component = 'windows-native-prerequisites'; installationBlocked = $true; nativeQualified = $false; componentSucceeded = $false; code = $code } | ConvertTo-Json
        exit 1
    }
}
