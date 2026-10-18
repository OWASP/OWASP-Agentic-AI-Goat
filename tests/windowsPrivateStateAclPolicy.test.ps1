# Controlled ACL-policy fixtures, no filesystem access or Win32 calls.
# Run on an explicitly permitted PowerShell 5.1 test host. This suite is not
# live OS/storage qualification; it executes the actual C# pure policy method.
$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot '../scripts/windows/windows-private-state.cs')
$flags = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
$method = [Dvaia.WindowsPrivateState].GetMethod('AncestorAclIsSafe', $flags)
$user = 'S-1-5-21-101-102-103-1001'
$other = 'S-1-5-21-101-102-103-1002'
$trusted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
[void]$trusted.Add($user)
[void]$trusted.Add('S-1-5-18')
[void]$trusted.Add('S-1-5-32-544')
# Construct RawAcl directly so deliberately noncanonical deny/allow order is
# preserved; an ACL editor must not silently reorder the negative fixture.
function Ace([string]$qualifier, [int]$flags, [int]$mask, [string]$sid) {
    [pscustomobject]@{ Qualifier = $qualifier; Flags = $flags; Mask = $mask; Sid = $sid }
}
function Check-Policy([string]$name, [bool]$expected, [array]$aces, [string]$owner = $user) {
    $acl = [System.Security.AccessControl.RawAcl]::new(2, $aces.Length)
    foreach ($entry in $aces) {
        $qualifier = [Enum]::Parse([System.Security.AccessControl.AceQualifier], [string]$entry.Qualifier)
        $aceFlags = [System.Security.AccessControl.AceFlags]$entry.Flags
        $sid = [System.Security.Principal.SecurityIdentifier]::new([string]$entry.Sid)
        $ace = [System.Security.AccessControl.CommonAce]::new($aceFlags, $qualifier, [int]$entry.Mask, $sid, $false, $null)
        $acl.InsertAce($acl.Count, $ace)
    }
    $ownerSid = [System.Security.Principal.SecurityIdentifier]::new($owner)
    $control = [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($control, $ownerSid, $ownerSid, $null, $acl)
    $arguments = New-Object object[] 2
    $arguments[0] = $descriptor; $arguments[1] = $trusted
    $actual = $method.Invoke($null, $arguments)
    if ($actual -ne $expected) { throw "Controlled policy fixture failed: $name" }
}
$allow = 'AccessAllowed'; $deny = 'AccessDenied'; $everyone = 'S-1-1-0'; $users = 'S-1-5-32-545'
Check-Policy 'ordinary drive root grants create-sibling only' $true @((Ace $allow 0 6 $everyone))
Check-Policy 'read-only untrusted trustee' $true @((Ace $allow 0 0x120089 $users))
Check-Policy 'trusted owner full control' $true @((Ace $allow 0 0x1f01ff $user))
foreach ($right in @(0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000)) {
    Check-Policy "untrusted mutation right $right" $false @((Ace $allow 0 $right $other))
}
Check-Policy 'inherit-only grant has no effective parent rights' $true @((Ace $allow 0x0b 0x1f01ff $everyone))
Check-Policy 'inherited effective dangerous grant is rejected' $false @((Ace $allow 0x10 0x10000 $users))
Check-Policy 'same SID deny preceding allow covers dangerous bits' $true @((Ace $deny 0 0x10000 $users), (Ace $allow 0 0x10000 $users))
Check-Policy 'allow preceding same SID deny remains unsafe' $false @((Ace $allow 0 0x10000 $users), (Ace $deny 0 0x10000 $users))
Check-Policy 'Everyone deny covers later untrusted allow' $true @((Ace $deny 0 0x10000 $everyone), (Ace $allow 0 0x10000 $users))
Check-Policy 'unrelated group deny cannot prove grant safe' $false @((Ace $deny 0 0x10000 $users), (Ace $allow 0 0x10000 $other))
Check-Policy 'partial deny leaves dangerous bits allowed' $false @((Ace $deny 0 0x10000 $users), (Ace $allow 0 0x50000 $users))
Check-Policy 'inherit-only deny cannot cover effective grant' $false @((Ace $deny 0x0b 0x10000 $users), (Ace $allow 0 0x10000 $users))
Check-Policy 'generic write expands to dangerous attribute rights' $false @((Ace $deny 0 6 $users), (Ace $allow 0 0x40000000 $users))
Check-Policy 'generic write fully denied by specific dangerous bits' $true @((Ace $deny 0 0x110 $users), (Ace $allow 0 0x40000000 $users))
Check-Policy 'untrusted directory owner can change ACL' $false @((Ace $allow 0 0x120089 $users)) $other
# Null DACL (unrestricted access) fails closed.
$ownerSid = [System.Security.Principal.SecurityIdentifier]::new($user)
$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new([System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent, $ownerSid, $ownerSid, $null, $null)
$arguments = New-Object object[] 2; $arguments[0] = $descriptor; $arguments[1] = $trusted
if ($method.Invoke($null, $arguments)) { throw 'Null DACL was admitted' }
# Callback ACEs cannot be reasoned about without their condition evaluator.
$acl = [System.Security.AccessControl.RawAcl]::new(2, 1)
$callback = [System.Security.AccessControl.CommonAce]::new([System.Security.AccessControl.AceFlags]::None, [System.Security.AccessControl.AceQualifier]::AccessAllowed, 0x120089, $ownerSid, $true, [byte[]]@())
$acl.InsertAce(0, $callback)
$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new([System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent, $ownerSid, $ownerSid, $null, $acl)
$arguments[0] = $descriptor
if ($method.Invoke($null, $arguments)) { throw 'Callback ACE was admitted' }
[Console]::Out.WriteLine('Controlled native ACL-policy fixtures passed; no storage qualification performed.')
