# ECGuard driver deployment and ACL hardening. MUST run elevated.
#
# Deploys WinRing0x64.dll/.sys into an administrator-only-writable directory so
# a non-elevated process cannot swap the kernel driver that gets loaded, and
# verifies both files by SHA256 before and after the copy.
#
# Creates no service, no scheduled task, and no startup entry.
[CmdletBinding()]
param(
    [string]$SourceDir = (Join-Path $PSScriptRoot '..\driver'),
    [string]$TargetDir = 'C:\ProgramData\ECGuard\driver',
    [string]$StateDir  = 'C:\ProgramData\ECGuard\state'
)

$ErrorActionPreference = 'Stop'

$Expected = @{
    'WinRing0x64.dll' = 'a746fd5728e7485f741cc330a279674bc8590b1b8007d8614046c49f58698485'
    'WinRing0x64.sys' = '11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5'
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This installer must run elevated. Re-run it as Administrator."
    }
    Write-Host "Running as $($id.Name) (elevated)" -ForegroundColor Green
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

Assert-Admin

Write-Host "`n[1/5] Verifying source driver hashes" -ForegroundColor Cyan
$SourceDir = (Resolve-Path -LiteralPath $SourceDir).Path
foreach ($name in $Expected.Keys) {
    $src = Join-Path $SourceDir $name
    if (-not (Test-Path -LiteralPath $src)) { throw "missing source file: $src" }
    $sha = Get-Sha256 $src
    if ($sha -ne $Expected[$name]) { throw "SHA256 mismatch for $name`n  got      $sha`n  expected $($Expected[$name])" }
    Write-Host "  OK  $name  $sha"
}

Write-Host "`n[2/5] Creating protected directories" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
New-Item -ItemType Directory -Force -Path $StateDir  | Out-Null

Write-Host "`n[3/5] Copying driver into the protected directory" -ForegroundColor Cyan
foreach ($name in $Expected.Keys) {
    Copy-Item -LiteralPath (Join-Path $SourceDir $name) -Destination (Join-Path $TargetDir $name) -Force
    $sha = Get-Sha256 (Join-Path $TargetDir $name)
    if ($sha -ne $Expected[$name]) { throw "post-copy SHA256 mismatch for $name (got $sha)" }
    Write-Host "  copied + verified  $name"
}

Write-Host "`n[4/5] Locking down ACLs (administrators write, everyone else read)" -ForegroundColor Cyan
# Disable inheritance and drop inherited ACEs, then grant explicit rights only.
foreach ($dir in @($TargetDir, $StateDir)) {
    $acl = Get-Acl -LiteralPath $dir
    $acl.SetAccessRuleProtection($true, $false)          # protected, no inherited rules
    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    # Builtin Administrators: full control
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, 'FullControl', $inherit, $propagate, $allow)))
    # SYSTEM: full control
    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inherit, $propagate, $allow)))
    # Authenticated Users: read + execute only (so the bridge can load the driver)
    $users = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', $inherit, $propagate, $allow)))

    Set-Acl -LiteralPath $dir -AclObject $acl
    Write-Host "  ACL set on $dir"
}

Write-Host "`n[5/5] Resulting ACL" -ForegroundColor Cyan
foreach ($dir in @($TargetDir, $StateDir)) {
    Write-Host "  $dir"
    (Get-Acl -LiteralPath $dir).Access | ForEach-Object {
        Write-Host ("    {0,-42} {1}" -f $_.IdentityReference, $_.FileSystemRights)
    }
}

# Prove a standard user cannot write there. (We are elevated, so this is
# informational only: the ACE above is the actual guarantee.)
Write-Host "`nDriver deployed. No service, scheduled task, or startup entry was created." -ForegroundColor Green
Write-Host "Driver dir : $TargetDir"
Write-Host "State dir  : $StateDir"
