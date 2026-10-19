# Deploy the ECGuard bridge into the protected driver directory.
#
# REQUIRED because WinRing0x64.dll's InitializeOls() resolves its kernel driver
# as <directory-of-the-host-EXE>\WinRing0x64.sys (it uses GetModuleFileName(NULL)
# which returns the HOST process image, not the DLL path). Therefore the bridge
# EXE, WinRing0x64.dll and WinRing0x64.sys must all live in the same directory.
#
# Run Install-EcGuard.ps1 first (it places and verifies the DLL/SYS), then this.
# Creates no service, no scheduled task, no startup entry.
[CmdletBinding()]
param(
    [string]$SourceExe = (Join-Path (Split-Path -Parent $PSScriptRoot) 'windows\ECGuardBridge.exe'),
    [string]$TargetDir = 'C:\ProgramData\ECGuard\driver'
)

$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This deployment must run elevated.'
}

# Rebuild if a C# compiler is available and the sources are newer.
$src = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows\ECGuardBridge.cs'
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if ((Test-Path -LiteralPath $csc) -and (Test-Path -LiteralPath $src)) {
    if ((-not (Test-Path -LiteralPath $SourceExe)) -or
        ((Get-Item -LiteralPath $src).LastWriteTime -gt (Get-Item -LiteralPath $SourceExe).LastWriteTime)) {
        Write-Host "Rebuilding ECGuardBridge.exe from source..."
        & $csc /nologo /target:exe /platform:x64 /optimize+ /out:$SourceExe $src
        if ($LASTEXITCODE -ne 0) { throw "csc failed with $LASTEXITCODE" }
    }
}

if (-not (Test-Path -LiteralPath $SourceExe)) { throw "bridge not built: $SourceExe" }

$target = Join-Path $TargetDir 'ECGuardBridge.exe'
Copy-Item -LiteralPath $SourceExe -Destination $target -Force

Write-Host "`nLayout in $TargetDir (must contain all three):" -ForegroundColor Cyan
$required = 'ECGuardBridge.exe', 'WinRing0x64.dll', 'WinRing0x64.sys'
$missing = @()
foreach ($name in $required) {
    $p = Join-Path $TargetDir $name
    if (Test-Path -LiteralPath $p) {
        $item = Get-Item -LiteralPath $p
        Write-Host ("  OK      {0,-22} {1,8} bytes" -f $name, $item.Length)
    }
    else {
        Write-Host ("  MISSING {0}" -f $name) -ForegroundColor Red
        $missing += $name
    }
}
if ($missing) { throw "missing required files: $($missing -join ', ')" }

Write-Host "`nECGuardBridge.exe deployed to $target" -ForegroundColor Green
Write-Host "No service, scheduled task, or startup entry was created."
