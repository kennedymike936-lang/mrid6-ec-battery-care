# Run an ECGuard action. MUST run elevated.
#
# IMPORTANT (learned the hard way): WinRing0x64.dll's InitializeOls() resolves
# its kernel driver as  <directory-of-the-HOST-EXE>\WinRing0x64.sys
# (it calls GetModuleFileName(NULL, ...)), NOT relative to the DLL. So the
# bridge executable, the DLL and the SYS must all sit in the same protected
# directory. That is achieved by:
#   * Install-EcGuard.ps1      -> places DLL/SYS in C:\ProgramData\ECGuard\driver
#   * ECGuard-Deploy.ps1       -> places ECGuardBridge.exe in the same directory
# Python then launches the bridge from that directory (transport.DEFAULT_BRIDGE).
#
# The DLL itself installs and starts the demand-start kernel service, and
# DeinitializeOls() removes it again on process exit, so no service persists.
#
# No service is created by this script, no scheduled task, no startup entry,
# and no security policy is modified.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('inspect', 'verify', 'enable', 'disable', 'guard')]
    [string]$Action,

    [int]$Repeats = 2,
    [int]$Samples = 5,
    [double]$Interval = 10.0,
    [switch]$ClearGuardAfterInspection
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot            # ...\ecguard

function Step([string]$text) { Write-Host "== $text" }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "ECGuard"
Write-Host "  action   : $Action"
Write-Host "  elevated : $elevated"
Write-Host ("-" * 70)
if (-not $elevated) { throw "This wrapper must run elevated." }

# Confirm the bridge + driver are colocated as InitializeOls() requires.
$driverDir = 'C:\ProgramData\ECGuard\driver'
foreach ($f in 'ECGuardBridge.exe', 'WinRing0x64.dll', 'WinRing0x64.sys') {
    $p = Join-Path $driverDir $f
    if (-not (Test-Path -LiteralPath $p)) {
        throw "$p is missing. Run Install-EcGuard.ps1 then ECGuard-Deploy.ps1 (both elevated)."
    }
}
Write-Host "  layout OK: bridge + DLL + SYS all in $driverDir" -ForegroundColor Green

try {
    Step "locate python"
    . (Join-Path $PSScriptRoot 'Resolve-Python.ps1')
    $python = Resolve-EcGuardPython

    $env:PYTHONPATH = $root
    $env:PYTHONUTF8 = '1'
    $env:PYTHONDONTWRITEBYTECODE = '1'

    $argv = switch ($Action) {
        'inspect' {
            $a = @('-m', 'ecguard.cli', 'inspect', '--repeats', $Repeats)
            if ($ClearGuardAfterInspection) { $a += '--clear-guard-after-inspection' }
            $a
        }
        'verify'  { @('-m', 'ecguard.cli', 'verify', '--samples', $Samples, '--interval', $Interval) }
        'enable'  { @('-m', 'ecguard.cli', 'enable', '--repeats', $Repeats) }
        'disable' { @('-m', 'ecguard.cli', 'disable') }
        'guard'   { @('-m', 'ecguard.cli', 'guard-status') }
    }

    Step "run ecguard.cli $Action"
    Push-Location $root
    try { & $python @argv; $exitCode = $LASTEXITCODE }
    finally { Pop-Location }
    Write-Host "   python exit code: $exitCode"
}
finally {
    Step "confirm the DLL removed its own kernel service"
    $leftover = & sc.exe query type= driver 2>&1 | Select-String -Pattern 'WinRing|ECGuard|OpenLibSys'
    if ($leftover) {
        Write-Host "   WARNING: a WinRing service is still present:" -ForegroundColor Yellow
        $leftover | ForEach-Object { Write-Host "     $_" }
    } else {
        Write-Host "   confirmed: no WinRing/ECGuard kernel service remains" -ForegroundColor Green
    }
    Write-Host ("-" * 70)
    Write-Host "exit code: $exitCode"
}

exit $exitCode

