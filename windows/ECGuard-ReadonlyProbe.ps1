# Run the READ-ONLY transport bring-up probe elevated, capturing console output
# to a workspace log so it can be inspected afterwards.
#
# Performs NO EC RAM writes: the transport refuses to emit the 0x93 command.
[CmdletBinding()]
param(
    [int]$Repeats = 3,
    [switch]$Phase1Only
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Resolve-Python.ps1')
$python = Resolve-EcGuardPython
$tool = Join-Path $root 'tools\readonly_probe.py'

$logDir = Join-Path $root 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$console = Join-Path $logDir "readonly-$stamp.log"

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) { throw 'must run elevated' }

$env:PYTHONPATH = $root
$env:PYTHONUTF8 = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
Set-Location $root

$args = @($tool, '--repeats', $Repeats)
if ($Phase1Only) { $args += '--phase1-only' }

& $python @args 2>&1 | Tee-Object -FilePath $console
$code = $LASTEXITCODE

Write-Output ("-" * 70)
Write-Output "exit code: $code"
Write-Output "console log: $console"

# Independently re-verify that nothing was left behind, after the tool's own cleanup.
Write-Output "--- post-run service check ---"
$svc = & sc.exe query type= driver 2>&1 | Select-String -Pattern 'WinRing|ECGuard|OpenLibSys'
if ($svc) { $svc | ForEach-Object { Write-Output "  LEFTOVER: $_" } } else { Write-Output '  no WinRing/ECGuard service remains' }
Write-Output ("-" * 70)
exit $code
