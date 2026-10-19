# Read-only preflight. Runs elevated. Performs NO EC writes.
#
# Purpose: verify the pieces of the `enable` path that cannot be exercised
# without elevation -- the CIM telemetry call (which enable logs) and one
# full read-only register sample through the real bridge.
[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$LogFile = (Join-Path (Split-Path -Parent $PSScriptRoot) 'logs\elevated-preflight.log')
)

$ErrorActionPreference = 'Continue'
$Root = (Resolve-Path -LiteralPath $Root).Path

# Elevated processes started with -Verb RunAs cannot have their streams
# redirected by the caller, so transcribe everything to a file ourselves.
$logDir = Split-Path -Parent $LogFile
if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
Start-Transcript -Path $LogFile -Force | Out-Null

. (Join-Path $PSScriptRoot 'Resolve-Python.ps1')
$python = Resolve-EcGuardPython

$env:PYTHONPATH = $Root
$env:PYTHONUTF8 = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
Set-Location $Root

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Output "elevated: $elevated"
Write-Output "root    : $Root"
Write-Output ("-" * 70)

Write-Output '--- 1) CIM telemetry (used by enable/verify logging) ---'
& $python -c "import sys; sys.path.insert(0, r'$Root'); from ecguard import transport; import json; print(json.dumps(transport.cim_battery_telemetry()))"
Write-Output "cim exit=$LASTEXITCODE"

Write-Output '--- 2) one read-only register sample through the real bridge ---'
& $python -m ecguard.cli verify --samples 1 --interval 0
Write-Output "verify exit=$LASTEXITCODE"

Write-Output '--- 3) confirm no kernel service was left behind ---'
$left = & sc.exe query type= driver 2>&1 | Select-String -Pattern 'WinRing|ECGuard|OpenLibSys'
if ($left) { $left | ForEach-Object { Write-Output "  LEFTOVER: $_" } } else { Write-Output '  none' }

Write-Output '--- 4) guard state ---'
& $python -m ecguard.cli guard-status
Write-Output ("-" * 70)
Write-Output 'preflight complete (no EC writes performed)'
Stop-Transcript | Out-Null
Write-Host "log: $LogFile"
