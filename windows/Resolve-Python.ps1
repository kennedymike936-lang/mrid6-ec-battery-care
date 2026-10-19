# Shared Python interpreter discovery for the ECGuard PowerShell wrappers.
#
# Dot-source this file, then call Resolve-EcGuardPython.
#
# Search order:
#   1. $env:ECGUARD_PYTHON            (explicit override, always wins)
#   2. python.exe on PATH
#   3. the Windows "py" launcher      (py -3)
#   4. common per-user / system install locations
#
# No machine-specific paths are baked into this repository.

function Resolve-EcGuardPython {
    [CmdletBinding()]
    param([switch]$Quiet)

    $found = $null

    if ($env:ECGUARD_PYTHON) {
        if (Test-Path -LiteralPath $env:ECGUARD_PYTHON) {
            $found = (Resolve-Path -LiteralPath $env:ECGUARD_PYTHON).Path
        }
        else {
            throw "ECGUARD_PYTHON is set to '$env:ECGUARD_PYTHON' but that file does not exist."
        }
    }

    if (-not $found) {
        $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($cmd) { $found = $cmd.Source }
    }

    if (-not $found) {
        $py = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($py) {
            try {
                $candidate = & $py.Source -3 -c "import sys; print(sys.executable)" 2>$null
                if ($candidate -and (Test-Path -LiteralPath $candidate)) { $found = $candidate.Trim() }
            }
            catch { }
        }
    }

    if (-not $found) {
        $candidates = @(
            (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python310\python.exe'),
            'C:\Python313\python.exe',
            'C:\Python312\python.exe',
            'C:\Python311\python.exe',
            'C:\Python310\python.exe'
        )
        foreach ($candidate in $candidates) {
            if (Test-Path -LiteralPath $candidate) { $found = $candidate; break }
        }
    }

    if (-not $found) {
        throw ("No Python 3 interpreter found.`n" +
               "  Set it explicitly, e.g.:  `$env:ECGUARD_PYTHON = 'C:\Path\To\python.exe'`n" +
               "  or install Python 3.10+ and make sure 'python' is on PATH.")
    }

    # Require 3.10+ (the code uses PEP 604 unions and modern typing).
    try {
        $version = & $found -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    }
    catch {
        throw "Found '$found' but it failed to run."
    }
    if (-not $version) { throw "Found '$found' but could not determine its version." }

    $parts = $version.Trim().Split('.')
    $major = [int]$parts[0]
    $minor = [int]$parts[1]
    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
        throw "Python $version at '$found' is too old; Python 3.10+ is required."
    }

    if (-not $Quiet) { Write-Host "   python: $found (Python $version)" }
    return $found
}
