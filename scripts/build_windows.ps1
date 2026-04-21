param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "could not find .venv\\Scripts\\python.exe"
}

Push-Location $root
try {
    if ($Clean) {
        Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
    }

    & $python -m PyInstaller --noconfirm .\CryptoTools.spec
}
finally {
    Pop-Location
}
