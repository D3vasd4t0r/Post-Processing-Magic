param(
    [string]$Python = "$PSScriptRoot\.venv\Scripts\python.exe",
    [string]$OutputDirectory = "$PSScriptRoot\dist"
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path -LiteralPath $Python)) {
        throw 'Zuerst eine .venv mit Python 3.12+ und pip install -e .[dev] einrichten.'
    }
    & $Python -m pytest
    if ($LASTEXITCODE -ne 0) { throw 'Tests fehlgeschlagen.' }
    & $Python -m ruff check .
    if ($LASTEXITCODE -ne 0) { throw 'Lint fehlgeschlagen.' }
    # A fresh workspace avoids locked remnants from earlier builds and antivirus scans.
    $buildDirectory = Join-Path $PSScriptRoot ('build/' + [guid]::NewGuid().ToString('N'))
    & $Python -m PyInstaller --noconfirm --noupx --onefile --windowed --icon 'forensic_app/assets/shield.ico' --name PostProcessingMagic --distpath $OutputDirectory --workpath $buildDirectory --add-data 'forensic_app/web:forensic_app/web' --add-data 'forensic_app/assets:forensic_app/assets' --collect-submodules uvicorn run_app.py
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller-Build fehlgeschlagen.' }
    & $Python -m pip freeze | Set-Content -LiteralPath (Join-Path $OutputDirectory 'build-environment.txt') -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw 'Paketinventar fehlgeschlagen.' }
    & $Python -c "from forensic_app import __version__; print(__version__)" | Set-Content -LiteralPath (Join-Path $OutputDirectory 'app-version.txt') -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw 'App-Version konnte nicht erfasst werden.' }
    Write-Host "Erstellt: $OutputDirectory\PostProcessingMagic.exe (EXE-Abnahme separat ausführen)."
} finally {
    Pop-Location
}

