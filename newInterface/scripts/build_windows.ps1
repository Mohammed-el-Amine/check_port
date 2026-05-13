<# build_windows.ps1 — Build PyInstaller pour gui_qt.py (PySide6) #>
$ErrorActionPreference = "Stop"
$ProjectDir = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectDir

$Py = if ($Env:PYTHON) { $Env:PYTHON } else { "python" }
$Venv = ".venv_build"

Write-Host "==> Python: $(& $Py --version)"

if (-not (Test-Path $Venv)) {
    & $Py -m venv $Venv
}
& "$Venv\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
& "$Venv\Scripts\python.exe" -m pip install -r requirements.txt
& "$Venv\Scripts\python.exe" -m pip install pyinstaller

& "$Venv\Scripts\pyinstaller.exe" --noconfirm --clean scan_port_gui.spec

Write-Host "==> Terminé. Binaire : dist\scan_port_gui.exe"
Get-ChildItem dist
