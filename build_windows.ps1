<# build_windows.ps1
   Script PowerShell pour construire un exécutable Windows pour gui_port_scanner.py
   Usage (PowerShell administrateur recommandé pour certaines opérations):
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
     .\build_windows.ps1

     Executer comme ça : Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build_windows.ps1
#>

$ErrorActionPreference = 'Stop'
$venv = '.venv_build'
$distName = 'scan_port_gui'
$src = 'gui_port_scanner.py'

Write-Host '==> Vérification de Python (py -3)...'
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    Write-Error 'Python launcher (py) introuvable. Installez Python 3 et réessayez.'
    exit 1
}

if (-not (Test-Path $venv)) {
    Write-Host "==> Création du virtualenv $venv"
    py -3 -m venv $venv
}

Write-Host '==> Activation du virtualenv'
$activate = Join-Path $venv 'Scripts/Activate.ps1'
if (-not (Test-Path $activate)) {
    Write-Error "Impossible de trouver $activate"
    exit 1
}

# Importer l'environnement
. $activate

Write-Host '==> Vérification de tkinter (module GUI)'
# Exécuter python pour tester l'importation de tkinter
python -c "import tkinter" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "tkinter introuvable pour cette installation Python." -ForegroundColor Yellow
    # Essayer d'installer Python officiel via winget ou chocolately si disponible
    $hasWinget = (Get-Command winget -ErrorAction SilentlyContinue) -ne $null
    $hasChoco = (Get-Command choco -ErrorAction SilentlyContinue) -ne $null

    if ($hasWinget -or $hasChoco) {
        Write-Host "Le script peut tenter d'installer une distribution Python officielle qui inclut tcl/tk."
        $ans = Read-Host "Voulez-vous que j'essaie d'installer Python (requiert élévation) ? [y/N]"
        if ($ans -match '^[Yy]') {
            if ($hasWinget) {
                Write-Host "Lancement de winget pour installer Python (peut ouvrir une fenêtre UAC)..."
                $args = 'install --id Python.Python -e --accept-package-agreements --accept-source-agreements'
                Start-Process -FilePath winget -ArgumentList $args -Verb RunAs -Wait
                Write-Host "Installation via winget terminée. Fermez et rouvrez PowerShell puis relancez ce script." -ForegroundColor Green
                exit 0
            } elseif ($hasChoco) {
                Write-Host "Lancement de Chocolatey pour installer Python (peut ouvrir une fenêtre UAC)..."
                $args = 'install python -y'
                Start-Process -FilePath choco -ArgumentList $args -Verb RunAs -Wait
                Write-Host "Installation via Chocolatey terminée. Fermez et rouvrez PowerShell puis relancez ce script." -ForegroundColor Green
                exit 0
            }
        } else {
            Write-Host "Abandon de l'installation automatique. Installez Python avec tcl/tk puis relancez." -ForegroundColor Yellow
            exit 1
        }
    }

    Write-Host "Aucun gestionnaire d'installation automatique détecté (winget/choco)." -ForegroundColor Yellow
    Write-Host "Veuillez installer une version officielle de Python depuis https://python.org (cocher 'Install Tcl/Tk') et relancer ce script." -ForegroundColor Yellow
    exit 1
}

Write-Host '==> Mise à jour pip et installation de PyInstaller'
python -m pip install --upgrade pip setuptools wheel
python -m pip install pyinstaller

Write-Host '==> Lancement de PyInstaller (onefile)'
# Pour inclure des fichiers additionnels, utilisez --add-data "src;dest"
pyinstaller --noconfirm --name $distName --onefile $src

Write-Host '==> Construction terminée. Artéfacts dans .\dist\'
$exePath = Join-Path 'dist' $distName
if (Test-Path $exePath) {
    Write-Host "Executable: $exePath"
    Write-Host "Vous pouvez l'exécuter depuis PowerShell : .\dist\$distName.exe"
} else {
    Write-Host 'Executable introuvable. Vérifiez la sortie de PyInstaller.' -ForegroundColor Red
    exit 1
}

Write-Host '==> Fini'
