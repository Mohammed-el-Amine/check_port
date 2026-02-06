INSTRUCTIONS DE BUILD
=====================

Objectif
--------
Ce document décrit comment produire des exécutables pour l'application GUI `gui_port_scanner.py` (Linux, Windows et macOS).

Fichiers et scripts fournis
---------------------------
- `build_linux.sh` : script Bash (virtualenv + PyInstaller via spec).
- `build_windows.ps1` : script PowerShell (installe Python si besoin, build via spec).
- `build_macos.sh` : script macOS pour construire via spec.
- `build_all.sh` : script qui choisit le bon build selon l’OS.
- `scan_port_gui.spec` : spec PyInstaller utilisée pour un build reproductible.
- `assets/icon.*` : icônes Windows/macOS/Linux.

Pré‑requis
----------
- Python 3.8+ installé sur la machine de build.
- Paquet système tkinter (Debian/Ubuntu: `sudo apt install python3-tk`).

Build local (rapide) — Linux
----------------------------
```bash
chmod +x build_linux.sh
./build_linux.sh
```

Build Windows (local)
---------------------
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build_windows.ps1
```

Build macOS (local)
------------------
```bash
chmod +x build_macos.sh
./build_macos.sh
```

Build auto (tous OS)
--------------------
```bash
chmod +x build_all.sh
./build_all.sh
```

Utiliser le spec (recommandé pour CI)
------------------------------------
```bash
pyinstaller scan_port_gui.spec
```

Le fichier `scan_port_gui.spec` contient une entrée `datas` où vous pouvez ajouter des fichiers (icônes, exemples, assets) à embarquer.

Icônes
------
- Windows: `assets/icon.ico`
- macOS: `assets/icon.icns`
- Linux: `assets/icon.png` (utilisée via .desktop)

CI / GitHub Actions
--------------------
Le dépôt contient un workflow GitHub Actions (`.github/workflows/build.yml`). Il installe les dépendances, installe `python3-tk` sur Ubuntu runners, et lance PyInstaller via `scan_port_gui.spec`.

Conseils et dépannage
----------------------
- Pour le développement privilégiez `--onedir` : plus simple à déboguer.
- Si PyInstaller oublie des imports, ajoutez-les dans `hiddenimports` du spec ou utilisez `--hidden-import`.
- Si tkinter pose problème, installez `tk` / `python3-tk`.
