BUILD INSTRUCTIONS
==================

Goal
----
This document explains how to build executables for `gui_port_scanner.py` (Linux, Windows, macOS).

Provided files
--------------
- `build_linux.sh`: Bash script (venv + PyInstaller via spec)
- `build_windows.ps1`: PowerShell script (installs Python if needed, builds via spec)
- `build_macos.sh`: macOS build script via spec
- `build_all.sh`: auto-select build per OS
- `scan_port_gui.spec`: PyInstaller spec for reproducible builds
- `assets/icon.*`: icons for Windows/macOS/Linux

Requirements
------------
- Python 3.8+
- Tkinter package (Ubuntu/Debian: `sudo apt install python3-tk`)

Local build — Linux
-------------------
```bash
chmod +x build_linux.sh
./build_linux.sh
```

Local build — Windows
---------------------
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build_windows.ps1
```

Local build — macOS
-------------------
```bash
chmod +x build_macos.sh
./build_macos.sh
```

Auto build (any OS)
-------------------
```bash
chmod +x build_all.sh
./build_all.sh
```

Using the spec (recommended for CI)
-----------------------------------
```bash
pyinstaller scan_port_gui.spec
```

Icons
-----
- Windows: `assets/icon.ico`
- macOS: `assets/icon.icns`
- Linux: `assets/icon.png` (used via .desktop)

CI / GitHub Actions
-------------------
Workflow `.github/workflows/build.yml` builds artifacts on all OSes.

Tips
----
- Use `--onedir` for easier debugging.
- Add missing imports to `hiddenimports` in the spec or use `--hidden-import`.
- If Tkinter fails, install `tk` / `python3-tk`.
