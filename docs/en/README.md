# 🛠️ Scan Port GUI & CLI
Advanced port scanner with **Tkinter GUI** and **CLI**. Smart service detection, flexible scan options, and clean service stop (admin privileges).

**Quality & Security:** audited (Bandit, Ruff, pip‑audit, Gitleaks) ✅

---
## ✅ Security & QA checks (last audit)
- **Bandit** (Python security): `bandit -r .` → **no High**, **no Medium** (remaining Low: subprocess usage/try‑except best‑effort)
- **Ruff** (lint): `ruff check .` → **0 errors**
- **Gitleaks** (secrets): `gitleaks detect --no-git --source .` → **no leaks**
- **pip‑audit** (dependencies): **N/A** (no `requirements.txt`/`pyproject.toml` in repo)

---
## ✅ Features
- **CLI + GUI** (Tkinter)
- **Fast presets** (common, top1000, top5000)
- **Custom ranges** (`1-1024`, `8000-9000`)
- **Specific ports** (`22,80,443`)
- **UDP option** (best‑effort)
- **CSV/JSON export** (GUI)
- **Smart service stop** (systemctl when available)
- **PID / process display** (admin)

---
## 📦 Requirements
- Python **3.8+**
- Linux/macOS: `python3-tk` (Tkinter)

### Optional (pip)
```bash
pip install -r requirements.txt
# or
pip install -e .
```

### Linux (Ubuntu/Debian)
```bash
sudo apt install python3-tk
```

---
## 🚀 CLI Usage
```bash
python3 check_port.py <target> [ports] [options]
```

### CLI Help (available)
```bash
python3 check_port.py --help
```

Examples:
```bash
python3 check_port.py localhost
python3 check_port.py 192.168.1.1 top1000
python3 check_port.py 192.168.1.1 1-1024
python3 check_port.py 192.168.1.1 22,80,443
python3 check_port.py 192.168.1.1 all
# TCP + UDP
python3 check_port.py 192.168.1.1 top1000 --udp
```

---
## 🖥️ GUI
Launch the GUI:
```bash
python3 gui_port_scanner.py
```

### With admin privileges (PID/actions)
```bash
sudo python3 gui_port_scanner.py
```

✅ The UI provides a **Relaunch with sudo** button (Linux/macOS).

### GUI Options
- **UDP scan** (slower, best‑effort)
- **CSV/JSON export**

---
## 🔐 Permissions
- **Without sudo**: scan OK, PID info limited
- **With sudo**: full access (PID + kill/stop)

---
## ⚙️ Dynamic ports
Dynamic/ephemeral ports are hidden by default. To show them:
```bash
python3 check_port.py --show-dynamic localhost all
```

---
## 📦 Build & Packaging (PyInstaller)
Scripts provided:
- `scripts/build_linux.sh`
- `scripts/build_windows.ps1`
- `scripts/build_macos.sh`
- `scripts/build_all.sh`
- `scan_port_gui.spec`

### Quick Linux build
```bash
./scripts/build_linux.sh
```

### GitHub Actions CI
Workflow ready: `.github/workflows/build.yml`

---
## 🎨 Icon / Logo
Icons are in `assets/`:
- `icon.ico` (Windows)
- `icon.icns` (macOS)
- `icon.png` (Linux)

`scan_port_gui.spec` selects the icon per OS.

**Linux**: icon is displayed via a `.desktop` launcher.

---
## 📁 Project structure
- `gui_port_scanner.py` : GUI
- `check_port.py` : scanner engine
- `scan_port_gui.spec` : PyInstaller spec
- `assets/` : icons
- `build_*.sh` / `scripts/build_windows.ps1` : build scripts
- `.github/workflows/build.yml` : CI

---
## ⚠️ Best practices
- Scan only your own machines / authorized networks
- Avoid `all` unless necessary (slow/heavy)
- Prefer `top1000` for a good balance

---
## ❓ FAQ
**Q: No icon on Linux?**
A: Linux uses a `.desktop` launcher for icons.

**Q: UDP scan is slow / freezes?**
A: UDP is best‑effort. Use `top1000` instead of `all`.

**Q: How to see PID/process?**
A: Run with sudo (Linux/macOS) or as Administrator (Windows).

---
## 📄 License
This project is under **MIT** (see `LICENSE`).

---
## ✅ Versions
- v1.0 : base scan
- v2.0 : optimizations
- v2.1 : service detection & smart stop
- v2.2 : GUI + packaging + CI
