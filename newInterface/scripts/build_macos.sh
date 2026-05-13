#!/usr/bin/env bash
# Build PyInstaller — macOS. Builds gui_qt.py (PySide6).
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

PY="${PYTHON:-python3}"
VENV=".venv_build"

echo "==> Python : $($PY --version)"

if [ ! -d "$VENV" ]; then
  $PY -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install pyinstaller

pyinstaller --noconfirm --clean scan_port_gui.spec

echo "==> Terminé. App : dist/scan_port_gui (ou dist/scan_port_gui.app)"
ls -la dist/ || true
deactivate || true
