#!/usr/bin/env bash
# Build PyInstaller — Linux. Builds gui_qt.py (PySide6).
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

PY="${PYTHON:-python3}"
VENV=".venv_build"

echo "==> Python : $($PY --version)"

if [ ! -d "$VENV" ]; then
  echo "==> Création virtualenv $VENV"
  $PY -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "==> Mise à jour pip + install requirements + PyInstaller"
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install pyinstaller

echo "==> Build PyInstaller"
pyinstaller --noconfirm --clean scan_port_gui.spec

echo "==> Terminé. Binaire : dist/scan_port_gui"
ls -la dist/ || true
deactivate || true
