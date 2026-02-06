#!/usr/bin/env bash
set -euo pipefail

# Build macOS executable for gui_port_scanner.py using PyInstaller spec
# Requires: Python 3.8+, tkinter (usually bundled on macOS), pyinstaller

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

# Create venv if missing
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install pyinstaller

# Build using spec for reproducibility
pyinstaller scan_port_gui.spec

echo "✅ macOS build done. Check ./dist/"
