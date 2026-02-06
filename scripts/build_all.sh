#!/usr/bin/env bash
set -euo pipefail

# Build executable depending on the current OS.
# Cross-compiling with PyInstaller is NOT supported; run this on each OS.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

OS="$(uname -s)"
case "$OS" in
  Linux)
    echo "▶ Building Linux binary..."
    chmod +x build_linux.sh
    ./build_linux.sh
    ;;
  Darwin)
    echo "▶ Building macOS binary..."
    chmod +x build_macos.sh
    ./build_macos.sh
    ;;
  MINGW*|MSYS*|CYGWIN*)
    echo "▶ Detected Windows shell. Run PowerShell script instead:" 
    echo "   powershell -ExecutionPolicy Bypass -File .\\build_windows.ps1"
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
 esac
